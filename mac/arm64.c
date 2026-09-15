/*
 * Native Apple Silicon crash reporting using Apple's public Mach/Mach-O SDK
 * interfaces, dladdr, and the system atos symbolicator.
 */
#include "mac/arm64.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "mac/exception.h"

extern boolean_t mach_exc_server(mach_msg_header_t*, mach_msg_header_t*);

static mach_port_t     exceptionPort;
static mach_port_t     childExceptionPort;
static pthread_mutex_t forkMutex = PTHREAD_MUTEX_INITIALIZER;
static pid_t           parentPid;
static pthread_mutex_t crashMutex = PTHREAD_MUTEX_INITIALIZER;
static mac_crash_t*    crashes;
static size_t          crashCount, crashLimit;

static bool readMemory(task_t task, uint64_t addr, void* out, size_t size) {
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(task, addr, size, (mach_vm_address_t)out, &copied) ==
               KERN_SUCCESS &&
           copied == size;
}

/* Saved return addresses can contain PAC bits, even in an ordinary arm64 target. */
static uint64_t codeAddress(uint64_t addr) {
    return addr & UINT64_C(0x0000ffffffffffff);
}

typedef struct mac_image {
    uint64_t base, end;
    char     path[PATH_MAX];
    bool     sharedCache;
} image_t;

static bool readString(task_t task, uint64_t addr, char out[PATH_MAX]) {
    for (size_t i = 0; i < PATH_MAX;) {
        size_t amount = 64;
        if (amount > PATH_MAX - i) amount = PATH_MAX - i;
        if (!readMemory(task, addr + i, out + i, amount)) {
            amount = 1;
            if (!readMemory(task, addr + i, out + i, amount)) return false;
        }
        if (memchr(out + i, 0, amount)) return true;
        i += amount;
    }
    out[PATH_MAX - 1] = 0;
    return false;
}

static size_t readImages(task_t task, image_t* images, size_t capacity) {
    struct task_dyld_info  dyld;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld, &count) != KERN_SUCCESS ||
        dyld.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64)
        return 0;
    struct dyld_all_image_infos info;
    if (!readMemory(task, dyld.all_image_info_addr, &info, sizeof(info)) ||
        info.infoArrayCount > 4096)
        return 0;
    size_t  found    = 0;
    int64_t deadline = util_timeNowUSecs() + 500000;
    for (unsigned i = 0; i < info.infoArrayCount && found < capacity; i++) {
        if (util_timeNowUSecs() >= deadline) break;
        struct dyld_image_info image;
        struct mach_header_64  header;
        if (!readMemory(
                task, (uintptr_t)info.infoArray + i * sizeof(image), &image, sizeof(image)) ||
            !readMemory(task, (uintptr_t)image.imageLoadAddress, &header, sizeof(header)) ||
            header.magic != MH_MAGIC_64 || header.sizeofcmds > 1024 * 1024 || header.ncmds > 4096)
            continue;
        uint64_t cmdAddress = (uintptr_t)image.imageLoadAddress + sizeof(header);
        uint64_t cmdEnd     = cmdAddress + header.sizeofcmds;
        for (unsigned j = 0; j < header.ncmds && cmdAddress < cmdEnd; j++) {
            if (util_timeNowUSecs() >= deadline) break;
            struct load_command cmd;
            if (!readMemory(task, cmdAddress, &cmd, sizeof(cmd)) || cmd.cmdsize < sizeof(cmd) ||
                cmd.cmdsize > cmdEnd - cmdAddress)
                break;
            if (cmd.cmd == LC_SEGMENT_64 && cmd.cmdsize >= sizeof(struct segment_command_64)) {
                struct segment_command_64 segment;
                if (!readMemory(task, cmdAddress, &segment, sizeof(segment))) break;
                if (strncmp(segment.segname, SEG_TEXT, sizeof(segment.segname)) == 0) {
                    image_t* out     = &images[found];
                    out->sharedCache = (header.flags & MH_DYLIB_IN_CACHE) != 0;
                    out->base        = (uintptr_t)image.imageLoadAddress;
                    if (segment.vmsize > UINT64_MAX - out->base) break;
                    out->end = out->base + segment.vmsize;
                    if (readString(task, (uintptr_t)image.imageFilePath, out->path)) found++;
                    break;
                }
            }
            cmdAddress += cmd.cmdsize;
        }
    }
    return found;
}

static const char* baseName(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void addFrame(
    mac_crash_t* crash, const image_t* images, size_t imageCount, uint64_t address, bool returned) {
    funcs_t* frame  = &crash->frames[crash->frameCount++];
    uint64_t lookup = returned && address >= 4 ? address - 4 : address;
    frame->pc       = (void*)(uintptr_t)address;
    snprintf(frame->func, sizeof(frame->func), "???");
    snprintf(frame->module, sizeof(frame->module), "???");
    uint64_t offset = lookup;
    for (size_t i = 0; i < imageCount; i++) {
        if (lookup < images[i].base || lookup >= images[i].end) continue;
        offset = lookup - images[i].base;
        snprintf(frame->module, sizeof(frame->module), "%s", baseName(images[i].path));
        /* Shared-cache images mapped in this process can be resolved with dladdr.
         * Require matching image identity and base; never resolve against our own executable.
         */
        Dl_info symbol;
        if (dladdr((void*)(uintptr_t)lookup, &symbol) && symbol.dli_fname &&
            (uintptr_t)symbol.dli_fbase == images[i].base &&
            strcmp(baseName(symbol.dli_fname), baseName(images[i].path)) == 0 && symbol.dli_sname) {
            snprintf(frame->func, sizeof(frame->func), "%s + 0x%llx", symbol.dli_sname,
                lookup - (uintptr_t)symbol.dli_saddr);
        }
        break;
    }
    if (crash->frameCount == 1) crash->pcOffset = offset;
    crash->hash =
        (crash->hash ^ util_hash(frame->module, strlen(frame->module))) * 1099511628211ULL;
    crash->hash = (crash->hash ^ offset) * 1099511628211ULL;
}

/* Resolve on-disk target images in one atos invocation per image. No shell is used.
 * Bound symbolication time so a damaged image cannot hold the crash server forever.
 */
static void symbolizeImage(mac_crash_t* crash, const image_t* image) {
    if (image->sharedCache || access(image->path, R_OK)) return;
    char        base[32], addresses[_HF_MAX_FUNCS][32];
    const char* args[_HF_MAX_FUNCS + 9] = {
        "/usr/bin/atos", "-arch", "arm64", "-o", image->path, "-l", base};
    size_t indices[_HF_MAX_FUNCS], count = 0;
    snprintf(base, sizeof(base), "0x%llx", image->base);
    for (size_t i = 0; i < crash->frameCount; i++) {
        uint64_t pc = (uintptr_t)crash->frames[i].pc;
        if (i && pc >= 4) pc -= 4;
        if (pc < image->base || pc >= image->end) continue;
        snprintf(addresses[count], sizeof(addresses[count]), "0x%llx", pc);
        indices[count]  = i;
        args[7 + count] = addresses[count];
        count++;
    }
    if (!count) return;
    int pipefd[2];
    if (pipe(pipefd)) return;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t          attrs;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawnattr_init(&attrs);
    posix_spawnattr_setflags(&attrs, POSIX_SPAWN_CLOEXEC_DEFAULT);
    char* env[] = {"PATH=/usr/bin:/bin", NULL};
    pid_t pid;
    int   result = posix_spawn(&pid, args[0], &actions, &attrs, (char* const*)args, env);
    posix_spawnattr_destroy(&attrs);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    if (result) {
        close(pipefd[0]);
        return;
    }
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    char    output[_HF_MAX_FUNCS * 1024];
    size_t  used     = 0;
    int64_t deadline = util_timeNowUSecs() + 1000000;
    bool    done     = false;
    while (util_timeNowUSecs() < deadline && used < sizeof(output) - 1) {
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        if (poll(&pfd, 1, 50) < 0 && errno != EINTR) break;
        ssize_t n = read(pipefd[0], output + used, sizeof(output) - 1 - used);
        if (n > 0)
            used += (size_t)n;
        else if (n == 0) {
            done = true;
            break;
        } else if (errno != EAGAIN && errno != EINTR)
            break;
    }
    close(pipefd[0]);
    if (!done) kill(pid, SIGKILL);
    int   status;
    pid_t waited;
    while ((waited = TEMP_FAILURE_RETRY(waitpid(pid, &status, WNOHANG))) == 0 &&
           util_timeNowUSecs() < deadline)
        util_sleepForMSec(10);
    if (!waited) {
        kill(pid, SIGKILL);
        waited = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        done   = false;
    }
    if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || !done) return;
    output[used] = 0;
    char* next   = output;
    for (size_t i = 0; i < count; i++) {
        char* end = strchr(next, '\n');
        if (!end) break;
        *end = 0;
        if (strncmp(next, "0x", 2) && *next)
            snprintf(
                crash->frames[indices[i]].func, sizeof(crash->frames[indices[i]].func), "%s", next);
        next = end + 1;
    }
}

static void collectCrash(mac_crash_t* crash, task_t task, thread_t thread,
    const arm_thread_state64_t* state, uint64_t encoded, uint64_t subcode) {
    unsigned exception = (encoded >> 20) & 0xf;
    uint64_t code       = encoded & 0xfffff;
    crash->signo       = (encoded >> 24) & 0xff;
    crash->pc          = arm_thread_state64_get_pc(*state);
    crash->address     = exception == EXC_BAD_ACCESS ? subcode : 0;
    crash->hash        = 14695981039346656037ULL ^ crash->signo;
    snprintf(crash->description, sizeof(crash->description),
        "macOS ARM64 %s, exception code 0x%llx", mac_exceptionToString(exception), code);

    image_t* images     = util_Calloc(1024 * sizeof(*images));
    size_t   imageCount = readImages(task, images, 1024);
    addFrame(crash, images, imageCount, crash->pc, false);
    uint64_t lr = codeAddress(arm_thread_state64_get_lr(*state));
    if (lr && lr != crash->pc) addFrame(crash, images, imageCount, lr, true);
    uint64_t fp         = arm_thread_state64_get_fp(*state);
    bool     firstFrame = true;
    while (crash->frameCount < _HF_MAX_FUNCS && fp && !(fp & 15)) {
        uint64_t record[2];
        if (!readMemory(task, fp, record, sizeof(record))) break;
        uint64_t ret = codeAddress(record[1]);
        if (!ret) break;
        if (!firstFrame || ret != lr) addFrame(crash, images, imageCount, ret, true);
        firstFrame = false;
        /* A damaged or cyclic chain must never hang the exception server. */
        if (record[0] <= fp || record[0] - fp > 64 * 1024 * 1024) break;
        fp = record[0];
    }

    util_ssnprintf(crash->registers, sizeof(crash->registers),
        "MACH EXCEPTION REASON: %s\nARM64 REGISTERS:\n", mac_exceptionReason(exception, code));
    for (unsigned i = 0; i < 29; i++)
        util_ssnprintf(crash->registers, sizeof(crash->registers), " x%-2u: 0x%016llx%s", i,
            state->__x[i], i % 3 == 2 ? "\n" : " ");
    util_ssnprintf(crash->registers, sizeof(crash->registers),
        "\n fp: 0x%016llx lr: 0x%016llx sp: 0x%016llx\n pc: 0x%016llx cpsr: 0x%08x\n",
        arm_thread_state64_get_fp(*state), lr, arm_thread_state64_get_sp(*state), crash->pc,
        state->__cpsr);
    uint32_t instruction;
    if (readMemory(task, crash->pc, &instruction, sizeof(instruction)))
        util_ssnprintf(crash->registers, sizeof(crash->registers),
            "ARM64 INSTRUCTION: .long 0x%08x\n", instruction);
    arm_exception_state64_t fault;
    mach_msg_type_number_t  faultCount = ARM_EXCEPTION_STATE64_COUNT;
    const char*             accessType = "unknown";
    if (exception == EXC_BAD_ACCESS && thread_get_state(thread, ARM_EXCEPTION_STATE64,
                                           (thread_state_t)&fault, &faultCount) == KERN_SUCCESS) {
        /* ESR EC and WnR encodings: Apple's XNU osfmk/arm64/proc_reg.h. */
        unsigned ec = fault.__esr >> 26;
        if (ec == 0x24 || ec == 0x25) accessType = (fault.__esr & (1U << 6)) ? "write" : "read";
        if (ec == 0x20 || ec == 0x21) accessType = "execute";
        util_ssnprintf(crash->registers, sizeof(crash->registers), "ESR: 0x%08x FAR: 0x%016llx\n",
            fault.__esr, fault.__far);
    }
    util_ssnprintf(crash->registers, sizeof(crash->registers), "ACCESS TYPE: %s\n", accessType);
    /* All remote reads are complete. Let waitpid finish before optional atos work;
     * readers of the completed report synchronize through crashMutex.
     */
    kill(crash->pid, SIGKILL);
    /* Keep only images represented in this stack. Symbolize later in the worker,
     * outside the server mutex, so other crashing processes can be released promptly.
     */
    size_t used = 0;
    for (size_t i = 0; i < imageCount; i++) {
        for (size_t j = 0; j < crash->frameCount; j++) {
            uint64_t pc = (uintptr_t)crash->frames[j].pc;
            if (pc >= images[i].base && pc < images[i].end) {
                images[used++] = images[i];
                break;
            }
        }
    }
    crash->imageCount = used;
    if (used) {
        crash->images = util_Malloc(used * sizeof(*images));
        memcpy(crash->images, images, used * sizeof(*images));
    }
    free(images);
}

kern_return_t catch_mach_exception_raise(mach_port_t port HF_ATTR_UNUSED,
    mach_port_t thread HF_ATTR_UNUSED, mach_port_t task HF_ATTR_UNUSED,
    exception_type_t exception HF_ATTR_UNUSED, mach_exception_data_t code HF_ATTR_UNUSED,
    mach_msg_type_number_t count HF_ATTR_UNUSED) {
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state(mach_port_t port HF_ATTR_UNUSED,
    exception_type_t exception HF_ATTR_UNUSED, const mach_exception_data_t code HF_ATTR_UNUSED,
    mach_msg_type_number_t count HF_ATTR_UNUSED, int* flavor HF_ATTR_UNUSED,
    const thread_state_t old HF_ATTR_UNUSED, mach_msg_type_number_t oldCount HF_ATTR_UNUSED,
    thread_state_t out HF_ATTR_UNUSED, mach_msg_type_number_t* outCount HF_ATTR_UNUSED) {
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t port HF_ATTR_UNUSED,
    mach_port_t thread, mach_port_t task, exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t count, int* flavor, thread_state_t old, mach_msg_type_number_t oldCount,
    thread_state_t out, mach_msg_type_number_t* outCount) {
    pid_t               pid = 0;
    struct proc_bsdinfo info;
    if (exception != EXC_CRASH || *flavor != ARM_THREAD_STATE64 || count < 2 ||
        oldCount != ARM_THREAD_STATE64_COUNT || oldCount > *outCount ||
        pid_for_task(task, &pid) != KERN_SUCCESS || pid <= 0 ||
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) ||
        info.pbi_ppid != (unsigned)parentPid)
        return KERN_FAILURE;

    /* MIG aligns payloads to four bytes; copy before accessing 64-bit values. */
    arm_thread_state64_t state;
    uint64_t             codes[2];
    memcpy(&state, old, sizeof(state));
    memcpy(codes, code, sizeof(codes));
    unsigned signo = (codes[0] >> 24) & 0xff;
    if (signo == 0 || signo >= NSIG) return KERN_FAILURE;
    memcpy(out, old, oldCount * sizeof(natural_t));
    *outCount          = oldCount;
    mac_crash_t* crash = util_Calloc(sizeof(*crash));
    crash->pid         = pid;
    pthread_mutex_lock(&crashMutex);
    collectCrash(crash, task, thread, &state, codes[0], codes[1]);
    if (crashCount >= crashLimit) {
        /* Bound storage even if a timed-out child could not be matched by waitpid. */
        mac_crash_t** last = &crashes;
        while ((*last)->next) last = &(*last)->next;
        free((*last)->images);
        free(*last);
        *last = NULL;
        crashCount--;
    }
    crash->next = crashes;
    crashes     = crash;
    crashCount++;
    pthread_mutex_unlock(&crashMutex);
    mach_port_deallocate(mach_task_self(), task);
    mach_port_deallocate(mach_task_self(), thread);
    return KERN_SUCCESS;
}

mac_crash_t* mac_arm64TakeCrash(pid_t pid) {
    pthread_mutex_lock(&crashMutex);
    mac_crash_t** next = &crashes;
    while (*next && (*next)->pid != pid) next = &(*next)->next;
    mac_crash_t* found = *next;
    if (found) {
        *next = found->next;
        crashCount--;
    }
    pthread_mutex_unlock(&crashMutex);
    if (found) {
        for (size_t i = 0; i < found->imageCount; i++) symbolizeImage(found, &found->images[i]);
        free(found->images);
        found->images = NULL;
    }
    return found;
}

static void* exceptionServer(void* unused HF_ATTR_UNUSED) {
    for (;;) {
        kern_return_t result = mach_msg_server_once(mach_exc_server, 8192, exceptionPort, 0);
        if (result != KERN_SUCCESS) {
            LOG_F("Mach exception server failed: %s", mach_error_string(result));
        }
    }
    return NULL;
}

bool mac_arm64Init(size_t workers) {
    parentPid  = getpid();
    crashLimit = workers * 2 + 1;
    kern_return_t result =
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort);
    if (result == KERN_SUCCESS)
        result = mach_port_insert_right(
            mach_task_self(), exceptionPort, exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    if (result != KERN_SUCCESS) {
        LOG_E("Cannot allocate crash port: %s", mach_error_string(result));
        return false;
    }
    pthread_t server;
    int       error = pthread_create(&server, NULL, exceptionServer, NULL);
    if (error) {
        LOG_E("Cannot start crash reporter: %s", strerror(error));
        return false;
    }
    pthread_detach(server);
    return true;
}

/* Mach port names are not inherited by fork. Exception rights are: install the
 * send right only around fork, then restore the parent's original handlers.
 * Serialize this brief swap across fuzzing workers. libxpc owns the registered
 * port slots and overwrites them in its atfork handler, so those cannot be used.
 */
pid_t mac_arm64Fork(void) {
    exception_mask_t       masks[EXC_TYPES_COUNT];
    mach_port_t            ports[EXC_TYPES_COUNT];
    exception_behavior_t   behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t  flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    pthread_mutex_lock(&forkMutex);
    kern_return_t result = task_swap_exception_ports(mach_task_self(), EXC_MASK_CRASH,
        exceptionPort, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64, masks,
        &count, ports, behaviors, flavors);
    if (result != KERN_SUCCESS) {
        pthread_mutex_unlock(&forkMutex);
        errno = EIO;
        return -1;
    }
    pid_t pid        = fork();
    int   savedErrno = errno;
    if (pid == 0) {
        count  = EXC_TYPES_COUNT;
        result = task_get_exception_ports(
            mach_task_self(), EXC_MASK_CRASH, masks, &count, ports, behaviors, flavors);
        if (result != KERN_SUCCESS || count != 1 || !MACH_PORT_VALID(ports[0])) _exit(127);
        childExceptionPort = ports[0];
        /* Helpers launched with subproc_System must not inherit our handler. */
        if (task_set_exception_ports(mach_task_self(), EXC_MASK_CRASH, MACH_PORT_NULL,
                EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS)
            _exit(127);
        return 0;
    }
    for (unsigned i = 0; i < count; i++) {
        result = task_set_exception_ports(
            mach_task_self(), masks[i], ports[i], behaviors[i], flavors[i]);
        if (result != KERN_SUCCESS) {
            LOG_F("Cannot restore parent exception ports: %s", mach_error_string(result));
        }
        if (MACH_PORT_VALID(ports[i])) mach_port_deallocate(mach_task_self(), ports[i]);
    }
    pthread_mutex_unlock(&forkMutex);
    errno = savedErrno;
    return pid;
}

bool mac_arm64Spawn(posix_spawnattr_t* attrs) {
    int error = posix_spawnattr_setexceptionports_np(attrs, EXC_MASK_CRASH, childExceptionPort,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    /* Spawn attributes keep the port name, not a send right. Keep it alive until exec. */
    if (error) LOG_E("Cannot set child crash port: %s", strerror(error));
    return error == 0;
}
