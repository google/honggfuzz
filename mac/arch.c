/*
 *
 * honggfuzz - architecture dependent code (MAC OS X)
 * -----------------------------------------
 *
 * Authors: Robert Swiecki <swiecki@google.com>
 *          Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#include "arch.h"

#import <Foundation/Foundation.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/i386/thread_status.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <poll.h>
#include <pthread.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fuzz.h"
#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "mach_exc.h"
#include "mach_excServer.h"
#include "subproc.h"

/*
 * Interface to third_party/CrashReport_*.o
 */
@interface CrashReport : NSObject
- (id)initWithTask:(task_t)task
         exceptionType:(exception_type_t)anExceptionType
         exceptionCode:(mach_exception_data_t)anExceptionCode
    exceptionCodeCount:(mach_msg_type_number_t)anExceptionCodeCount
                thread:(thread_t)thread
     threadStateFlavor:(thread_state_flavor_t)aThreadStateFlavor
           threadState:(thread_state_data_t)aThreadState
      threadStateCount:(mach_msg_type_number_t)aThreadStateCount;
@end

/*
 * Global to have exception port available in the collection thread
 */
static mach_port_t g_exception_port = MACH_PORT_NULL;

/*
 * From xnu/bsd/sys/proc_internal.h
 */
#define PID_MAX 99999

/*
 * Global to store crash info in exception handler thread
 */
run_t g_fuzzer_crash_information[PID_MAX + 1];

/*
 * Global to store the CrashWrangler generated callstack from
 * the exception handler thread
 */
static char* g_fuzzer_crash_callstack[PID_MAX + 1];

/*
 * Global to have a unique service name for each honggfuzz process
 */
char g_service_name[256];

struct {
    bool        important;
    const char* descr;
} arch_sigs[NSIG];

__attribute__((constructor)) void arch_initSigs(void) {
    for (int x = 0; x < NSIG; x++) arch_sigs[x].important = false;

    arch_sigs[SIGILL].important  = true;
    arch_sigs[SIGILL].descr      = "SIGILL";
    arch_sigs[SIGFPE].important  = true;
    arch_sigs[SIGFPE].descr      = "SIGFPE";
    arch_sigs[SIGSEGV].important = true;
    arch_sigs[SIGSEGV].descr     = "SIGSEGV";
    arch_sigs[SIGBUS].important  = true;
    arch_sigs[SIGBUS].descr      = "SIGBUS";
    arch_sigs[SIGABRT].important = true;
    arch_sigs[SIGABRT].descr     = "SIGABRT";

    /* Is affected from tmoutVTALRM flag */
    arch_sigs[SIGVTALRM].important = false;
    arch_sigs[SIGVTALRM].descr     = "SIGVTALRM";
}

const char* exception_to_string(int exception) {
    switch (exception) {
    case EXC_BAD_ACCESS:
        return "EXC_BAD_ACCESS";
    case EXC_BAD_INSTRUCTION:
        return "EXC_BAD_INSTRUCTION";
    case EXC_ARITHMETIC:
        return "EXC_ARITHMETIC";
    case EXC_EMULATION:
        return "EXC_EMULATION";
    case EXC_SOFTWARE:
        return "EXC_SOFTWARE";
    case EXC_BREAKPOINT:
        return "EXC_BREAKPOINT";
    case EXC_SYSCALL:
        return "EXC_SYSCALL";
    case EXC_MACH_SYSCALL:
        return "EXC_MACH_SYSCALL";
    case EXC_RPC_ALERT:
        return "EXC_RPC_ALERT";
    case EXC_CRASH:
        return "EXC_CRASH";
    }
    return "UNKNOWN";
}

static void arch_generateReport(run_t* run, int termsig) {
    run->report[0] = '\0';
    util_ssnprintf(run->report, sizeof(run->report), "ORIG_FNAME: %s\n", run->dynfile->path);
    util_ssnprintf(run->report, sizeof(run->report), "FUZZ_FNAME: %s\n", run->crashFileName);
    util_ssnprintf(run->report, sizeof(run->report), "PID: %d\n", run->pid);
    util_ssnprintf(
        run->report, sizeof(run->report), "SIGNAL: %s (%d)\n", arch_sigs[termsig].descr, termsig);
    util_ssnprintf(
        run->report, sizeof(run->report), "EXCEPTION: %s\n", exception_to_string(run->exception));
    util_ssnprintf(run->report, sizeof(run->report), "FAULT ADDRESS: %" PRIx64 "\n", run->access);
    util_ssnprintf(run->report, sizeof(run->report), "CRASH FRAME PC: %" PRIx64 "\n", run->pc);
    util_ssnprintf(run->report, sizeof(run->report), "STACK HASH: %016llx\n", run->backtrace);
    if (g_fuzzer_crash_callstack[run->pid]) {
        util_ssnprintf(
            run->report, sizeof(run->report), "STACK: \n%s\n", g_fuzzer_crash_callstack[run->pid]);
    } else {
        util_ssnprintf(run->report, sizeof(run->report), "STACK: \n Callstack not available.\n");
    }

    return;
}

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static void arch_analyzeSignal(run_t* run, int status) {
    /*
     * Resumed by delivery of SIGCONT
     */
    if (WIFCONTINUED(status)) {
        return;
    }

    /*
     * Boring, the process just exited
     */
    if (WIFEXITED(status)) {
        LOG_D("Process (pid %d) exited normally with status %d", run->pid, WEXITSTATUS(status));
        return;
    }

    /*
     * Shouldn't really happen, but, well..
     */
    if (!WIFSIGNALED(status)) {
        LOG_E("Process (pid %d) exited with the following status %d, please report that as a bug",
            run->pid, status);
        return;
    }

    int termsig = WTERMSIG(status);
    LOG_D("Process (pid %d) killed by signal %d '%s'", run->pid, termsig, strsignal(termsig));
    if (!arch_sigs[termsig].important) {
        LOG_D("It's not that important signal, skipping");
        return;
    }

    /*
     * Signal is interesting
     */
    /*
     * Increase crashes counter presented by ASCII display
     */
    ATOMIC_POST_INC(run->global->cnts.crashesCnt);

    /*
     * Get data from exception handler
     */
    run->pc        = g_fuzzer_crash_information[run->pid].pc;
    run->exception = g_fuzzer_crash_information[run->pid].exception;
    run->access    = g_fuzzer_crash_information[run->pid].access;
    run->backtrace = g_fuzzer_crash_information[run->pid].backtrace;

    defer {
        if (g_fuzzer_crash_callstack[run->pid]) {
            free(g_fuzzer_crash_callstack[run->pid]);
            g_fuzzer_crash_callstack[run->pid] = NULL;
        }
    };

    /*
     * Check if stackhash is blocklisted
     */
    if (run->global->feedback.blocklist &&
        (fastArray64Search(run->global->feedback.blocklist, run->global->feedback.blocklistCnt,
             run->backtrace) != -1)) {
        LOG_I("Blacklisted stack hash '%" PRIx64 "', skipping", run->backtrace);
        ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
        return;
    }

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->dynfile->path);
    } else if (run->global->io.saveUnique) {
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.%s.PC.%.16llx.STACK.%.16llx.ADDR.%.16llx.%s", run->global->io.crashDir,
            arch_sigs[termsig].descr, exception_to_string(run->exception), run->pc, run->backtrace,
            run->access, run->global->io.fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H.%M.%S", localtmstr, sizeof(localtmstr), time(NULL));

        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.%s.PC.%.16llx.STACK.%.16llx.ADDR.%.16llx.TIME.%s.PID.%.5d.%s",
            run->global->io.crashDir, arch_sigs[termsig].descr, exception_to_string(run->exception),
            run->pc, run->backtrace, run->access, localtmstr, run->pid, run->global->io.fileExtn);
    }

    if (files_exists(run->crashFileName)) {
        LOG_I("Crash (dup): '%s' already exists, skipping", run->crashFileName);
        // Clear filename so that verifier can understand we hit a duplicate
        memset(run->crashFileName, 0, sizeof(run->crashFileName));
        return;
    }

    if (!files_writeBufToFile(run->crashFileName, run->dynfile->data, run->dynfile->size,
            O_CREAT | O_EXCL | O_WRONLY)) {
        LOG_E("Couldn't save crash as '%s'", run->crashFileName);
        return;
    }

    LOG_I("Crash: saved as '%s'", run->crashFileName);

    ATOMIC_POST_INC(run->global->cnts.uniqueCrashesCnt);
    /* If unique crash found, reset dynFile counter */
    ATOMIC_CLEAR(run->global->cfg.dynFileIterExpire);

    arch_generateReport(run, termsig);
}

pid_t arch_fork(run_t* run HF_ATTR_UNUSED) {
    return fork();
}

bool arch_launchChild(run_t* run) {
    LOG_D("Launching '%s' on file '%s' (%s mode)", run->args[0],
        run->global->exe.persistent ? "PERSISTENT_MODE" : _HF_INPUT_FILE_PATH,
        run->global->exe.fuzzStdin ? "stdin" : "file");

    /*
     * Get child's bootstrap port.
     */
    mach_port_t child_bootstrap = MACH_PORT_NULL;
    if (task_get_bootstrap_port(mach_task_self(), &child_bootstrap) != KERN_SUCCESS) {
        return false;
    }

    /*
     * Get exception port.
     */
    mach_port_t exception_port = MACH_PORT_NULL;

    if (bootstrap_look_up(child_bootstrap, g_service_name, &exception_port) != KERN_SUCCESS) {
        return false;
    }

    /*
     * Here we register the exception port in the child
     */
    if (task_set_exception_ports(mach_task_self(), EXC_MASK_CRASH, exception_port,
            EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
            MACHINE_THREAD_STATE) != KERN_SUCCESS) {
        return false;
    }

    /* alarm persists across forks, so disable it here */
    alarm(0);
    execvp(run->args[0], (char* const*)run->args);
    alarm(1);

    return false;
}

void arch_prepareParent(run_t* run HF_ATTR_UNUSED) {
}

void arch_prepareParentAfterFork(run_t* run HF_ATTR_UNUSED) {
}

static bool arch_checkWait(run_t* run) {
    /* All queued wait events must be tested when SIGCHLD was delivered */
    for (;;) {
        int   status;
        pid_t pid = TEMP_FAILURE_RETRY(wait4(run->pid, &status, WNOHANG, NULL));
        if (pid == 0) {
            return false;
        }
        if (pid == -1 && errno == ECHILD) {
            LOG_D("No more processes to track");
            return true;
        }
        if (pid == -1) {
            PLOG_F("wait4(pid/session=%d) failed", (int)run->pid);
        }

        arch_analyzeSignal(run, status);

        LOG_D("pid=%d returned with status: %s", pid, subproc_StatusToStr(status));

        if (pid == run->pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            if (run->global->exe.persistent) {
                if (!fuzz_isTerminating()) {
                    LOG_W("Persistent mode: PID %d exited with status: %s", pid,
                        subproc_StatusToStr(status));
                }
            }
            return true;
        }
    }
}

void arch_reapChild(run_t* run) {
    for (;;) {
        if (subproc_persistentModeStateMachine(run)) {
            break;
        }

        subproc_checkTimeLimit(run);
        subproc_checkTermination(run);

        if (run->global->exe.persistent) {
            struct pollfd pfd = {
                .fd     = run->persistentSock,
                .events = POLLIN,
            };
            int r = poll(&pfd, 1, 250 /* 0.25s */);
            if (r == 0 || (r == -1 && errno == EINTR)) {
            }
            if (r == -1 && errno != EINTR) {
                PLOG_F("poll(fd=%d)", run->persistentSock);
            }
        } else {
            /* Return with SIGIO, SIGCHLD */
            int sig;
            if (sigwait(&run->global->exe.waitSigSet, &sig) != 0) {
                PLOG_F("sigwait(SIGIO|SIGCHLD)");
            }
        }

        if (arch_checkWait(run)) {
            run->pid = 0;
            break;
        }
    }
}

void arch_reapKill(void) {
}

void* wait_for_exception() {
    while (1) {
        mach_msg_server_once(mach_exc_server, 4096, g_exception_port, MACH_MSG_OPTION_NONE);
    }
}

/*
 * Called once before fuzzing starts. Prepare mach ports for attaching crash reporter.
 */
bool arch_archInit(honggfuzz_t* hfuzz) {
    char plist[PATH_MAX];
    snprintf(plist, sizeof(plist), "/Users/%s/Library/Preferences/com.apple.DebugSymbols.plist",
        getlogin());

    if (files_exists(plist)) {
        LOG_W("honggfuzz won't work if DBGShellCommands are set in "
              "~/Library/Preferences/com.apple.DebugSymbols.plist");
    }

    /*
     * Allocate exception port.
     */
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exception_port) !=
        KERN_SUCCESS) {
        return false;
    }

    /*
     * Insert exception receive port.
     */
    if (mach_port_insert_right(mach_task_self(), g_exception_port, g_exception_port,
            MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        return false;
    }

    /*
     * Get bootstrap port.
     */
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_bootstrap_port(mach_task_self(), &bootstrap) != KERN_SUCCESS) {
        return false;
    }

    /*
     * Generate and register exception port service.
     */
    snprintf(g_service_name, sizeof(g_service_name), "com.google.code.honggfuzz.%d",
        (int)util_rndGet(0, 999999));
    if (bootstrap_check_in(bootstrap, g_service_name, &g_exception_port) != KERN_SUCCESS) {
        return false;
    }

    /*
     * Create a collection thread to catch the exceptions from the
     * children
     */
    pthread_t exception_thread;

    if (pthread_create(&exception_thread, NULL, wait_for_exception, 0)) {
        LOG_F("Parent: could not create thread to wait for child's exception");
        return false;
    }

    if (pthread_detach(exception_thread)) {
        LOG_F("Parent: could not detach thread to wait for child's exception");
        return false;
    }

    /* Default is false */
    arch_sigs[SIGVTALRM].important = hfuzz->timing.tmoutVTALRM;

    return true;
}

#ifdef DEBUG
/*
 * Write the crash report to DEBUG
 */
static void write_crash_report(thread_port_t thread, task_port_t task, exception_type_t exception,
    mach_exception_data_t code, mach_msg_type_number_t code_count, int* flavor,
    thread_state_t in_state, mach_msg_type_number_t in_state_count) {
    NSAutoreleasePool* pool         = [[NSAutoreleasePool alloc] init];
    CrashReport*       _crashReport = nil;

    _crashReport = [[CrashReport alloc] initWithTask:task
                                       exceptionType:exception
                                       exceptionCode:code
                                  exceptionCodeCount:code_count
                                              thread:thread
                                   threadStateFlavor:*flavor
                                         threadState:(thread_state_t)in_state
                                    threadStateCount:in_state_count];

    NSString* crashDescription = [_crashReport description];
    char*     description      = (char*)[crashDescription UTF8String];

    LOG_D("CrashReport: %s", description);

    [_crashReport release];
    [pool drain];
}
#endif

/* Hash the callstack in an unique way */
static uint64_t hash_callstack(thread_port_t thread, task_port_t task, exception_type_t exception,
    mach_exception_data_t code, mach_msg_type_number_t code_count, int* flavor,
    thread_state_t in_state, mach_msg_type_number_t in_state_count) {
    NSAutoreleasePool* pool         = [[NSAutoreleasePool alloc] init];
    CrashReport*       _crashReport = nil;

    _crashReport = [[CrashReport alloc] initWithTask:task
                                       exceptionType:exception
                                       exceptionCode:code
                                  exceptionCodeCount:code_count
                                              thread:thread
                                   threadStateFlavor:*flavor
                                         threadState:(thread_state_t)in_state
                                    threadStateCount:in_state_count];

    NSString* crashDescription = [_crashReport description];
    char*     description      = (char*)[crashDescription UTF8String];

    /*
     * The callstack begins with the following word
     */
    char* callstack = strstr(description, "Crashed:");

    if (callstack == NULL) {
        LOG_F("Could not find callstack in crash report %s", description);
    }

    /*
     * Scroll forward to the next newline
     */
    char* callstack_start = strstr(callstack, "\n");

    if (callstack_start == NULL) {
        LOG_F("Could not find callstack start in crash report %s", description);
    }

    /*
     * Skip the newline
     */
    callstack_start++;

    /*
     * Determine the end of the callstack
     */
    char* callstack_end = strstr(callstack_start, "\n\nThread");

    if (callstack_end == NULL) {
        LOG_F("Could not find callstack end in crash report %s", description);
    }

    if (callstack_end <= callstack_start) {
        LOG_F("Malformed callstack: %s", description);
    }

/*
 * Check for too large callstack.
 */
#define MAX_CALLSTACK_SIZE 4096
    const size_t callstack_size = (callstack_end - callstack_start);
    if (callstack_size > MAX_CALLSTACK_SIZE) {
        LOG_W("Too large callstack (%zu bytes), truncating to %d bytes", callstack_size,
            MAX_CALLSTACK_SIZE);
        callstack_start[MAX_CALLSTACK_SIZE] = '\0';
        callstack_end                       = callstack_start + MAX_CALLSTACK_SIZE;
    }

    pid_t pid;
    pid_for_task(task, &pid);

    char** buf = &g_fuzzer_crash_callstack[pid];
    /*
     * Check for memory leaks. This shouldn't happen.
     */
    if (*buf) {
        LOG_E("Memory leak: arch_analyzeSignal didn't free previous callstack");
        free(*buf);
        *buf = NULL;
    }

    /*
     * Copy the CrashWrangler formatted callstack and make sure
     * it's NULL-terminated.
     */
    *callstack_end = '\0';
    *buf           = util_StrDup(callstack_start);

    /*
     *
     * For each line, we only take the last three nibbles from the
     * address.
     *
     * Sample outputs:
     *
     * 0 libsystem_kernel.dylib 0x00007fff80514d46 __kill + 10
     * 1 libsystem_c.dylib 0x00007fff85731ec0 __abort + 193
     * 2 libsystem_c.dylib 0x00007fff85732d17 __stack_chk_fail + 195
     * 3 stack_buffer_overflow64-stripped 0x000000010339def5 0x10339d000 + 3829
     * 4 ??? 0x4141414141414141 0 + 4702111234474983745
     *
     * 0 libsystem_kernel.dylib 0x00007fff80514d46 __kill + 10
     * 1 libsystem_c.dylib 0x00007fff85731ec0 __abort + 193
     * 2 libsystem_c.dylib 0x00007fff85732d17 __stack_chk_fail + 195
     * 3 stack_buffer_overflow64 0x0000000108f41ef5 main + 133
     * 4 ??? 0x4141414141414141 0 + 4702111234474983745
     *
     * 0 libsystem_kernel.dylib 0x940023ba __kill + 10
     * 1 libsystem_kernel.dylib 0x940014bc kill$UNIX2003 + 32
     * 2 libsystem_c.dylib 0x926f362e __abort + 246
     * 3 libsystem_c.dylib 0x926c2b60 __chk_fail + 49
     * 4 libsystem_c.dylib 0x926c2bf9 __memset_chk + 53
     * 5 stack_buffer_overflow32-stripped 0x00093ee5 0x93000 + 3813
     * 6 libdyld.dylib 0x978c6725 start + 1
     *
     * 0 libsystem_kernel.dylib 0x940023ba __kill + 10
     * 1 libsystem_kernel.dylib 0x940014bc kill$UNIX2003 + 32
     * 2 libsystem_c.dylib 0x926f362e __abort + 246
     * 3 libsystem_c.dylib 0x926c2b60 __chk_fail + 49
     * 4 libsystem_c.dylib 0x926c2bf9 __memset_chk + 53
     * 5 stack_buffer_overflow32 0x0003cee5 main + 117
     * 6 libdyld.dylib 0x978c6725 start + 1
     *
     */

    uint64_t hash = 0;
    char*    pos  = callstack_start;

    /*
     * Go through each line until we run out of lines
     */
    while (strstr(pos, "\t") != NULL) {
        /*
         * Format: dylib spaces tab address space symbol space plus space offset
         * Scroll pos forward to the last three nibbles of the address.
         */
        if ((pos = strstr(pos, "\t")) == NULL) break;
        if ((pos = strstr(pos, " ")) == NULL) break;
        pos = pos - 3;
        /*
         * Hash the last three nibbles
         */
        hash ^= util_hash(pos, 3);
        /*
         * Scroll pos one forward to skip the current tab
         */
        pos++;
    }

    LOG_D("Callstack hash %llu", hash);

    [_crashReport release];
    [pool drain];

    return hash;
}

kern_return_t catch_mach_exception_raise(mach_port_t exception_port, mach_port_t thread,
    mach_port_t task, exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt) {
    LOG_F("This function should never get called");
    return KERN_SUCCESS;
}

kern_return_t catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception, const mach_exception_data_t code, mach_msg_type_number_t codeCnt,
    int* flavor, const thread_state_t old_state, mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state, mach_msg_type_number_t* new_stateCnt) {
    LOG_F("This function should never get called");
    return KERN_SUCCESS;
}

kern_return_t catch_mach_exception_raise_state_identity(
    __attribute__((unused)) exception_port_t exception_port, thread_port_t thread, task_port_t task,
    exception_type_t exception, mach_exception_data_t code, mach_msg_type_number_t code_count,
    int* flavor, thread_state_t in_state, mach_msg_type_number_t in_state_count,
    thread_state_t out_state, mach_msg_type_number_t* out_state_count) {
    if (exception != EXC_CRASH) {
        LOG_F("Got non EXC_CRASH! This should not happen.");
    }

    /*
     * We will save our results to the honggfuzz_t global
     */
    pid_t pid;
    pid_for_task(task, &pid);
    LOG_D("Crash of pid %d", pid);

    run_t* run = &g_fuzzer_crash_information[pid];

    /*
     * Get program counter.
     * Cast to void* in order to silence the alignment warnings
     */
#if defined(__x86_64__)
    x86_thread_state_t* platform_in_state = ((x86_thread_state_t*)(void*)in_state);
#elif defined(__aarch64__)
    arm_thread_state_t* platform_in_state = ((arm_thread_state_t*)(void*)in_state);
#endif /* defined(__x86_64__) */

#if defined(__x86_64__)
    if (x86_THREAD_STATE32 == platform_in_state->tsh.flavor) {
        run->pc = platform_in_state->uts.ts32.__eip;
    } else {
        run->pc = platform_in_state->uts.ts64.__rip;
    }
#elif defined(__aarch64__)
    run->pc = platform_in_state->__pc;
#endif /* defined(__x86_64__) */

    /*
     * Get the exception type
     */
    exception_type_t exception_type = ((code[0] >> 20) & 0x0F);
    if (exception_type == 0) {
        exception_type = EXC_CRASH;
    }
    run->exception = exception_type;

    /*
     * Get the access address.
     */
    mach_exception_data_type_t exception_data[2];
    memcpy(exception_data, code, sizeof(exception_data));
    exception_data[0] = (code[0] & ~(0x00000000FFF00000));
    exception_data[1] = code[1];

    mach_exception_data_type_t access_address = exception_data[1];
    run->access                               = (uint64_t)access_address;

    /*
     * Get a hash of the callstack
     */
    uint64_t hash =
        hash_callstack(thread, task, exception, code, code_count, flavor, in_state, in_state_count);
    run->backtrace = hash;

#ifdef DEBUG
    write_crash_report(thread, task, exception, code, code_count, flavor, in_state, in_state_count);
#endif

    /*
     * Cleanup
     */
    if (mach_port_deallocate(mach_task_self(), task) != KERN_SUCCESS) {
        LOG_W("Exception Handler: Could not deallocate task");
    }

    if (mach_port_deallocate(mach_task_self(), thread) != KERN_SUCCESS) {
        LOG_W("Exception Handler: Could not deallocate thread");
    }

    /*
     * KERN_SUCCESS indicates that this should not be forwarded to other crash
     * handlers
     */
    return KERN_SUCCESS;
}

bool arch_archThreadInit(run_t* run HF_ATTR_UNUSED) {
    return true;
}
