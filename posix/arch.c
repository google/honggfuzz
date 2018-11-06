/*
 *
 * honggfuzz - architecture dependent code (POSIX / SIGNAL)
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *         riusksk <riusksk@qq.com>
 *
 * Copyright 2010-2015 by Google Inc. All Rights Reserved.
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

#include "../common.h"
#include "../arch.h"

#include <poll.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../files.h"
#include "../log.h"
#include "../sancov.h"
#include "../subproc.h"
#include "../util.h"

#define ARGS_MAX 512

/*  *INDENT-OFF* */
struct {
    bool important;
    const char *descr;
} arch_sigs[NSIG] = {
    [0 ... (NSIG - 1)].important = false,
    [0 ... (NSIG - 1)].descr = "UNKNOWN",

    [SIGILL].important = true,
    [SIGILL].descr = "SIGILL",
    [SIGFPE].important = true,
    [SIGFPE].descr = "SIGFPE",
    [SIGSEGV].important = true,
    [SIGSEGV].descr = "SIGSEGV",
    [SIGBUS].important = false,
    [SIGBUS].descr = "SIGBUS",
    [SIGABRT].important = true,
    [SIGABRT].descr = "SIGABRT"
};
/*  *INDENT-ON* */

bool arch_isExistProcess(char *name)
{
    char buffer[128];
    char result[128];
    char cmd[128];

    snprintf(cmd, sizeof(cmd), "taskkill /F /IM %s 2>/dev/null", name);

    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
          LOG_E("popen fail");
          return false;
    }

    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe)) {
                strcat(result,buffer);
        }
    }
    pclose(pipe);

    //if (strstr(result, "成功")) {
    if (strstr(result, "PID")) {       
        return true;    // crash
    } else {
        return false;   // no crash
    }
}

/* Return true if windows GUI app crash */
bool arch_checkCrash() {
    if (arch_isExistProcess("cdb.exe")) {
        return true;
    } else if (arch_isExistProcess("DWWIN.EXE")) {
        return true;
    } else if (arch_isExistProcess("WerFault.exe")) {
        return true;
    }
    return false;
}

void arch_getFileName(honggfuzz_t * hfuzz, char *fileName)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    snprintf(fileName, PATH_MAX, "%s/honggfuzz.%d.%lu.%" PRIx64 ".%s", hfuzz->workDir,
             (int)getpid(), (unsigned long int)tv.tv_sec, util_rnd64(), hfuzz->fileExtn);
}

char* arch_get_str_value(char * input_string, char *check_string)
{
    char *pos;
    char *tmp;
    char *newline;
    char *start;
    int length;
    
    pos = strstr(input_string, check_string);
    if (pos) {
        newline = strstr(pos, "\n");

        if (!strcmp(check_string,"Recommended Bug Title:")) {
            start = strstr(pos, " at ") + 4;
        } else {
            start = pos + strlen(check_string) + 1;
        }

        length = newline - start;
        tmp = (char *)malloc(ARGS_MAX);
        memset(tmp, 0, ARGS_MAX);
        strncpy(tmp, start, length);
        LOG_D("cdb ret value: %s\n", tmp);
        return tmp;
    }else{
        return "Unknow";
    }
}

// cygwin下各磁盘目录会变成 “/cygdrive/磁盘id/”，因此需要还原下，否则文件路径可能无法识别
char* arch_fix_cygdrive_path(char cyg_path[])
{   
    static char tmp[PATH_MAX];
    int offset = strlen("/cygdrive/");

    strncpy(tmp, cyg_path, strlen(cyg_path));
    *(tmp + strlen(cyg_path)) = '\0';

    if (strstr(tmp, "/cygdrive/")) {
        tmp[offset-1] = tmp[offset];
        tmp[offset] = ':';
        return &tmp[offset-1];
    }
    return &cyg_path[0];
}

bool arch_runVerifier(honggfuzz_t * hfuzz, fuzzer_t * crashedFuzzer)
{
    int crashFd = -1;
    uint8_t *crashBuf = NULL;
    off_t crashFileSz = 0;

    crashBuf = files_mapFile(crashedFuzzer->crashFileName, &crashFileSz, &crashFd, false);
    if (crashBuf == NULL) {
        LOG_E("Couldn't open and map '%s' in R/O mode", crashedFuzzer->crashFileName);
        return false;
    }
    defer {
        munmap(crashBuf, crashFileSz);
        close(crashFd);
    };

    LOG_I("Launching verifier for %" PRIx64 " hash", crashedFuzzer->backtrace);
    for (int i = 0; i < _HF_VERIFIER_ITER; i++) {
        fuzzer_t vFuzzer = {
            .pid = 0,
            .persistentPid = 0,
            .timeStartedMillis = util_timeNowMillis(),
            .crashFileName = {0},
            .pc = 0ULL,
            .backtrace = 0ULL,
            .access = 0ULL,
            .exception = 0,
            .dynamicFileSz = 0,
            .dynamicFile = NULL,
            .sanCovCnts = {
                           .hitBBCnt = 0ULL,
                           .totalBBCnt = 0ULL,
                           .dsoCnt = 0ULL,
                           .iDsoCnt = 0ULL,                          
                           .newBBCnt = 0ULL,
                           .lastBBTime = 0ULL,
                           .crashesCnt = 0ULL,
                           },
            .report = {'\0'},
            .mainWorker = false,
            .fuzzNo = crashedFuzzer->fuzzNo,
            .persistentSock = -1,
            .tmOutSignaled = false,

            .linux = {
                      .hwCnts = {
                                 .cpuInstrCnt = 0ULL,
                                 .cpuBranchCnt = 0ULL,
                                 .bbCnt = 0ULL,
                                 .newBBCnt = 0ULL,
                                 .softCntPc = 0ULL,
                                 .softCntCmp = 0ULL,
                                 },
                      .perfMmapBuf = NULL,
                      .perfMmapAux = NULL,
                      .attachedPid = 0,
                      },
        };

        if (arch_archThreadInit(hfuzz, &vFuzzer) == false) {
            LOG_F("Could not initialize the thread");
        }

        arch_getFileName(hfuzz, vFuzzer.fileName);
        if (files_writeBufToFile(vFuzzer.fileName, crashBuf, crashFileSz,
             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC) == false) {
            LOG_E("Couldn't write buffer to file '%s'", vFuzzer.fileName);
            return false;
        }

        if (subproc_Run(hfuzz, &vFuzzer) == false) {        
            LOG_F("subproc_Run()");
         }

    }

    // 上述崩溃验证通过后，使用bugid(需要管理员权限开启PageHeap)或者cdb（可能延时较长）分析崩溃信息，
    // 并将崩溃信息标记到文件名中，同时也可作为去重的依据
    char buffer[1024*32] = {0};
    char result[1024*32] = {0};
    char cmd[1024] = {0};
    char *exploitable;
    char *description;
    char *hash;

    snprintf(cmd, sizeof(cmd), "cdb -c 'g;g;!load msec.dll;!exploitable -v;q' '%s' '%s' 2>/dev/null",
            arch_fix_cygdrive_path(hfuzz->cmdline[0]), arch_fix_cygdrive_path(crashedFuzzer->crashFileName));
    LOG_D("cmd=%s\n", cmd);
    FILE* pipe = popen(cmd, "r");
    if (!pipe){
          LOG_E("cdb run fail");
          return 0;
    }

    while(!feof(pipe)) {
        if(fgets(buffer, sizeof(buffer), pipe)){
                strcat(result,buffer);
        }
    }
    pclose(pipe);
    LOG_D("cdb result: %s", result);

    exploitable = arch_get_str_value(result, "Exploitability Classification:");
    description = arch_get_str_value(result, "Short Description:");
    hash = arch_get_str_value(result, "Recommended Bug Title:");

    char verFile[PATH_MAX] = { 0 };
    if (strcmp(hash,"Unknow") && strcmp(exploitable,"Unknow") && strcmp(description,"Unknow")) {
        snprintf(verFile, sizeof(verFile), "%s_%s_%s.%s", exploitable, description, hash, hfuzz->fileExtn);
    } else {
        snprintf(verFile, sizeof(verFile), "%s.verified", crashedFuzzer->crashFileName);
    }
    LOG_W("%s", verFile);
    /* Copy file with new suffix & remove original copy */
    bool dstFileExists = false;
    if (files_copyFile(crashedFuzzer->crashFileName, verFile, &dstFileExists)) {
        LOG_I("Successfully verified, saving as (%s)", verFile);
        ATOMIC_POST_INC(hfuzz->verifiedCrashesCnt);
        unlink(crashedFuzzer->crashFileName);
    } else {
        if (dstFileExists) {
            LOG_I("It seems that '%s' already exists, skipping", verFile);
        } else {
            LOG_E("Couldn't copy '%s' to '%s'", crashedFuzzer->crashFileName, verFile);
            return false;
        }
    }

    return true;
}

void delay(int seconds)
{
   clock_t start = clock();
   clock_t lay = (clock_t)seconds * CLOCKS_PER_SEC;
 
   while ((clock()-start) < lay) ;
}

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static bool arch_analyzeSignal(honggfuzz_t * hfuzz, int status, fuzzer_t * fuzzer)
{
    /*
     * Resumed by delivery of SIGCONT
     */
    if (WIFCONTINUED(status)) {
        return false;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        sancov_Analyze(hfuzz, fuzzer);
    }

    /*
     * Boring, the process just exited
     */
    if (WIFEXITED(status)) {
        LOG_D("Process (pid %d) exited normally with status %d", fuzzer->pid, WEXITSTATUS(status));
        
        if( strstr(hfuzz->cmdline[0], "EdgeDbg") ){
            delay(1);    // 延时1秒，因为win10下启动Edge或者图片查看只能通过其它程序拉起，所以增加延时避免过早退出
        }

        return true;
    }

    /*
     * Shouldn't really happen, but, well..
     */
    if (!WIFSIGNALED(status)) {
        LOG_E("Process (pid %d) exited with the following status %d, please report that as a bug",
              fuzzer->pid, status);
        return true;
    }

    int termsig = WTERMSIG(status);
    LOG_D("Process (pid %d) killed by signal %d '%s'", fuzzer->pid, termsig, strsignal(termsig));
    if (!arch_sigs[termsig].important) {
        LOG_D("It's not that important signal, skipping");

        // Check Windows GUI app crash
        if(arch_checkCrash()){
            LOG_W("Process (pid %d) may crash !", fuzzer->pid);
        }else{
            LOG_D("WerFault.exe Process Not Found");
            return true;
        }
    }

    LOG_D("Save crash file");

    char localtmstr[PATH_MAX];
    util_getLocalTime("%F.%H.%M.%S", localtmstr, sizeof(localtmstr), time(NULL));

    /* If dry run mode, copy file with same name into workspace */
    if (hfuzz->origFlipRate == 0.0L && hfuzz->useVerifier) {
        snprintf(fuzzer->crashFileName, sizeof(fuzzer->crashFileName), "%s.%s", arch_sigs[termsig].descr, fuzzer->origFileName);
    } else {
        snprintf(fuzzer->crashFileName, sizeof(fuzzer->crashFileName), "%s/%s.TIME.%s.orig.%s.%s",
                 hfuzz->workDir, arch_sigs[termsig].descr, localtmstr, fuzzer->origFileName,
                 hfuzz->keepext?fuzzer->ext:hfuzz->fileExtn);
    }

    /*
     * All crashes are marked as unique due to lack of information in POSIX arch
     */
    ATOMIC_POST_INC(hfuzz->crashesCnt);
    ATOMIC_POST_INC(hfuzz->uniqueCrashesCnt);

    if (files_exists(fuzzer->crashFileName)) {
        LOG_I("It seems that '%s' already exists, skipping", fuzzer->crashFileName);
        // Clear filename so that verifier can understand we hit a duplicate
        memset(fuzzer->crashFileName, 0, sizeof(fuzzer->crashFileName));
        return true;
    }

    LOG_I("Crash! Saving the '%s' as '%s'", fuzzer->fileName, fuzzer->crashFileName);

    if (files_writeBufToFile(fuzzer->crashFileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
         O_CREAT | O_EXCL | O_WRONLY) == false) {
        LOG_E("Couldn't copy '%s' to '%s'", fuzzer->fileName, fuzzer->crashFileName);
    }

    return true;
}

pid_t arch_fork(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer UNUSED)
{
    return fork();
}

bool arch_launchChild(honggfuzz_t * hfuzz, char *fileName)
{
    char *args[ARGS_MAX + 2];
    char argData[PATH_MAX] = { 0 };
    int x;

    char current_absolute_path[ARGS_MAX];
    //获取当前目录绝对路径
    if (NULL == getcwd(current_absolute_path, ARGS_MAX))
    {
        LOG_E("Get Current Dir Error");
        exit(-1);
    }

    for (x = 0; x < ARGS_MAX && hfuzz->cmdline[x]; x++) {
        if (!hfuzz->fuzzStdin && strcmp(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER) == 0) {
        // 有些软件必须使用绝对路径，否则会出错，比如 Adobe Digital Editions
        // cygwin下各磁盘目录会变成 “/cygdrive/磁盘id/”，因此需要还原下，否则目标程序可能无法识别
        args[x] = arch_fix_cygdrive_path(current_absolute_path);
        strcat(args[x], "/");
        strcat(args[x], fileName);
        LOG_D("args[x]=%s", args[x]);

        } else if (!hfuzz->fuzzStdin && strstr(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER)) {
            const char *off = strstr(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER);
            snprintf(argData, PATH_MAX, "%.*s%s", (int)(off - hfuzz->cmdline[x]), hfuzz->cmdline[x],
                     fileName);
            args[x] = argData;
        } else {
            args[x] = hfuzz->cmdline[x];
        }
    }

    args[x++] = NULL;

    LOG_D("Launching '%s' on file '%s'", args[0], fileName);

    execvp(args[0], args);

    return false;
}

void arch_prepareChild(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer UNUSED)
{
}

void arch_checkTimeLimit(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - fuzzer->timeStartedMillis;
    if (diffMillis > (hfuzz->tmOut * 1000)) {
        LOG_D("PID %d took too much time (limit %ld s). Sending SIGKILL",
              fuzzer->pid, hfuzz->tmOut);
        kill(fuzzer->pid, SIGKILL);
        ATOMIC_POST_INC(hfuzz->timeoutedCnt);
    }
}

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    for (;;) {
        subproc_checkTimeLimit(hfuzz, fuzzer);
        if (hfuzz->persistent) {
            struct pollfd pfd = {
                .fd = fuzzer->persistentSock,
                .events = POLLIN,
            };
            int r = poll(&pfd, 1, -1);
            if (r == -1 && errno != EINTR) {
                PLOG_F("poll(fd=%d)", fuzzer->persistentSock);
            }
        }

        if (subproc_persistentModeRoundDone(hfuzz, fuzzer) == true) {
            break;
        }

        int status;
        int flags = hfuzz->persistent ? WNOHANG : 0;
        int ret = waitpid(fuzzer->pid, &status, flags);
        if (ret == -1 && errno == EINTR) {
			  if (hfuzz->tmOut) {
                arch_checkTimeLimit(hfuzz, fuzzer);
            }
            continue;
        }

        if (ret == -1) {
            printf("waitpid(pid=%d)", fuzzer->pid);
            continue;
        }
        if (ret != fuzzer->pid) {
            continue;
        }

        char strStatus[4096];
        if (hfuzz->persistent && ret == fuzzer->persistentPid
            && (WIFEXITED(status) || WIFSIGNALED(status))) {
            fuzzer->persistentPid = 0;
            LOG_W("Persistent mode: PID %d exited with status: %s", ret,
                  subproc_StatusToStr(status, strStatus, sizeof(strStatus)));
        }

        LOG_D("Process (pid %d) came back with status: %s", fuzzer->pid,
              subproc_StatusToStr(status, strStatus, sizeof(strStatus)));

        if (arch_analyzeSignal(hfuzz, status, fuzzer)) {
            break;
        }
    }
}

bool arch_archInit(honggfuzz_t * hfuzz UNUSED)
{
    /* Default is false */
    arch_sigs[SIGVTALRM].important = hfuzz->tmout_vtalrm;

    /* Default is true for all platforms except Android */
    arch_sigs[SIGABRT].important = hfuzz->monitorSIGABRT;

    return true;
}

void arch_sigFunc(int sig UNUSED)
{
    return;
}

static bool arch_setTimer(timer_t * timerid)
{
    /*
     * Kick in every 200ms, starting with the next second
     */
    const struct itimerspec ts = {
        .it_value = {.tv_sec = 0,.tv_nsec = 250000000,},
        .it_interval = {.tv_sec = 0,.tv_nsec = 250000000,},
    };
    if (timer_settime(*timerid, 0, &ts, NULL) == -1) {
        PLOG_E("timer_settime(arm) failed");
        timer_delete(*timerid);
        return false;
    }

    return true;
}

bool arch_setSig(int signo)
{
    sigset_t smask;
    sigemptyset(&smask);
    struct sigaction sa = {
        .sa_handler = arch_sigFunc,
        .sa_mask = smask,
        .sa_flags = 0,
    };

    if (sigaction(signo, &sa, NULL) == -1) {
        PLOG_W("sigaction(%d) failed", signo);
        return false;
    }

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, signo);
    if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_W("pthread_sigmask(%d, SIG_UNBLOCK)", signo);
        return false;
    }

    return true;
}

bool arch_archThreadInit(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer UNUSED)
{
    if (arch_setSig(SIGIO) == false) {
        LOG_E("arch_setSig(SIGIO)");
        return false;
    }
    if (arch_setSig(SIGCHLD) == false) {
        LOG_E("arch_setSig(SIGCHLD)");
        return false;
    }

    struct sigevent sevp = {
        .sigev_value.sival_ptr = &fuzzer->timerId,
        .sigev_signo = SIGIO,
        .sigev_notify = SIGEV_SIGNAL,
    };
    if (timer_create(CLOCK_REALTIME, &sevp, &fuzzer->timerId) == -1) {
        PLOG_E("timer_create(CLOCK_REALTIME) failed");
        return false;
    }
    if (arch_setTimer(&(fuzzer->timerId)) == false) {
        LOG_F("Couldn't set timer");
    }

    return true;
}
