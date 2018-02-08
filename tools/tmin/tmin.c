/*

   tmin - testcase minimizer
   -------------------------

   A quick and efficient fault test case optimizer for complex formats.
   Please refer to command-line summary for usage hints.

   Author: Michal Zalewski <lcamtuf@google.com>
   Copyright 2008 Google Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <string.h>
#include <sys/wait.h>

#ifndef __FreeBSD__
#  include <getopt.h>
#endif /* !__FreeBSD__ */

#include "types.h"

/******************************************/
/******** Configurable parameters: ********/
/******************************************/

#define MAX_SKIP    16		      /* Max deletion chunk size for stage 2 */
#define REPL_CHAR   '0'	              /* Replacement character for stage 3/4 */
#define INFILE      "testcase.in"     /* Input test case file                */
#define OUTFILE	    "testcase.small"  /* Output test case file               */
#define BUF_SIZE    (64 * 1024)	      /* Input/output buffer size            */

#define ABORT_FAULT		      /* Treat abort() as crash              */
#undef  KEEP_OUTPUT		      /* Preserve program's stdout / stderr  */
#undef  DEBUG_CASES		      /* Dump progress to screen             */

#define VERSION     "0.05-beta"

/***********************************/
/******** End configuration ********/
/***********************************/

#define debug(x...) fprintf(stderr,x)

#define fatal(x...) do { \
    debug("[-] ERROR: "); \
    debug(x); \
    debug("\n"); \
    exit(1); \
  } while (0)

#define pfatal(x) do { \
    debug("[-] ERROR: "); \
    perror(x); \
    exit(1); \
  } while (0)

#ifdef DEBUG_CASES
#define DEBUG(x...) debug(x)
#else
#define DEBUG(x...)
#endif /* ^DEBUG_CASES */

static _u8 wait_signal,
           use_retcode;

static _u8 *write_file;

static _u8* data;
static _u32 data_len;

static _u32 orig_len;
static _u32 exec_nofault;
static _u32 exec_fault;

static volatile _u8 sig_status;

/* Show usage tips */
static void usage(_u8* argv0) {

  debug("Usage: %s  [ ( -s | -x ) ] [ -w <fname> ] -- /path/to/target [ params ]\n\n"

        "The utility takes a single input file, named '%s', that must be present\n"
        "in the current directory. This tool then optimizes the testcase by calling the\n"
        "program and examining its exit status (or alternatively, receiving SIGUSR1 or\n"
        "SIGUSR2 from an external supervisor script to indicate clean execution / crash,\n"
        "respectively) to confirm which subsets of the testcase still prompt a fault\n"
        "condition. The goal is to narrow the dataset down so that it is expressed with:\n\n"

        "  1) The lowest number of bytes possible, then\n"
        "  2) The smallest, most homogenous alphabet possible.\n\n"

        "The result is stored as '%s'.\n\n"

        "Command-line options:\n"
        "  /path/to/target  - target application / shell script wrapper to execute\n"
        "  -w <fname>       - test file to write to (default: target's stdin)\n"
        "  -s               - ignore return, wait for external signal to confirm crash\n"
        "  -x               - interpret non-zero return from target as a fault condition\n\n"

        "To send data to remote clients or servers, simply invoke nc as a target in -s\n"
        "mode, and send a proper signal to 'tmin' from a script used to validate the\n"
        "outcome of a test. For example, when testing a browser, this might be generated\n"
        "by a local CGI script invoked by client-side Javascript, or by a native script\n"
        "automating UI interaction. If you just want to write data to file, but not invoke\n"
        "a local program, specify /bin/true as a target in -w -s mode.\n\n"
        
        "Comments and complaints: Michal Zalewski <lcamtuf@google.com>\n", argv0, INFILE, OUTFILE);

  exit(1);

}


/* Load input file once. */
static void load_input(void) {
  _s32 f,i;

  f = open(INFILE,O_RDONLY);
  if (f < 0) pfatal(INFILE);

  data = malloc(BUF_SIZE);
  if (!data) fatal("out of memory");

  while (1) { 
  
    i = read(f,data + data_len,BUF_SIZE);

    if (i > 0) data_len += i;
    if (i != BUF_SIZE) break;

    data = realloc(data, data_len + BUF_SIZE);
    if (!data) fatal("out of memory");
  
  }

  close(f);

  if (!data_len) fatal("empty input test case.");

  orig_len = data_len;

}


/* Handle "no crash" ping. */
static void handle_usr1(int sig) {
  sig_status = 1;
}


/* Handle "crash" ping. */
static void handle_usr2(int sig) {
  sig_status = 2;
}


/* Execute target, wait for results; returns 0 if no fault, 1 if fault */
static _u8 execute_wait(_u8** argv, _u8* cur_data, _u32 cur_len) {
  _s32 pid, f;
  int p[2];

  /* Prepare input file, if requested. */

  if (write_file) {

    unlink(write_file);
    f = open(write_file, O_WRONLY | O_CREAT | O_EXCL, 0622);
    if (f < 0) pfatal(write_file);

    if (write(f,cur_data,cur_len) != cur_len) fatal("short write to '%s'",write_file);

    close(f);

  }

  if (wait_signal) sig_status = 0;

  if (pipe(p)) pfatal("pipe() failed");

  pid = fork();
  if (pid < 0) pfatal("fork() failed");

  if (!pid) {

    /* sink errors here */

    close(p[1]);
    dup2(p[0],0);

#ifndef KEEP_OUTPUT
    dup2(2,137);
    f = open("/dev/null",O_RDWR);
    dup2(f,1);
    dup2(f,2);
#endif /* !KEEP_OUTPUT */

    execvp(argv[0],(char**)argv);
   
#ifndef KEEP_OUTPUT
    dup2(137,2);
#endif /* !KEEP_OUTPUT */

    debug("[-] ERROR: ");
    perror(argv[0]);
    exit(0);

  }

  close(p[0]);

  if (!write_file)
    write(p[1],cur_data,cur_len); /* sink errors */

  close(p[1]);

  if (wait_signal) {

    while (!sig_status) pause();

    /* Terminate child once signal received. */
    kill(pid,SIGKILL);

    waitpid(pid,&f,0); /* sink errors */

    if (sig_status == 2) exec_fault++; else exec_nofault++;

    return (sig_status == 2);

  }

  if (waitpid(pid,&f,0) != pid) pfatal("waitpid() failed");

  if (WIFSIGNALED(f) && (WTERMSIG(f) == SIGSEGV || WTERMSIG(f) == SIGBUS ||
      WTERMSIG(f) == SIGILL
#ifdef ABORT_FAULT
                            || WTERMSIG(f) == SIGABRT
#endif /* ABORT_FAULT */
                                                     )) {
    exec_fault++;
    return 1;
  }

  if (use_retcode && WIFEXITED(f) && WEXITSTATUS(f)) {
    exec_fault++;
    return 1;
  }

  exec_nofault++;
  return 0;

}


static void minimize(_u8** argv) {

  _u32 trunc_round = 0, skip_round = 0, subst_round = 0, char_round = 0,
       data_replaced = 0;
  _s32 prev_remove, f;
  _u32 div, pos, a, replaceable, orig_alpha = 0;
  _u8* wkbuf;

  _u32 alcount[256];
  _u32 alelem;

  /* Step 0 is to make sure we repro the crash for the actual input file. */

  debug("[*] Stage 0: loading '%s' and validating fault condition...\n", INFILE);

  load_input();
  if (!execute_wait(argv, data, data_len)) fatal("no fault detected with original test case!");

restart_truncation:

  trunc_round++;
  debug("[*] Stage 1: recursive truncation (round %d, input = %d/%d)\n", trunc_round, data_len, orig_len);

  /* Fast truncation: use progressively more fine-grained attempts to cut
     off head or tail of input data. */

  prev_remove = -1;

  for (div=2;div<=data_len;div++) {

    _u32 remove = data_len / div;

    if (prev_remove == remove || remove == 0) continue;
    prev_remove = remove;

    /* div      : 3
       data     : "AABBCC" (data_len = 8)
       remove   : 2
       tr_left  : "BBCC"
       tr_right : "AABB" */

    DEBUG("--> Trying l_trunc(%u / %u = %u)\n", data_len, div, remove);

    /* Left-trunaced string still causes failure? */
    if (execute_wait(argv, data + remove, data_len - remove)) {
      _u8* tmp;

      data_len -= remove;
      tmp = malloc(data_len);
      if (!tmp) fatal("out of memory");

      memcpy(tmp, data + remove, data_len);
      free(data);
      data = tmp;

      goto restart_truncation;
    }

    DEBUG("--> Trying r_trunc(%u / %u = %u)\n", data_len, div, remove);

    /* Right-trunaced string still causes failure? */
    if (execute_wait(argv, data, data_len - remove)) {
      data_len -= remove;
      goto restart_truncation;
    }

  }

restart_skipping:

  skip_round++;
  debug("[*] Stage 2: block skipping (round %d, input = %d/%d)\n", skip_round, data_len, orig_len);

  wkbuf = malloc(data_len);
  if (!wkbuf) fatal("out of memory");

  for (pos=1;pos+2<data_len;pos++) {
    _u32 skip_cnt = MAX_SKIP;

    if (pos + skip_cnt >= data_len) skip_cnt = data_len - pos - 1;

    for (;skip_cnt>0;skip_cnt--) {

      memcpy(wkbuf,data, pos);
      memcpy(wkbuf + pos,data + pos + skip_cnt, data_len - pos - skip_cnt);

      DEBUG("--> Trying skip(%u,%u)\n", pos, skip_cnt);

      if (execute_wait(argv,wkbuf, data_len - skip_cnt)) {
        free(data);
        data = wkbuf;
        data_len -= skip_cnt;
        goto restart_skipping;
      }

    }

  }

  free(wkbuf);

#define COUNT_ALPHABET(d, dl) do { \
    _u32 _c; \
    memset(alcount,0,256 * sizeof(_u32)); \
    alelem = 0; \
    for (_c=0;_c<(dl);_c++) alcount[d[_c]]++; \
    for (_c=0;_c<256;_c++) if (alcount[_c]) alelem++; \
  } while (0)

restart_substitution:

  COUNT_ALPHABET(data, data_len);
  if (!subst_round) orig_alpha = alelem;

  subst_round++;
  debug("[*] Stage 3: alphabet normalization (round %d, charset = %d/%d)\n", subst_round, alelem, orig_alpha);

  wkbuf = malloc(data_len);
  if (!wkbuf) fatal("out of memory");

  for (a=0;a<256;a++) 

    if (a != REPL_CHAR && alcount[a]) {

      _u32 tmp_replaced = 0;

      memcpy(wkbuf,data,data_len);

      for (pos=0;pos<data_len;pos++)
       if (wkbuf[pos] == a) {
         wkbuf[pos] = REPL_CHAR;
         tmp_replaced++;
       }

      DEBUG("--> Trying replace_all(%u)\n", a);

      if (execute_wait(argv,wkbuf,data_len)) {
        free(data);
        data = wkbuf;
        data_replaced += tmp_replaced;
        goto restart_substitution;
      }

    }

  free(wkbuf);

#define COUNT_REPLACEABLE(d, dl) do { \
    _u32 _c; \
    replaceable = 0; \
    for (_c=0;_c<(dl);_c++) if (d[_c] != REPL_CHAR) replaceable++; \
  } while (0)

restart_charbychar:

  COUNT_REPLACEABLE(data, data_len);

  char_round++;
  debug("[*] Stage 4: character normalization (round %d, characters = %d/%d)\n", char_round, replaceable, data_len);

  wkbuf = malloc(data_len);
  if (!wkbuf) fatal("out of memory");
  memcpy(wkbuf,data,data_len);

  for (pos=0;pos<data_len;pos++)

    if (wkbuf[pos] != REPL_CHAR) {

      wkbuf[pos] = REPL_CHAR;

      DEBUG("--> Trying replace_at(%u)\n", pos);

      if (execute_wait(argv,wkbuf,data_len)) {
        free(data);
        data = wkbuf;
        data_replaced += 1;
        goto restart_charbychar;
      }

      wkbuf[pos] = data[pos];

    }

  free(wkbuf);

  debug("[*] All done - writing output to '%s'...\n", OUTFILE);

  unlink(OUTFILE);
  f = open(OUTFILE, O_WRONLY|O_EXCL|O_CREAT, 0622);
  if (f < 0) pfatal(OUTFILE);
  if (write(f,data,data_len) != data_len) fatal("short write to '%s'",OUTFILE);
  close(f);

  debug("\n"
        "== Final statistics==\n"
        " Original size : %d bytes\n"
        "Optimized size : %d bytes (-%.02f%%)\n"
        "Chars replaced : %d (%.02f%%)\n"
        "    Efficiency : %d good / %d bad\n"
        "  Round counts : 1:%d 2:%d 3:%d 4:%d\n\n",
        orig_len, data_len, 100 - (data_len * 100.0 / orig_len),
        data_replaced, (data_replaced * 100.0 / orig_len),
        exec_fault, exec_nofault, trunc_round, skip_round,
        subst_round, char_round);

}


int main(int argc, char** argv) {
  _s32 opt;

  if (argc == 1) usage(argv[0]);

  while ((opt = getopt(argc,argv,"+w:sx")) > 0) 
    switch (opt) {

      case 'w': write_file = optarg; break;

      case 's': wait_signal = 1; break;

      case 'x': use_retcode = 1; break;

      default: usage(argv[0]);

    }

  if (optind == argc) fatal("no target program specified");

  if (wait_signal) {
    if (use_retcode) fatal("-s and -x are mutually exclusive");
    signal(SIGUSR1, handle_usr1);
    signal(SIGUSR2, handle_usr2);
  }

  signal(SIGPIPE, SIG_IGN);

  debug("tmin - complex testcase minimizer, version " VERSION " (lcamtuf@google.com)\n");

  minimize((_u8**)(argv + optind));

  return 0;

}

