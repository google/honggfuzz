#!/bin/bash

rm HONGGFUZZ.REPORT.TXT SIGABR* HF.san* SIGSEGV.*.fuzz

../honggfuzz --keep_output --debug --sanitizers --stdin_input --threads 1 --verbose --logfile log.txt --socket_fuzzer -- ./vulnserver_cov &
python3 ./honggfuzz_socketclient.py auto $!
