#!/bin/bash

rm -rf HONGGFUZZ.REPORT.TXT SIGABR* HF.san*

../honggfuzz --keep_output --debug --sanitizers --stdin_input --threads 1 --verbose --logfile log.txt --socket_fuzzer -- ./vulnserver_cov &

python ./honggfuzz_socketclient.py auto $!
