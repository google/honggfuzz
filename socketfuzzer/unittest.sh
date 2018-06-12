#!/bin/bash

rm -rf HF_SANCOV/ HONGGFUZZ.REPORT.TXT SIGABR* HF.san*

../honggfuzz --keep_output --debug --sanitizers --sancov --stdin_input --threads 1 --verbose --logfile log.txt --socket_fuzzer -- ./vulnserver_cov &

python ./honggfuzz_socketclient.py auto $!
