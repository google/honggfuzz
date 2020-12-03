# Honggfuzz - SocketClient

Use Honggfuzz as Code-Coverage tool, and implement an external fuzzer which
interacts with the target (usually a network server). The actual fuzzer and 
honggfuzz communicate via a local socket. 

Tested on Ubuntu 17.04, 18.04.


## Protocol

Simple:

```
HonggFuzz      <->       FFW
             "Fuzz" -->
         <-- "Okay"
             "New!" -->
             "Cras" -->
         <-- "bad!"
...
         <-- "halt"
```

* "Fuzz": HongFuzz tells FFW to send its network messages to the target server
* "Okay": FFW tells HonggFuzz that it is finished sending the messages
* "New!": HonggFuzz tells FFW that new basic blocks have been reached
* "Cras": HonggFuzz tells FFW that the target has crashed
* "bad!": FFW tells Honggfuzz that the server is crashed
* "halt": Fuzzing finished, shutdown HonggFuzz in an orderly manner.

## Overview

`vulnserver_cov` will listen to localhost:5001 and expect messages starting with "A", "B", "C",
"D" or "E". Message "B" can provoke a stack based buffer overflow, while message "C"
can provoke a heap based buffer overflow.

The current `honggfuzz_socketclient` will send one of these messages (decided by the user),
after honggfuzz told it that it is ready (the client process is started). Number 0-4 correspond
to "A"-"E", while number 5 and 6 will provoke memory corruption overflows.

`honggfuzz_socketclient` will then proceed to send the messages to `vulnserver_cov` on port
5001. After that hongfuzz may send a message to `hongfuzz_client`, indicating that new
basic blocks have been reached.


## Preparation

Compile the test server, with `make` or:
```
~/honggfuzz/hfuzz_cc/hfuzz-gcc vulnserver_cov.c -O0 -o vulnserver_cov
```

## How-to

Start hongfuzz in socket-client mode:

```
$ cd ~/honggfuzz
$ mkdir test
$ cd test
$ ../honggfuzz --keep_output --debug --sanitizers --stdin_input --threads 1 --verbose --logfile log.txt --socket_fuzzer -- ../socketfuzzer/vulnserver_cov
Waiting for SocketFuzzer connection on socket: /tmp/honggfuzz_socket.<pid>
```

In another terminal, start the socketfuzzer client:
```
$ python ./honggfuzz_socketclient.py interactive
connecting to /tmp/honggfuzz_socket
--[ Send Msg #: 1
Send to target: 1
--[ R Adding file to corpus...
--[ Send Msg #: 5
Send to target: 5
--[ R Target crashed
--[ Send Msg #: 1
Send to target: 1
--[ Send Msg #: 5
Send to target: 5
--[ Send Msg #: 1
Send to target: 1
--[ Send Msg #: 5
Send to target: 5
--[ Send Msg #: 2
Send to target: 2
--[ R Adding file to corpus...
--[ Send Msg #: 3
Send to target: 3
--[ R Adding file to corpus...
--[ Send Msg #: 5
Send to target: 5
```

Automatic test, successful run:
```
$ ./unittest.sh
Auto Test
connecting to /tmp/honggfuzz_socket.24916

Test: 0 - initial
A SocketFuzzer client connected. Continuing.
  ok: Fuzz

Test: 1 - expecting first new BB
# vulnserver_cov: Listening on port: 5001
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 6 on state: 0
# vulnserver_cov: Auth success
# vulnserver_cov: Closing...
  ok: New!
  ok: Fuzz

Test: 2 - expecting second new BB
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 6 on state: 0
# vulnserver_cov: Handledata1: BBBBBB
# vulnserver_cov: Closing...
  ok: New!
  ok: Fuzz

Test: 3 - repeat second msg, expecting no new BB
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 6 on state: 0
# vulnserver_cov: Handledata1: BBBBBB
# vulnserver_cov: Closing...
  ok: Fuzz

Test: 4 - crash stack, expect new BB, then crash notification
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 128 on state: 0
# vulnserver_cov: Handledata1: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB�
  ok: New!
  ok: Cras
  ok: Fuzz

Test: 5 - resend second, expecting no new BB
# vulnserver_cov: Listening on port: 5001
  ok: Fuzz

Test: 6 - send three, expecting new BB
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 6 on state: 0
# vulnserver_cov: Handledata2: CCCCCC
# vulnserver_cov: Closing...
  ok: New!
  ok: Fuzz

Test: 7 - send four, new BB
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 6 on state: 0
# vulnserver_cov: Handledata3: 6
# vulnserver_cov: Closing...
  ok: New!
  ok: Fuzz

Test: 8 - fake unresponsive server
  ok: Fuzz

Test: 9 - send four again, no new BB
# vulnserver_cov: New client connected
# vulnserver_cov: Received data with len: 6 on state: 0
# vulnserver_cov: Handledata3: 6
# vulnserver_cov: Closing...
# vulnserver_cov: Listening on port: 5001
  ok: Fuzz
```
