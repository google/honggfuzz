# Introduction #

This page described how to use honggfuzz in batch mode. The simplest example would be Apache Web Server, which cannot be restarted every time we want to send new input (for performance reasons).

_Note: This currently works with Linux OS only_

# What do we need? #

We need to choose what we actually want to fuzz. In this example it'd be HTTP header parser of Apache WS. We need to create a fuzzing tool which will create those headers and then we'll use netcat (_/bin/nc_) to send it to Apache. I had created my own tool (_headfuzz_), it will create output which looks like:

```
GET (Orig-Uri) HTTP/1.0
private: expires=application/x-zip-compressed
Proxy-Authorization: HTTP/144444444444444444444444444.2
Date: "application/x-gzip"

ABC
```

In order to attach to a given PID we'll use the **-p** flag. Note that honggfuzz supports attaching to threads as well; in other words, it will attach to every thread in the same thread group (_ls /proc/pid/task_).

# Start Apache WS #

We need to run in debug mode, so it doesn't spawn child processes (-X flag)

```
# APACHE_RUN_USER=www-data APACHE_RUN_GROUP=www-data apache2 -k start -X
```

# Run honggfuzz #

We'll use _-s_ flag to send contents of the fuzz to the standard input of _/bin/nc_

```
# ./honggfuzz -c ./headfuzz -s -p "`pidof apache2`" -- /bin/nc -q2 -w2 127.0.0.1 80
honggfuzz version 0.3 Robert Swiecki <swiecki@google.com>, Copyright 2010 by Google Inc. All Rights Reserved.
[INFO] External PID specified, concurrency disabled
[INFO] debugLevel: 3, inputFile '(null)', nullifyStdio: 0, fuzzStdin: 1, saveUnique: 0, flipRate: 0.001000, flipMode: 'B', externalCommand: './headfuzz', tmOut: 3, threadsMax: 1, fileExtn 'fuzz', ignoreAddr: (nil), memoryLimit: 0 (MiB), fuzzExe: '/bin/nc', fuzzedPid: 9378
[INFO] No input file corpus specified, the external command './headfuzz' is responsible for creating the fuzz files
[INFO] Successfully attached to pid/tid: 9378
[INFO] Launched new process, pid: 9983, (1/1)
....
```

If Apache crashes we will see:

```
[INFO] Ok, that's interesting, saved '.honggfuzz.10014.1310049998.834508.645006950.fuzz' as 'SIGSEGV.PC.0x7f45942f1c20.CODE.0.ADDR.0x288d.INSTR.cmp_rax,_0xfffff001.2011-07-07.16.46.38.9378.fuzz'
[WARNING] Monitored process PID: 9378 finished
```

And we'll find the following file in the current directory

```
SIGSEGV.PC.0x7f45942f1c20.CODE.0.ADDR.0x288d.INSTR.cmp_rax,_0xfffff001.2011-07-07.16.46.38.9378.fuzz
```

Happy fuzzing!
