# Introduction #

With honggfuzz you can fuzz files by flipping bytes (`-mB`) or bits (`-mb`). You can also specify the rate (`-r`) of how many bytes or bits should be changed in the input file.

Alternatively to this _"dumb"_ fuzzing mode, you can specify a custom fuzzer (`-c`) to modify input files.

# Details #

When run in `-mB` or `-mb` mode, honggfuzz does the following:
  1. a random file from the input files is chosen, and saved as a `.honggfuzz` file
  1. depending on the file size, the specified rate (`-r`) of bits or bytes is flipped
  1. the fuzzing target is executed with the input file (either via STDIN (`-s`) or via a command line parameter (`___FILE___`)

When run in `-c` mode, the first and last steps are the same, but the file modification differs:
  1. a random file from the input files is chosen, and saved as a `.honggfuzz` file
  1. honggfuzz executes the external fuzzing binary or script specified by the `-c` parameter and appends the temporary `.honggfuzz` file as the first argument to the external fuzzer
  1. the external fuzzer should open and modify the temporary file
  1. honggfuzz waits for the external fuzzer to terminate
  1. the fuzzing target is executed with the modified input file (either via STDIN (`-s`) or via a command line parameter (`___FILE___`)

# Example #

If we consider the badcode1.c examples from the examples directory, we can see that it runs correctly for the sample input:

```
$ ./examples/targets/badcode1 examples/inputfiles/badcode1.txt
123456789012345678901234567890123456789012345678901234567890
123456789012345678901234567890123456789012345678901234567890
```

The bug in badcode1.c is that it reads lines up to 128 bytes from the input file and writes them to a 64 byte buffer (`fgets(str, 128, fp)`). If we would modify random bytes in the input file, the bug would only trigger when we overwrite the newline in the inputfile. With standard honggfuzz options this might take a while:

```
$ ./honggfuzz -n 1 -f examples/badcode/inputfiles/badcode1.txt -- ./examples/badcode/targets/badcode1 ___FILE___
honggfuzz, version 0.1 Robert Swiecki <swiecki@google.com>, Copyright 2010 by Google Inc. All Rights Reserved.
[INFO] Launched new process, pid: 43288, (1/1)
123456789012345678901234567890123456789012345678901234567890
12345678012345678901234567890123456789012345678901234567890
[INFO] Launched new process, pid: 43289, (1/1)
123456789012345678901234567890123456789012345678901234567890
12345678901234567890123456789?123456789012345678901234567890
...
```

Now if we take a look at the script under [examples/externalfuzzers/lowBytesIncrease.py](http://code.google.com/p/honggfuzz/source/browse/trunk/examples/externalfuzzers/lowBytesIncrease.py), we see that it searches the input file (as provided by `argv[1]`) for low bytes and increases them randomly. This will modify the newlines, and thus trigger the bug much faster, as shown below:

```
$ ./honggfuzz -n 1 -f examples/badcode/inputfiles/badcode1.txt -c `pwd`/examples/externalfuzzers/lowBytesIncrease.py -- ./examples/badcode/targets/badcode1 ___FILE___
honggfuzz, version 0.1 Robert Swiecki <swiecki@google.com>, Copyright 2010 by Google Inc. All Rights Reserved.
[INFO] Launched new process, pid: 44578, (1/1)
[INFO] Ok, that's interesting, saving the '.honggfuzz.1287067149.44576.413228313.fuzz' as 'SIGSEGV.44578.2010-10-14.16.39.09.fuzz'
[INFO] Launched new process, pid: 44580, (1/1)
[INFO] Ok, that's interesting, saving the '.honggfuzz.1287067149.44576.637798454.fuzz' as 'SIGSEGV.44580.2010-10-14.16.39.09.fuzz'
...
```$ ./honggfuzz -n 1 -f examples/badcode/inputfiles/badcode1.txt -c `pwd`/examples/externalfuzzers/lowBytesIncrease.py -- ./examples/badcode/targets/badcode1 ___FILE___
honggfuzz, version 0.1 Robert Swiecki <swiecki@google.com>, Copyright 2010 by Google Inc. All Rights Reserved.
[INFO] Launched new process, pid: 44578, (1/1)
[INFO] Ok, that's interesting, saving the '.honggfuzz.1287067149.44576.413228313.fuzz' as 'SIGSEGV.44578.2010-10-14.16.39.09.fuzz'
[INFO] Launched new process, pid: 44580, (1/1)
[INFO] Ok, that's interesting, saving the '.honggfuzz.1287067149.44576.637798454.fuzz' as 'SIGSEGV.44580.2010-10-14.16.39.09.fuzz'
...
}}}```
