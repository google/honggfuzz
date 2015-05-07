# Feedback-driven fuzzing #

Honggfuzz (since its version 0.5) is capable of performing feedback-driven fuzzing. It utilizes Linux perf subsystem and hardware CPU counters to achieve the best outcomes.

Developers can provide their own initial file (-f flag) which will be gradually improved upon. Alternatively, honggfuzz is capable of starting with just empty buffer, and work its way through, creating a valid fuzzing input in the process.

# Requirements #
  * GNU/Linux OS
  * Relatively modern Linux kernel (v 3.2 should suffice)
  * CPU which is supported by the [perf subsystem](https://perf.wiki.kernel.org/index.php/Main_Page) for hardware-assisted instruction and branch counting
  * CPU supporting [BTS (Branch Trace Store)](https://software.intel.com/en-us/forums/topic/277868?language=es) for hardware assisted unique edge (branch pairs) counting. Currently it's available only in some newer Intel CPUs (unfortunately no AMD support for now)

# Examples #
The main fuzzing strategy is quite simple. It tries to maximize the number of perf events while mangling the file which servers as an unput for fuzzing.

## Instruction counting (-Di) ##

```
$ honggfuzz -q -Di -f /usr/share/doc/texlive-doc/latex/ctable/penguin.jpg -- ./djpeg.static ___FILE___
...
[INFO] Launched new process, pid: 21168, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1 / New: 1174343
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 1174343/1
[INFO] Launched new process, pid: 21170, (5/5)
[INFO] Launched new process, pid: 21173, (5/5)
[INFO] Launched new process, pid: 21172, (5/5)
[INFO] Launched new process, pid: 21171, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1174343 / New: 20105
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1174343 / New: 1156896
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1174343 / New: 1134940
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1174343 / New: 1134975
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1174343 / New: 1174344
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 1174344/1174343
```


It will start with some initial file (or with no file at all), and subsequent fuzzing iterations will try to maximize the number of instructions spent on parsing it.

## Branch counting (-Db) ##

As above, it will try to maximine the number of branches taken by CPU on behalf of the fuzzed process (here: djpeg.static) while performing the fuzzing process.

```
$ honggfuzz -q -Db -f /usr/share/doc/texlive-doc/latex/ctable/penguin.jpg -- ./djpeg.static ___FILE___
...
[INFO] Launched new process, pid: 21391, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1 / New: 115586
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 115586/1
[INFO] Launched new process, pid: 21393, (5/5)
[INFO] Launched new process, pid: 21395, (5/5)
[INFO] Launched new process, pid: 21394, (5/5)
[INFO] Launched new process, pid: 21396, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 115586 / New: 4326
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 115586 / New: 4871
[INFO] File size (New/Best): 2774/2789, Perf feedback: Best: 115586 / New: 104983
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 115586 / New: 119456
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 119456/115586

```

## Unique branch pair (edges) counting (-Dp) ##
This is the most powerfull mode of feedback-driven counting that honggfuzz supports. It utilizes Intel's BTS (Branch Trace Store) feature to record all branch events (edges) inside the fuzzed process. Later, honggfuzz will de-duplicate those entries. The resulting number of branch pairs (edges) is good approximation of how much code of a given tool have been actively executed/used (code coverage).

```
$ honggfuzz -q -Dp -f /usr/share/doc/texlive-doc/latex/ctable/penguin.jpg -- ./djpeg.static ___FILE___
...
[INFO] Launched new process, pid: 21715, (5/5)
[INFO] Launched new process, pid: 21719, (5/5)
[INFO] Launched new process, pid: 21717, (5/5)
[INFO] Launched new process, pid: 21718, (5/5)
[INFO] Launched new process, pid: 21716, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 1 / New: 887
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 887/1
[INFO] Launched new process, pid: 21721, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 887 / New: 887
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 887/887
[INFO] Launched new process, pid: 21723, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 887 / New: 887
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 887/887
[INFO] Launched new process, pid: 21725, (5/5)
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 887 / New: 887
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 887/887
[INFO] File size (New/Best): 2789/2789, Perf feedback: Best: 887 / New: 1606
[INFO] New BEST feedback: New/Old: 2789/2789', Perf feedback counter Curr/High: 1606/887
```