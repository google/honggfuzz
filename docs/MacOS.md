# arm64 macOS builds and crash reports

Build honggfuzz on an arm64 Mac:
```sh
make -j4
```

Compile fuzz target:
```sh
./hfuzz_cc/hfuzz-clang -isysroot "$(xcrun --show-sdk-path)" \
    -g -O1 \
    target.c -o target
```

`-fno-omit-frame-pointer` and `-fno-optimize-sibling-calls` are optional
flags that improve native stack traces. The target must accept a file path and
read the input supplied through `___FILE___`.

Start fuzzing:
```sh
./honggfuzz -i input -W work -- ./target ___FILE___
```

If switching from an earlier POSIX-only build, rebuild the objects:

```sh
make clean
make -j4
```

To opt out of native Mach reporting and use the portable POSIX signal backend,
use `make clean` followed by `make OS=POSIX -j4`. POSIX mode does not provide
the native ARM64 registers, Mach exception reasons, or Mach stack capture.

## Live reporting

Crash details are written to `HONGGFUZZ.REPORT.TXT`, including the signal,
Mach exception and reason, fault and instruction addresses, ARM64 registers,
access type, and a bounded stack trace. Reports also include stable stack and
PC identifiers for crash deduplication. `SIGTRAP` from ARM64 `brk` instructions
is reported as well.

The report's `PC` is the actual runtime address; the filename's `PC` tag is
image-relative for native stacks. The `ADDR` tag remains the actual fault
address, so faults at varying heap addresses can still produce separate files.
Sanitizer stack reports take precedence when available. Their existing hash
and filename behavior is preserved, and native register details are appended.

The reporter uses a Mach exception port installed when the target starts. It
supports native ARM64 targets without root or a launchd service. Descendant
processes and translated Intel processes use separate backends. Missing frame
pointers or symbols can reduce stack detail, but do not prevent the input from
being saved.

## Triage saved crashes

Use `tools/macos_triage.py` to analyze one report or replay one saved input:

```sh
python3 tools/macos_triage.py analyze HONGGFUZZ.REPORT.TXT
python3 tools/macos_triage.py replay --input path/to/saved-input \
    --output triage -- ./target ___FILE___
```

The script writes a JSON summary and labels the observed fault. It does not
determine exploitability.

## References
ESR field meanings are described in Apple's [XNU ARM64 register definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/arm64/proc_reg.h).
