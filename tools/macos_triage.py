#!/usr/bin/env python3
"""Replay saved inputs with honggfuzz's native ARM64 reporter; summarize evidence.

SPDX-License-Identifier: Apache-2.0
This tool does not use CrashWrangler or claim to determine exploitability.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys


def analyze(text):
    if len(re.findall(r"^CRASH:$", text, re.MULTILINE)) > 1:
        raise ValueError("report contains multiple crashes; analyze one replay report at a time")
    fields = dict(re.findall(r"^([A-Z][A-Z0-9 _]+): (.*)$", text, re.MULTILINE))
    # Sanitizer descriptions take precedence over the native exception description.
    native = "ARM64 REGISTERS:\n" in text and "ACCESS TYPE" in fields
    address = int(fields.get("FAULT ADDRESS", "0"), 16)
    access = fields.get("ACCESS TYPE", "unknown")
    signo = fields.get("SIGNAL", "unknown")
    if access in ("read", "write", "execute"):
        observation = "near-null-access" if address < 4096 else f"invalid-{access}"
    elif signo.startswith("SIGABRT"):
        observation = "abort"
    elif signo.startswith("SIGTRAP"):
        observation = "trap"
    else:
        observation = "unknown"
    return {
        "native_arm64_report": native,
        "signal": signo,
        "description": fields.get("DESCRIPTION", ""),
        "pc": fields.get("PC"),
        "fault_address": fields.get("FAULT ADDRESS"),
        "access_type": access,
        "stack_hash": fields.get("STACK HASH"),
        "frames": re.findall(r"^ <.*$", text, re.MULTILINE),
        "observation": observation,
        "review_priority": "high" if observation in ("invalid-write", "invalid-execute") else "normal",
        "exploitability": "undetermined",
        "note": "Priority reflects the observed fault only. Reads, aborts, traps, and near-null faults may also be security bugs.",
    }


def replay(args):
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("supply the original target command after --")
    source = args.input.resolve(strict=True)
    if not source.is_file():
        raise ValueError("--input must be a saved crash file")
    fuzzer = args.honggfuzz.resolve(strict=True)
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    corpus = destination / "input"
    corpus.mkdir()
    shutil.copyfile(source, corpus / "case")
    report = destination / "report.txt"
    invocation = [str(fuzzer), "-x", "-v", "-r", "0", "-n", "1", "-N", "1",
                  "-t", str(args.timeout), "--run_time", str(args.timeout + 5),
                  "-i", str(corpus), "-W", str(destination), "-R", str(report)]
    if args.stdin:
        invocation.append("-s")
    invocation += ["--", *command]
    with (destination / "run.log").open("w") as log:
        proc = subprocess.Popen(invocation, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = proc.wait(timeout=args.timeout + 15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise RuntimeError(f"replay exceeded its deadline; see {destination / 'run.log'}")
    text = report.read_text(errors="replace") if report.exists() else ""
    summary = analyze(text)
    summary.update(input=str(source), command=command, returncode=returncode,
                   reproduced=bool(text), report=str(report) if text else None)
    (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if returncode == 0 and summary["native_arm64_report"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    replay_parser = commands.add_parser("replay", help="reproduce one saved input without mutation")
    replay_parser.add_argument("--input", type=Path, required=True)
    replay_parser.add_argument("--output", type=Path, required=True, help="new directory for results")
    replay_parser.add_argument("--honggfuzz", type=Path, default=Path(__file__).resolve().parents[1] / "honggfuzz")
    replay_parser.add_argument("--timeout", type=int, default=5)
    replay_parser.add_argument("--stdin", action="store_true")
    replay_parser.add_argument("command", nargs=argparse.REMAINDER)
    analyze_parser = commands.add_parser("analyze", help="summarize one saved native report as JSON")
    analyze_parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "analyze":
            result = analyze(args.report.read_text(errors="replace"))
            print(json.dumps(result, indent=2))
            return 0 if result["native_arm64_report"] else 1
        if args.timeout < 1:
            parser.error("--timeout must be a positive number of seconds")
        return replay(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"macos_triage: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
