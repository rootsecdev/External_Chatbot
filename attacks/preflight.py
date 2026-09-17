#!/usr/bin/env python3
"""Pre-flight for a real-model demo.

A live model is non-deterministic and, on Azure, sits behind a content filter,
so a vector that lands in rehearsal can refuse on stage. This runs each vector
several times against whatever model the lab is currently driving and reports a
landing rate, so you know before you are in front of anyone which vectors are
reliable, which are flaky, and which the model resists outright.

Run it against a lab you have already started on a real provider:

    python3 lab.py --provider azure                 # in one terminal
    python3 attacks/preflight.py --runs 5           # in another

It attacks in vulnerable mode (mitigations off — that is where vectors are meant
to land) and restores the lab to vulnerable mode when it finishes. It changes no
files and hits the model repeatedly, so it costs tokens: use --runs and --vector
to keep it small.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exploit_runner import (BOLD, CYN, DIM, GRN, OFF, RED, YEL,  # noqa: E402
                            Lab, VECTORS)
from labconf import MODE_VULNERABLE  # noqa: E402

# landed == runs -> reliable; landed == 0 -> resisted; otherwise flaky.
RELIABLE, FLAKY, RESISTED = "reliable", "flaky", "resisted"


def _bucket(landed: int, runs: int) -> str:
    if landed >= runs:
        return RELIABLE
    if landed == 0:
        return RESISTED
    return FLAKY


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="http://127.0.0.1:8000")
    ap.add_argument("--runs", type=int, default=3,
                    help="times to attempt each vector (default 3)")
    ap.add_argument("--vector", type=int, action="append", default=[],
                    help="run only this vector number (repeatable)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every prompt and response")
    args = ap.parse_args()

    lab = Lab(args.target, args.verbose)
    provider = lab.state().get("provider", "?")

    print(f"{BOLD}Real-model pre-flight{OFF}  target {args.target}  "
          f"provider={provider}  runs={args.runs}")
    if provider == "simulated":
        print(f"{YEL}  warning: the lab is on the deterministic simulated engine. "
              f"Every vector will land every time and this tells you nothing about "
              f"a real model. Start the lab with --provider azure (or anthropic) "
              f"first.{OFF}")

    lab.set_mode(MODE_VULNERABLE)
    which = args.vector

    landed: dict[int, int] = defaultdict(int)
    total: dict[int, int] = defaultdict(int)
    names: dict[int, str] = {}

    for run in range(1, args.runs + 1):
        for fn in VECTORS:
            num = int(fn.__name__[1])
            if which and num not in which:
                continue
            lab.reset()
            result = fn(lab)
            names[num] = result.name
            total[num] += 1
            if result.succeeded:
                landed[num] += 1
            if args.verbose:
                mark = f"{RED}landed{OFF}" if result.succeeded else f"{GRN}resisted{OFF}"
                print(f"  run {run} vector {num}: {mark}")

    lab.set_mode(MODE_VULNERABLE)

    nums = sorted(names)
    print(f"\n{BOLD}landing rate over {args.runs} run(s){OFF}")
    print(f"  {'#':<3}{'vector':<52}{'landed':<10}{'verdict'}")
    print("  " + "-" * 78)
    buckets: dict[str, list[int]] = defaultdict(list)
    for num in nums:
        n_landed, n_total = landed[num], total[num]
        verdict = _bucket(n_landed, n_total)
        buckets[verdict].append(num)
        colour = {RELIABLE: GRN, FLAKY: YEL, RESISTED: DIM}[verdict]
        print(f"  {num:<3}{names[num]:<52}{f'{n_landed}/{n_total}':<10}"
              f"{colour}{verdict}{OFF}")

    def _fmt(vs: list[int]) -> str:
        return ", ".join(str(v) for v in vs) if vs else "none"

    print(f"\n{BOLD}demo guidance{OFF}")
    print(f"  {GRN}lead with (reliable):{OFF}          {_fmt(buckets[RELIABLE])}")
    print(f"  {YEL}rehearse or skip (flaky):{OFF}      {_fmt(buckets[FLAKY])}")
    print(f"  {DIM}narrate as the finding:{OFF}        {_fmt(buckets[RESISTED])}"
          f"  {DIM}(model or content filter resisted — that contrast is the point){OFF}")


if __name__ == "__main__":
    main()
