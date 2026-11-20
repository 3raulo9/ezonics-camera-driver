"""Compact call graph of a listing produced by re/disasm.py.

For every function: size in instructions, internal callees, imported APIs used,
indirect calls, and how many callers it has.

Usage: python -I re/callgraph.py <listing.asm> [--min N]
"""
import re
import sys
from collections import defaultdict


def main(path, min_size):
    funcs, order, cur = defaultdict(lambda: {"n": 0, "calls": [], "apis": set(), "indirect": 0}), [], None
    for line in open(path):
        if line.startswith("sub_"):
            cur = line.strip()[4:-1]
            order.append(cur)
            continue
        if cur is None or len(line) < 10:
            continue
        f = funcs[cur]
        f["n"] += 1
        m = re.search(r"call (0x[0-9a-f]+)$", line.strip())
        if m:
            f["calls"].append(f"{int(m.group(1), 16):08X}")
        elif " call " in line:
            api = re.search(r"; (\S+)$", line)
            if api:
                f["apis"].add(api.group(1))
            else:
                f["indirect"] += 1
    callers = defaultdict(int)
    for name in order:
        for c in set(funcs[name]["calls"]):
            callers[c] += 1
    for name in order:
        f = funcs[name]
        if f["n"] < min_size:
            continue
        callees = " ".join(sorted(set(c[-5:] for c in f["calls"])))
        apis = ",".join(sorted(a.replace("StreamClass", "SC.") for a in f["apis"]))
        ind = f" ind={f['indirect']}" if f["indirect"] else ""
        print(f"{name[-5:]} n={f['n']:<5} callers={callers[name]:<2}{ind} -> [{callees}] {apis}")


if __name__ == "__main__":
    mn = int(sys.argv[sys.argv.index("--min") + 1]) if "--min" in sys.argv else 0
    main(sys.argv[1], mn)
