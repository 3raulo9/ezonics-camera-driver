"""Statistics on a capture made by `EzcamProbe capture`.

Record format: ep(u8) transfer(u32) index(u16) status(i32) length(u16) data[length]

Usage: python -I re/analyze_capture.py <capture.bin> [--dump N]
"""
import struct
import sys
from collections import Counter, defaultdict


def load(path):
    data = open(path, "rb").read()
    pos, out = 0, defaultdict(list)
    while pos < len(data):
        ep, transfer, index, status, length = struct.unpack_from("<BIHiH", data, pos)
        pos += 13
        out[ep].append((transfer, index, status, data[pos:pos + length]))
        pos += length
    return out


def main(path, dump):
    pipes = load(path)
    for ep, pkts in sorted(pipes.items()):
        lens = [len(p[3]) for p in pkts]
        print(f"=== EP 0x{ep:02X}: {len(pkts)} packets, {sum(lens)} bytes")
        print("  length histogram:", Counter(lens).most_common(12))
        print("  status values   :", Counter(p[2] for p in pkts).most_common(5))
        firsts = Counter(p[3][:4].hex() for p in pkts if p[3])
        print("  first 4 bytes   :", firsts.most_common(8))
        allb = b"".join(p[3] for p in pkts)
        print("  byte histogram  : top", [(f"{b:02X}", c) for b, c in Counter(allb).most_common(6)],
              f"mean={sum(allb) / max(1, len(allb)):.1f}")
        # runs of non-full packets (frame boundary candidates)
        full = max(lens)
        short = [i for i, n in enumerate(lens) if n < full]
        gaps = [b - a for a, b in zip(short, short[1:])]
        print(f"  {len(short)} packets shorter than {full}; spacing between them: {Counter(gaps).most_common(8)}")
        if dump:
            for i, (t, ix, st, d) in enumerate(pkts[:dump]):
                print(f"  #{i:4} t={t} i={ix:2} st={st} len={len(d):3} {d[:24].hex(' ')}")
    # interleaving / per-millisecond sizes
    if 0x81 in pipes and 0x82 in pipes:
        a = [len(p[3]) for p in pipes[0x81]]
        b = [len(p[3]) for p in pipes[0x82]]
        print("=== per-ms size pairs (first 40):", list(zip(a[:40], b[:40])))


if __name__ == "__main__":
    n = int(sys.argv[sys.argv.index("--dump") + 1]) if "--dump" in sys.argv else 0
    main(sys.argv[1], n)
