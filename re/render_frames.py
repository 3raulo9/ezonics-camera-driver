"""Split a capture into frames and render them as PNG images for inspection.

Frame boundary = toggle of header bit 2 (0x04) in the 1-byte header of each isochronous
packet; the remaining bytes of each packet are payload. EP 0x81 carries luma, EP 0x82 chroma.

Usage: python -I re/render_frames.py <capture.bin> <out_dir> [--width W ...] [--frame N]
"""
import os
import struct
import sys
import zlib
from collections import defaultdict


def write_png(path, width, height, rows, channels=1):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    color = {1: 0, 3: 2}[channels]
    raw = b"".join(b"\0" + bytes(r) for r in rows)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)


def load(path):
    data = open(path, "rb").read()
    pos, pipes = 0, defaultdict(list)
    while pos < len(data):
        ep, t, ix, st, n = struct.unpack_from("<BIHiH", data, pos)
        pos += 13
        pipes[ep].append(data[pos:pos + n])
        pos += n
    return pipes


def frames(packets):
    """Yield payload of each complete frame (runs of equal header bit 2)."""
    out, cur, bit = [], bytearray(), None
    for p in packets:
        if not p:
            continue
        b = (p[0] >> 2) & 1
        if bit is not None and b != bit:
            out.append(bytes(cur))
            cur = bytearray()
        bit = b
        cur += p[1:]
    return out[1:]  # the first run starts mid-frame


def main():
    cap, out_dir = sys.argv[1], sys.argv[2]
    widths = [int(sys.argv[i + 1]) for i, a in enumerate(sys.argv) if a == "--width"] or [352]
    want = int(sys.argv[sys.argv.index("--frame") + 1]) if "--frame" in sys.argv else 2
    os.makedirs(out_dir, exist_ok=True)
    pipes = load(cap)
    for ep in sorted(pipes):
        fr = frames(pipes[ep])
        print(f"EP 0x{ep:02X}: {len(fr)} frames, sizes {[len(f) for f in fr]}")
        f = fr[want]
        for w in widths:
            ww = w if ep == 0x81 else w // 2
            h = len(f) // ww
            rows = [f[y * ww:(y + 1) * ww] for y in range(h)]
            name = os.path.join(out_dir, f"ep{ep:02x}_f{want}_w{ww}.png")
            write_png(name, ww, h, rows)
            print("  wrote", name, f"{ww}x{h}")


if __name__ == "__main__":
    main()
