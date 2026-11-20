"""Convert a raw I420 (YUV 4:2:0 planar) frame to PNG.

Usage: python -I re/i420_to_png.py <in.i420> <out.png> [width height]
"""
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from render_frames import write_png  # noqa: E402


def clamp(v):
    return 0 if v < 0 else 255 if v > 255 else int(v)


def i420_to_rgb_rows(data, w, h):
    y_plane = data[:w * h]
    u_plane = data[w * h:w * h + (w // 2) * (h // 2)]
    v_plane = data[w * h + (w // 2) * (h // 2):w * h + 2 * (w // 2) * (h // 2)]
    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            Y = y_plane[y * w + x]
            U = u_plane[(y // 2) * (w // 2) + x // 2] - 128
            V = v_plane[(y // 2) * (w // 2) + x // 2] - 128
            row += bytes((clamp(Y + 1.402 * V), clamp(Y - 0.344 * U - 0.714 * V), clamp(Y + 1.772 * U)))
        rows.append(row)
    return rows


if __name__ == "__main__":
    w, h = (int(sys.argv[3]), int(sys.argv[4])) if len(sys.argv) > 4 else (352, 288)
    data = open(sys.argv[1], "rb").read()
    write_png(sys.argv[2], w, h, i420_to_rgb_rows(data, w, h), channels=3)
    print("wrote", sys.argv[2])
