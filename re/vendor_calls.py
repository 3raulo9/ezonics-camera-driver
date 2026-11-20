"""Recover the arguments of every USBCAMD_ControlVendorCommand call in a disassembly listing.

USBCAMD_ControlVendorCommand(DeviceContext, Request, Value, Index, Buffer,
                             BufferLength, GetData, CommandComplete, CommandContext)
is stdcall, so the 9 arguments are pushed right-to-left right before the call.
For one-byte writes the driver stores the data byte into a stack local between the
pushes and the call; this script tracks esp so it can report that byte too.

Usage: python -I re/vendor_calls.py <listing.asm> <wrapper_va_hex> [--func sub_XXXXXXXX]
"""
import re
import sys

LINE = re.compile(r"^([0-9A-F]{8})  \S+\s+(\S+)\s*(.*?)(?:\s+;.*)?$")
ARGS = ["ctx", "req", "value", "index", "buf", "plen", "get", "cb", "cbctx"]
CALLEE_SAVED = {"ebx", "esi", "edi", "ebp"}
SUB8 = {"bl": "ebx", "cl": "ecx", "dl": "edx", "al": "eax"}
NUM = r"(?:0x[0-9a-f]+|\d+)"


def load(path):
    rows, func = [], None
    for raw in open(path):
        raw = raw.rstrip("\n")
        if raw.startswith("sub_"):
            func = raw[:-1]
            continue
        m = LINE.match(raw)
        if m:
            rows.append((int(m.group(1), 16), m.group(2), m.group(3), func))
    return rows


def reg_value(rows, idx, reg):
    """Constant value of a register at rows[idx], scanning backwards within the function."""
    reg = SUB8.get(reg, reg)
    func = rows[idx][3]
    for j in range(idx - 1, -1, -1):
        _, mn, ops, f = rows[j]
        if f != func or mn == "ret":
            break
        if mn == "call" and reg not in CALLEE_SAVED:
            return None
        if mn == "xor" and ops == f"{reg}, {reg}":
            return 0
        m = re.fullmatch(rf"{reg}, ({NUM})", ops)
        if mn == "mov" and m:
            return int(m.group(1), 0)
        if re.match(rf"{reg},", ops) and mn not in ("cmp", "test", "push"):
            return None
    return None


def operand_value(rows, idx, op):
    if re.fullmatch(NUM, op):
        return int(op, 0)
    if re.fullmatch(r"[a-d][lx]|e[a-d]x|e[sd]i|ebp", op):
        return reg_value(rows, idx, op)
    return None


def main(path, wrapper, only_func=None):
    rows = load(path)
    target = f"0x{wrapper.lower().removeprefix('0x')}"
    for i, (va, mn, ops, func) in enumerate(rows):
        if mn != "call" or ops != target or (only_func and func != only_func):
            continue
        # find the 9 pushes
        push_idx, j = [], i - 1
        while j >= 0 and len(push_idx) < 9 and i - j < 80:
            if rows[j][1] == "push":
                push_idx.append(j)
            elif rows[j][1] in ("call", "ret"):
                break
            j -= 1
        if len(push_idx) < 9:
            print(f"{func:13} {va:08X}  <could not find 9 pushes>")
            continue
        start = push_idx[-1]
        # walk forward tracking esp delta (relative to esp before the first push)
        delta, regs_lea, stack_bytes, stack_dwords = 0, {}, {}, {}
        for k in range(start, i):
            _, kmn, kops, _ = rows[k]
            if kmn == "push":
                delta -= 4
            m = re.fullmatch(rf"(e[a-d]x|e[sd]i|ebp), \[esp \+ ({NUM})\]", kops)
            if kmn == "lea" and m:
                regs_lea[m.group(1)] = delta + int(m.group(2), 0)
            m = re.fullmatch(rf"byte ptr \[esp \+ ({NUM})\], (\S+)", kops)
            if kmn == "mov" and m:
                stack_bytes[delta + int(m.group(1), 0)] = operand_value(rows, k, m.group(2))
            m = re.fullmatch(rf"dword ptr \[esp \+ ({NUM})\], (\S+)", kops)
            if kmn == "mov" and m:
                stack_dwords[delta + int(m.group(1), 0)] = operand_value(rows, k, m.group(2))
        vals, data = {}, None
        for name, pj in zip(ARGS, push_idx):
            op = rows[pj][2]
            vals[name] = operand_value(rows, pj, op)
            if vals[name] is None:
                vals[name] = op
            if name == "buf" and op in regs_lea:
                data = stack_bytes.get(regs_lea[op], "?")
            if name == "plen" and op in regs_lea:
                vals["len"] = stack_dwords.get(regs_lea[op], "?")

        def h(v, w):
            return f"0x{v:0{w}X}" if isinstance(v, int) else f"<{v}>"

        direction = {0: "WRITE", 1: "READ "}.get(vals["get"], f"get={vals['get']}")
        line = (f"{func:13} {va:08X}  {direction} req={h(vals['req'], 2)} value={h(vals['value'], 4)} "
                f"index={h(vals['index'], 4)} len={h(vals.get('len', '?'), 1)}")
        if vals["get"] == 0:
            line += f" data={h(data, 2) if data is not None else '<?>'}"
        print(line)


if __name__ == "__main__":
    f = sys.argv[sys.argv.index("--func") + 1] if "--func" in sys.argv else None
    main(sys.argv[1], sys.argv[2], f)
