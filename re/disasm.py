"""Linear-sweep disassembly of a 32-bit x86 driver's .text section, with import names.

Usage: python -I re/disasm.py <file.sys> <out.asm>
Output lines: <VA>  <bytes>  <mnemonic> <operands>   ; annotations
Function starts (targets of direct calls) are marked with 'sub_XXXXXXXX:'.
"""
import re
import sys

import capstone
import pefile


def main(path, out):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            imports[imp.address] = (imp.name or b"?").decode()

    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    code = text.get_data()[: text.Misc_VirtualSize]
    start = base + text.VirtualAddress

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    insns = list(md.disasm(code, start))

    targets = set()
    for i in insns:
        if i.mnemonic == "call" and re.fullmatch(r"0x[0-9a-f]+", i.op_str):
            targets.add(int(i.op_str, 16))
    targets.add(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    with open(out, "w") as f:
        for i in insns:
            if i.address in targets:
                f.write(f"\nsub_{i.address:08X}:\n")
            note = ""
            m = re.search(r"\[(0x[0-9a-f]+)\]", i.op_str)
            if m and int(m.group(1), 16) in imports:
                note = f"   ; {imports[int(m.group(1), 16)]}"
            f.write(f"{i.address:08X}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}{note}\n")
    print(f"{len(insns)} instructions, {len(targets)} call targets -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
