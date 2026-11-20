"""Print a static overview of a PE file: header, sections, imports, exports, strings.

Usage: python -I re/pe_overview.py <file.sys> [--strings]
Never executes the target; it is only parsed.
"""
import re
import sys

import pefile


def main(path, show_strings):
    pe = pefile.PE(path)
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    print(f"Machine=0x{fh.Machine:04X} ImageBase=0x{oh.ImageBase:08X} "
          f"EntryPoint RVA=0x{oh.AddressOfEntryPoint:X} Subsystem={oh.Subsystem}")
    import datetime
    print("Linked:", datetime.datetime.utcfromtimestamp(fh.TimeDateStamp).isoformat())
    print("\nSections:")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        print(f"  {name:8} VA=0x{s.VirtualAddress:06X} "
              f"VSize=0x{s.Misc_VirtualSize:06X} Raw=0x{s.SizeOfRawData:06X} Flags=0x{s.Characteristics:08X}")
    print("\nImports:")
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        names = [(imp.name or f"ord{imp.ordinal}".encode()).decode() for imp in entry.imports]
        print(f"  {entry.dll.decode()}:")
        for imp, n in zip(entry.imports, names):
            print(f"    0x{imp.address:08X}  {n}")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("\nExports:")
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"  {e.name}")
    if show_strings:
        data = open(path, "rb").read()
        print("\nASCII strings (>=6):")
        for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
            print(f"  0x{m.start():06X}  {m.group().decode()}")
        print("\nUTF-16 strings (>=5):")
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", data):
            print(f"  0x{m.start():06X}  {m.group().decode('utf-16le')}")


if __name__ == "__main__":
    main(sys.argv[1], "--strings" in sys.argv)
