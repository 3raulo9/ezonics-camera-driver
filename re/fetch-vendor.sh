#!/usr/bin/env bash
# Downloads the original Ezonics EZCam II driver packages from the Internet Archive's copy of
# ezonics.com (2002) and unpacks them WITHOUT running them (they are WinZip self-extractors,
# so plain `unzip` reads them). Everything lands in vendor/, which is gitignored.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p vendor/original vendor/extracted/EZCAMNT vendor/extracted/ezcam2 vendor/analysis

fetch() { # <wayback timestamp> <file name>
  [ -s "vendor/original/$2" ] || curl -sSL --max-time 300 -o "vendor/original/$2" \
    "https://web.archive.org/web/${1}id_/http://www.ezonics.com:80/drivers/$2"
}
fetch 20020530031242 EZCAMNT.exe   # Windows NT/2000 package
fetch 20020614051628 ezcam2.exe    # Windows 98/ME/2000 package (InstallShield + Conexant folder)

unzip -o -q vendor/original/EZCAMNT.exe -d vendor/extracted/EZCAMNT || true
unzip -o -q vendor/original/ezcam2.exe  -d vendor/extracted/ezcam2  || true

# Both packages ship the same driver binary.
sha256sum vendor/extracted/EZCAMNT/usbcone.sys vendor/extracted/ezcam2/Conexant/usbcone.sys
echo "expected b7b84e718faf19c491ec64c41fc1f78eb78f42cb12cbcdf980824178151c37b6"

python -I re/disasm.py vendor/extracted/EZCAMNT/usbcone.sys vendor/analysis/usbcone.asm
