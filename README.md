# Ezonics EZCam II (P10UC) driver for 64-bit Windows

A from-scratch, user-mode driver for the **Ezonics EZCam II USB (model P10UC)**, a 2000-era
webcam built on a Conexant CN0352 bridge chip (USB `VID_0572&PID_0002`). The only drivers
ever released were 32-bit drivers for Windows 98/2000/XP, so the camera shows up on Windows 10/11
x64 as an unknown device with error code 28.

The camera's protocol was undocumented. It is being recovered by static analysis of the
original 2000 driver (`usbcone.sys`). See **[docs/FINDINGS.md](docs/FINDINGS.md)** for every
finding so far.

## Status

| Piece | State |
|---|---|
| USB descriptors and endpoint layout | done, confirmed on hardware |
| WinUSB binding without Device Manager (`tools/install-winusb.ps1`) | done, confirmed on hardware |
| Register protocol (bridge / sensor / EEPROM access) | done, confirmed on hardware |
| Full init sequence, stream start/stop | done (from running the original driver in an emulator) |
| Isochronous capture, frame assembly (about 21 fps) | done, confirmed on hardware |
| Exposure / gain, snapshot button | done, confirmed on hardware |
| Live viewer for testing (`EzcamProbe viewer`) | done |
| Image quality | **row noise even with the original driver's settings; likely a hardware fault** (see FINDINGS §6) |
| Chroma layout / color conversion | **todo** |
| Windows 11 virtual camera (shows up in Teams/Zoom/Camera) | **todo** |

## How it works (planned)

```
EZCam II ──USB──> WinUSB (in-box, Microsoft-signed)
                     │
                     ▼
               capture service ── replays init, reads isochronous video, builds frames
                     │
                     ▼
        Windows 11 virtual camera (MFCreateVirtualCamera) ──> Camera, Teams, Zoom, browsers
```

There's no kernel driver, so no test-signing mode and no need to turn off Secure Boot.

## Step 1: bind WinUSB to the camera

This uses Microsoft's own generic USB driver, and no custom driver files. From an
administrator PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File tools\install-winusb.ps1     # bind
powershell -ExecutionPolicy Bypass -File tools\uninstall-winusb.ps1   # undo
```

Or do it by hand:

1. Plug in the camera and open **Device Manager** (Win+X → Device Manager).
2. Under **Other devices**, right-click the unknown device (*USB Device* / `VID_0572&PID_0002`)
   → **Update driver**.
3. **Browse my computer for drivers** → **Let me pick from a list of available drivers on my computer**.
4. Select **Universal Serial Bus devices** → **Next**.
5. Manufacturer **WinUsb Device**, model **WinUsb Device** → **Next** → accept the warning.

## Viewer (hardware testing)

`EzcamProbe viewer` opens a live window: luma at 3×, about 21 fps, with readouts for
**brightness**, **row noise** (strength of the horizontal streaks) and **column noise**.

- Keys: Up/Down = exposure, Left/Right = gain (Shift = bigger steps), R = reset, S = snapshot, Esc = quit.
- The button on the camera also takes a snapshot. Snapshots go to `Pictures\EZCam II`.
- If the camera is on a USB port where WinUSB isn't set up yet, the viewer offers to run
  `install-winusb.ps1` (one UAC prompt).

To install it with a desktop shortcut (per-user, no admin):

```powershell
$dest = "$env:LOCALAPPDATA\Programs\EZCam II Viewer"
dotnet publish tools/EzcamProbe -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o $dest
Copy-Item captures/init-ae.seq "$dest\init.seq"      # init sequence generated for your camera by re/emu.py
Copy-Item tools/install-winusb.ps1 $dest
# then create a shortcut to "$dest\EzcamProbe.exe" with the argument: viewer
```

## Tools

| Path | What it does |
|---|---|
| `tools/dump-desc.ps1` | Reads the camera's USB descriptors through its hub. Works without any driver. |
| `tools/install-winusb.ps1` / `uninstall-winusb.ps1` | Bind and unbind Microsoft's in-box WinUSB driver (admin). |
| `tools/cycle-port.ps1` | USB port reset (admin). Doesn't help after a sensor-read lockup: unplug the camera instead. |
| `tools/EzcamProbe/` | .NET 10 tool: register read/write, EEPROM dump (read only), init replay, isochronous capture, live viewer, and a stdin register server for `re/emu.py live`. |
| `re/analyze_capture.py`, `re/render_frames.py`, `re/i420_to_png.py` | Inspect raw captures and turn them into PNGs. |
| `re/emu.py` | Runs the original driver's code in the Unicorn emulator and logs every USB request it would make. |
| `re/callgraph.py` | Compact call graph of the disassembly. |
| `re/fetch-vendor.sh` | Downloads the original 2002 driver packages from the Internet Archive into `vendor/` and unpacks them without running them. |
| `re/pe_overview.py` | Sections, imports and strings of a PE file. |
| `re/disasm.py` | Annotated linear disassembly of the driver (needs `capstone`, `pefile`). |
| `re/vendor_calls.py` | Recovers every vendor control request the driver issues. |

```powershell
# build and try the probe (after step 1)
dotnet build tools/EzcamProbe -c Release
dotnet tools/EzcamProbe/bin/Release/net10.0-windows/EzcamProbe.dll info
dotnet tools/EzcamProbe/bin/Release/net10.0-windows/EzcamProbe.dll regs
dotnet tools/EzcamProbe/bin/Release/net10.0-windows/EzcamProbe.dll eeprom captures/eeprom.bin

# generate the init sequence by emulating the original driver, then capture 3 s of raw video
python -I re/emu.py vendor/extracted/EZCAMNT/usbcone.sys captures/eeprom.bin start stream-on stream-off --sequence=captures/init-cif.seq
dotnet tools/EzcamProbe/bin/Release/net10.0-windows/EzcamProbe.dll capture captures/init-cif.seq 3 captures/stream1.bin
```

> Never read the sensor (I2C 0x44): it locks the camera up until it is unplugged.

## Legal note

The original Ezonics/Conexant files are not included in this repository; `vendor/` is
gitignored and `re/fetch-vendor.sh` downloads them. This project only documents the
camera's hardware interface (register addresses and values) so the camera can work with
modern systems.
