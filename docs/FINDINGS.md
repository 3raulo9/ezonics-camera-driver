# Findings: Ezonics EZCam II (P10UC) on 64-bit Windows

Everything we know about the camera and its original driver, how each fact was found, and
what is still unknown. Function addresses (`sub_XXXXXXXX`) refer to `usbcone.sys` loaded at its
preferred base `0x10000`, as listed by `re/disasm.py`.

Status legend: **[HW]** confirmed on a real camera · **[EMU]** observed by running the original
driver code in `re/emu.py` · **[RE]** read from the disassembly only.

## 1. The device

| | |
|---|---|
| Retail name | Ezonics EZCam II USB, model **P10UC** |
| Design | Conexant USB camera reference design, also sold as Tekom "P35U" |
| Bridge chip | Conexant **CN0352P** (reported by a 2001 linux-cpia mailing list post from someone who opened one) |
| USB ID | `VID_0572` (Conexant) `PID_0002`, `bcdDevice 0x0001` |
| USB version | 1.0, full speed, EP0 max packet 8 |
| Strings | none |
| Power | 198 mA, bus powered |

On Windows 11 x64, with no driver, the device shows **error code 28**. Its only interface is
class `0x0A` / subclass `0xFF` (vendor specific), so it isn't a UVC camera. **[HW]**

### Descriptors **[HW]**

```
DEVICE  12 01 00 01 00 00 00 08 72 05 02 00 01 00 00 00 00 01
CONFIG  09 02 65 00 01 01 00 80 63 09 04 00 00 02 0A FF
        00 00 07 05 81 01 00 00 01 07 05 82 01 00 00 01
        09 04 00 01 02 0A FF 00 00 07 05 81 01 22 02 01
        07 05 82 01 11 01 01 09 04 00 02 02 0A FF 00 00
        07 05 81 01 99 01 01 07 05 82 01 CD 00 01 09 04
        00 03 02 0A FF 00 00 07 05 81 01 11 01 01 07 05
        82 01 88 00 01
```

One configuration, one interface (#0) with four alternate settings, each with two
**isochronous IN** endpoints (interval 1 ms):

| Alt | EP 0x81 | EP 0x82 | Total bytes/ms |
|----:|----:|----:|----:|
| 0 | 0 | 0 | 0 (idle) |
| 1 | 546 | 273 | 819 |
| 2 | 409 | 205 | 614 |
| 3 | 273 | 136 | 409 |

The original driver streams in **alt 1**. **[EMU]**

### EEPROM (I2C address 0x50, 256 bytes) **[HW]**

| Offset | Contents |
|---|---|
| `0x00–0x11` | the USB device descriptor (above) |
| `0x12–0x76` | the USB configuration descriptor (above) |
| `0x77` | `FF` |
| `0x78–0xC3` | per-unit calibration: 16-bit little-endian values, likely the bad-pixel list |
| `0xC4–0xEF` | `FF` (unused) |
| `0xF0–0xF9` | `08 00 00 80 0B 28 08 34 28 1F` (configuration, meaning unknown) |

**The bridge chip loads its USB descriptors from this EEPROM.** If the EEPROM is corrupted,
the camera can no longer enumerate, so the tools refuse to write it.

## 2. The original driver

- **Where it came from:** the Internet Archive's copies of the Ezonics site:
  `ezonics.com/drivers/EZCAMNT.exe` (2002-05-30) and `ezonics.com/drivers/ezcam2.exe`
  (2002-06-14). Both are WinZip self-extractors, so `unzip` can unpack them without running
  anything. See `re/fetch-vendor.sh`.
- **Driver binary:** `usbcone.sys`, 82,336 bytes, linked 2000-06-23,
  SHA-256 `b7b84e718faf19c491ec64c41fc1f78eb78f42cb12cbcdf980824178151c37b6`.
- **Type:** 32-bit x86 WDM stream-class minidriver with Microsoft's **USBCAMD** framework
  linked in statically. It imports `STREAM.SYS` and `USBD.SYS` directly. It can't load on
  64-bit Windows, and no 64-bit build exists.
- **INF:** `Usbcone1_inf` binds only `USB\VID_0572&PID_0001`. The same code works for
  `PID_0002`.
- **Output formats advertised:** I420 (12 bpp) and RGB24 at 160×120, 176×144, 320×240,
  352×288 and 640×480. **[RE]**
- **Raw frame buffer:** `0x19610` = 103,952 bytes = **356 × 292 × 1 byte**. The sensor
  delivers an 8-bit raw frame slightly larger than CIF, and the driver converts it in software
  (bad-pixel fix, demosaic, color matrix, sharpening) into the 352×288 output (`0x25200` bytes
  = 352 × 288 × 1.5 for I420). **[RE]**

### Tuning knobs (registry, `HKLM\SOFTWARE\Conexant\USBCAMERA1`)

| Value | INF default | Meaning |
|---|---|---|
| `BadPixelStatus` | 1 | load the EEPROM bad-pixel list into the bridge (§4) |
| `FPNRReduction` | 1 | fixed-pattern-noise reduction (software) |
| `CCE0`..`CCE8` | 1024 diagonal | 3×3 color matrix. It ends up in bridge `5000–5011` as 4 on the diagonal |
| `DigitalGainLevel`, `LoopSpeed` | 1, 1 | auto-exposure (debug strings `new IT=%d`, `new g=%d`) |
| `Brightness` / `Saturation` / `Sharpness` / `Whitebalance` | 60 / 80 / 60 / 60 | |
| `SharpenImage`, `FluorescenceFrequency` | 1, 0 | |

Other values read: `XResolution`, `YResolution`, `FrameRate`, `AWBMethod`, `EnhancePixels`,
`ThreshAboveMean`, `NumBPinImager`, `NumBPonBlack`, `ResetEEPROM`, `CurrentEEPROM`,
`ScreenPrints`.

## 3. Register protocol **[HW]**

Every register access is a vendor control transfer on EP0 with `bRequest = 0`:

| `bmRequestType` | `wValue` | `wIndex` | Addresses |
|---|---|---|---|
| `0x40` write / `0xC0` read | `0x0000` | register | bridge register in the CN0352 (multi-byte writes auto-increment) |
| `0x40` | `0x0044` | register 0x00–0x08 | I2C device 0x44: the **image sensor**. **Write only, see warning.** |
| `0x40` / `0xC0` | `0x0050` | offset | I2C device 0x50: the **EEPROM** (§1). Read only for us. |

Bridge power-on values read from the real camera:
`E000=FE E001=10 E002=02 A000=0C B000=00 C001=00 C002=01 C003=CD C004=33 1000=00 2000=00 9000=00`.

> **Warning: never read the sensor.** A read with `wValue = 0x0044` never completes. It
> leaves the bridge's I2C engine stuck and the shared I2C bus held, so the camera stops
> answering everything. After a USB port reset it can't even load its descriptors
> ("Device Descriptor Request Failed"), because those come from the EEPROM on the same bus.
> Only unplugging the camera (cutting power) recovers it. The original driver never reads
> the sensor, and `EzcamProbe` refuses to.

How it was found: the only code that builds a vendor URB is `sub_000178D0`. Its only caller,
`sub_00017A10`, is USBCAMD's 9-argument `USBCAMD_ControlVendorCommand`. All 70 call sites were
decoded by `re/vendor_calls.py`, and the protocol was then confirmed on hardware with
`EzcamProbe regs` / `eeprom`.

## 4. Initialization and streaming **[EMU]**

`re/emu.py` runs the driver's device-start routine (`sub_00016F90`) in the Unicorn emulator.
Kernel APIs are stubbed, and register reads are answered from the camera's real EEPROM dump and
power-on values. For a 352×288 I420 format and default registry values it issues exactly this:

| Step | Request |
|---|---|
| 1 | read bridge `C000` |
| 2 | select alternate setting **1** |
| 3 | bridge `8020` ← `46 E6 7B 85 7B 85 00 00`, bridge `8028` ← `FF 01 00 00 FF 01` |
| 4 | bridge `1000` ← `0D`, `E000` ← `01`, `E001` ← `07`, `A000` ← `00` |
| 5 | read EEPROM `0x77`, then `0x78–0xFF` in 8-byte blocks |
| 6 | bridge `6100–612F` ← bad-pixel list: 16 entries × 3 bytes, computed from the EEPROM values |
| 7 | bridge `E002` ← `03`, `C001` ← `00`, `C002` ← `01`, `B000` ← `00`, `2000` ← `21`, `9000` ← `02` |
| 8 | bridge `6000–60FF` ← 256-entry gamma curve (`00 05 09 0E 12 16 1A 1D …` rising to `FF`) |
| 9 | bridge `5000–5011` ← 3×3 color matrix of 16-bit entries, diagonal = 4 |
| 10 | bridge `C003` ← `AA`, `C004` ← `AA`, `1000` ← `0C` |
| 11 | sensor `06` ← `00`, `04` ← `50`, `02` ← `01`, `03` ← `00`, `00` ← `01`, `01` ← `00` |
| 12 | sensor `08` ← `01`, `81`, `01` (pulse on bit 7) |
| 13 | bridge `1000` ← `0D` |

The full list, ready to replay, is produced by
`python -I re/emu.py <usbcone.sys> captures/eeprom.bin start stream-on stream-off --sequence=captures/init-cif.seq`.

**Stream start** (`sub_00017660`) sends no register writes. It resets both pipes
(`URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL` ×2), reads the current frame number and
starts isochronous reads of 32 packets per transfer. **Stream stop** (`sub_000176D0`) aborts
both pipes. The power-down path (`sub_00010BB0` → `sub_00020D70`) writes `A000=08`, sensor
`06=01`, sensor `08` pulse, `1000=0C`, `E001=02`.

Init mode is chosen by output width (`sub_00010870`): 176, 320, 352, or a default.

## 5. Stream format **[HW]**

After the §4 sequence and alt 1, both pipes stream with no USB errors (about 21 fps):

- **Every isochronous packet starts with a 1-byte header.** Bit 7 = first packet of a new
  frame, bits 0–2 = frame counter (0–7, wrapping). The rest of the packet is payload. 1-byte
  packets carry no data.
- **EP 0x81: exactly 25,344 bytes per frame = 176 × 144 8-bit luma, row-major.**
- **EP 0x82: exactly 12,672 bytes per frame = the chroma** (values centered on 0x80). The
  layout (planar U/V or interleaved) is still to be confirmed.
- The original driver configures a 176×144 raw frame (`cam+0x214` = 25,344) and scales it up
  to the 352×288 output in software (`sub_00016260` → `sub_00013240` → `sub_00010C00`).
  Running that converter in the emulator on a real captured frame gives a full 352×288 I420
  frame.

Capture pitfall: `WinUsb_ReadIsochPipeAsap` reports packet offsets **relative to the start of
each transfer**, not to the start of the registered buffer.

### Exposure and gain (sensor, from `sub_000212E0` / `sub_00021360`)

| Control | Sensor registers |
|---|---|
| Integration time (9 bits, stored at `cam+0x35E`) | `00` = bits 0–7, `01` bit 0 = bit 8 |
| Gain (7 bits, stored at `cam+0x360`) | `08` = gain; write `gain \| 0x80` then `gain` to apply |

Init leaves IT = 1 and gain = 1. On hardware, a larger IT makes the image **darker**
(IT 100 → mean 66, IT ≥ 300 → constant black 16), so IT behaves like a reset-row offset (larger
= shorter exposure). Gain isn't monotonic (1 → 92, 16 → 24, 64 → 85, 127 → 72), so it's
probably an encoded format. The auto-exposure loop is `sub_00017D40` / `sub_00018460`, which
uses 8 statistics bytes read from bridge `0x8010`.

### Auto-exposure, closed loop **[HW + EMU]**

`re/emu.py … live` runs the original driver's AE code in the emulator and sends its register
traffic to the real camera (through `EzcamProbe serve`). It reads the camera's real `0x8010`
statistics and frames. Indoors it settles at **IT = 291 (0x123), gain = 3**.
`captures/init-ae.seq` is the §4 sequence plus those four sensor writes:

```
W 0x0044 0x0000 23    W 0x0044 0x0001 01    W 0x0044 0x0008 83    W 0x0044 0x0008 03
```

### Snapshot button **[HW]**

Bridge `0xA000` bit 2, **active low** (`0xA000` reads `0x0C` at power-on, button up). The original driver
reads it once per frame. Debouncing over two 100 ms reads is reliable.

## 6. Still unknown

1. **Why the image shows no clear scene.** Even at the original driver's own AE settings and
   through its own 176×144 → 352×288 converter (run in the emulator on real frames), every
   frame is dominated by fixed column bands plus random per-row brightness offsets that change
   from frame to frame. Row noise (the spread of the per-row means) is about 35–40 levels.
   Ruled out:
   - **Capture/sync errors:** frame sizes are exact and the packet headers are consistent.
   - **Mains flicker:** the row-offset spectrum is flat, with no 50/60 Hz peak.

   Since the original driver's code gives the same picture, this is most likely a **hardware
   fault**: an aged sensor or dried-out decoupling capacitors on the sensor supply.
   `EzcamProbe viewer` shows the row-noise figure live, so repairs can be measured.
2. Chroma plane layout on EP 0x82.
3. How the EEPROM values turn into the 3-byte bad-pixel entries (for now the emulator
   computes them).

## 7. Plan for a working camera on Windows 11 x64

A kernel driver would need Microsoft attestation signing, or Secure Boot off plus test mode.
Instead, everything runs in user mode:

1. **WinUSB** (Microsoft-signed, ships with Windows) is bound to the camera by
   `tools/install-winusb.ps1`. Done and working.
2. **A capture service** replays §4, reads both isochronous pipes
   (`WinUsb_ReadIsochPipeAsap`), assembles the 176×144 luma and chroma frames (§5), scales
   them to 352×288 and converts them to NV12. Capture and frame assembly are done
   (`EzcamProbe preview` / `viewer`). Color and scaling aren't.
3. **A Windows 11 virtual camera** (`MFCreateVirtualCamera`, build 22000 and later) exposes those
   frames to every app (Camera, Teams, Zoom, browsers). It's a user-mode COM media source, so
   no kernel signing is needed.
