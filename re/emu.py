"""Run pieces of the original usbcone.sys in the Unicorn CPU emulator and log what it would
send to the camera.

Nothing here touches real hardware or the real kernel. Kernel APIs are replaced by small Python
stubs; USB requests are answered from the real camera's descriptors, a register model seeded
with power-on values read from the real camera, and a dump of the camera's EEPROM.

Usage:
  python -I re/emu.py <usbcone.sys> <eeprom.bin> [scenario ...]

Scenarios (run in order on the same emulated device):
  start        device start (sub_16F90): registry, init sequence, buffers
  capture-on   start-capture path (sub_10BB0)
  stream-on    stream worker (sub_16630) with "start"
  stream-off   stream worker (sub_16630) with "stop"
"""
import os
import struct
import sys

import pefile
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE)
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESP

STUB_BASE, HEAP_BASE, STACK_BASE = 0x0F000000, 0x20000000, 0x30000000
HEAP_SIZE, STACK_SIZE = 0x02000000, 0x00100000
RETURN_MAGIC = 0x0F00FFF0

# Camera facts (docs/FINDINGS.md). The EEPROM starts with the device descriptor (18 bytes)
# followed by the configuration descriptor (101 bytes), so those are taken from the dump.
ALT_PACKETS = {0: (0, 0), 1: (546, 273), 2: (409, 205), 3: (273, 136)}
POWER_ON_REGS = {0xE000: 0xFE, 0xE001: 0x10, 0xE002: 0x02, 0xA000: 0x0C, 0xB000: 0x00, 0xC001: 0x00,
                 0xC002: 0x01, 0xC003: 0xCD, 0xC004: 0x33, 0x1000: 0x00, 0x2000: 0x00, 0x9000: 0x00}

# Registry defaults from the original INF (HKLM\SOFTWARE\Conexant\USBCAMERA1)
REGISTRY = {"ApplyRegistryValues": 12345678, "BadPixelStatus": 1, "FluorescenceFrequency": 0,
            "Brightness": 60, "Saturation": 80, "Sharpness": 60, "Whitebalance": 60, "SharpenImage": 1,
            "CCE0": 1024, "CCE1": 0, "CCE2": 0, "CCE3": 0, "CCE4": 1024, "CCE5": 0, "CCE6": 0, "CCE7": 0,
            "CCE8": 1024, "LoopSpeed": 1, "DigitalGainLevel": 1, "FPNRReduction": 1, "SnapshotButton": 0}

# Values read from the device's own registry key with ZwQueryValueKey (none by default;
# set e.g. --reg FrameRate=10 on the command line).
DEVICE_KEY = {}

# stdcall stack-argument counts; None = cdecl (caller cleans up)
API_ARGS = {
    "_aulldiv": 4, "_allmul": 4, "KeInitializeSpinLock": 1, "IofCallDriver": 0, "IoFreeIrp": 1,
    "IoAllocateIrp": 2, "KeSetTimer": 4, "IoInitializeIrp": 3, "KeInitializeTimer": 1,
    "ExfInterlockedRemoveHeadList": 0, "ExQueueWorkItem": 2, "KeInitializeDpc": 3, "RtlCompareMemory": 3,
    "IoBuildDeviceIoControlRequest": 9, "KeInitializeEvent": 3, "InterlockedDecrement": 0,
    "RtlInitUnicodeString": 2, "InterlockedIncrement": 0, "KeInitializeSemaphore": 3, "KeCancelTimer": 1,
    "ExfInterlockedInsertTailList": 1, "ZwQueryValueKey": 6, "KeDelayExecutionThread": 3,
    "IoOpenDeviceRegistryKey": 4, "ZwClose": 1, "wcscmp": None, "RtlQueryRegistryValues": 5,
    "sprintf": None, "RtlWriteRegistryValue": 6, "ExAllocatePoolWithTag": 3, "ExFreePool": 1,
    "KeSetEvent": 3, "KeReleaseSemaphore": 4, "KeWaitForSingleObject": 5, "KeGetCurrentIrql": 0,
    "KfReleaseSpinLock": 0, "KfAcquireSpinLock": 0, "StreamClassStreamNotification": None,
    "StreamClassQueryMasterClockSync": 2, "StreamClassRegisterAdapter": 3,
    "StreamClassDeviceNotification": None, "_USBD_CreateConfigurationRequestEx@8": 2,
    "_USBD_ParseConfigurationDescriptorEx@28": 7,
}

VENDOR_CMD = 0x17A10   # USBCAMD_ControlVendorCommand(ctx, req, value, index, buf, plen, get, cb, cbctx)
SUBMIT_URB = 0x16B00   # synchronous URB submit (ext, urb)


class Emu:
    def __init__(self, sys_path, eeprom):
        self.pe = pefile.PE(sys_path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.eeprom = bytearray(eeprom)
        self.regs = dict(POWER_ON_REGS)
        self.log = []
        self.work = []
        self.heap = HEAP_BASE
        self.alt = 0
        self.proxy = None
        uc = self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        size = (self.pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        uc.mem_map(self.base, size)
        uc.mem_write(self.base, self.pe.get_memory_mapped_image())
        uc.mem_map(STUB_BASE, 0x10000)
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        uc.mem_map(STACK_BASE, STACK_SIZE)
        self.stubs = {}
        n = 0
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                addr = STUB_BASE + n * 0x10
                n += 1
                uc.mem_write(addr, b"\xC3")
                uc.mem_write(imp.address, struct.pack("<I", addr))
                self.stubs[addr] = imp.name.decode()
        uc.mem_write(RETURN_MAGIC, b"\xF4")  # hlt
        uc.hook_add(UC_HOOK_CODE, self._on_stub, begin=STUB_BASE, end=STUB_BASE + 0xFFFF)
        uc.hook_add(UC_HOOK_CODE, self._on_vendor, begin=VENDOR_CMD, end=VENDOR_CMD)
        uc.hook_add(UC_HOOK_CODE, self._on_submit, begin=SUBMIT_URB, end=SUBMIT_URB)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_bad_mem)
        # Structures we don't model contain NULL pointers; give them a zero page so execution
        # continues, and note each code location that relied on it.
        uc.mem_map(0, 0x10000)
        self.null_users = set()
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._on_null, begin=0, end=0xFFFF)

    # ---- memory helpers -------------------------------------------------------------------
    def alloc(self, size):
        addr = self.heap
        self.heap += (size + 0x1F) & ~0xF
        self.uc.mem_write(addr, b"\0" * size)
        return addr

    def proxy_cmd(self, line):
        self.proxy.stdin.write(line + "\n")
        self.proxy.stdin.flush()
        reply = self.proxy.stdout.readline().strip()
        if reply.startswith("error"):
            raise RuntimeError(f"camera: {reply} (for {line})")
        return reply

    def make_irp(self, at=None, stack=8):
        """A zeroed x86 IRP with `stack` I/O stack locations, set up like IoInitializeIrp does."""
        size = 0x70 + stack * 0x24
        irp = at or self.alloc(size)
        self.uc.mem_write(irp, b"\0" * size)
        self.w16(irp, 6)                                   # IO_TYPE_IRP
        self.w16(irp + 2, size)
        self.uc.mem_write(irp + 0x22, bytes([stack, stack + 1]))
        # The "next" stack location is the last one; CurrentStackLocation points just past it.
        self.w32(irp + 0x60, irp + 0x70 + stack * 0x24)
        return irp

    def u32(self, a): return struct.unpack("<I", self.uc.mem_read(a, 4))[0]
    def u16(self, a): return struct.unpack("<H", self.uc.mem_read(a, 2))[0]
    def u8(self, a): return self.uc.mem_read(a, 1)[0]
    def w32(self, a, v): self.uc.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))
    def w16(self, a, v): self.uc.mem_write(a, struct.pack("<H", v & 0xFFFF))

    def wstr(self, a):
        out = bytearray()
        while a:
            c = self.uc.mem_read(a, 2)
            if c == b"\0\0":
                break
            out += c
            a += 2
        return out.decode("utf-16le", errors="replace")

    def arg(self, i):
        return self.u32(self.uc.reg_read(UC_X86_REG_ESP) + 4 + 4 * i)

    def _return(self, value, nargs):
        uc = self.uc
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret = self.u32(esp)
        uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * (nargs or 0))
        uc.reg_write(UC_X86_REG_EAX, value & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_EIP, ret)

    # ---- hooks ----------------------------------------------------------------------------
    def _on_null(self, uc, access, addr, size, value, _):
        eip = uc.reg_read(UC_X86_REG_EIP)
        if eip not in self.null_users:
            self.null_users.add(eip)
            self.log.append(f"   (null-page {'write' if access == UC_MEM_WRITE else 'read'} "
                            f"0x{addr:04X} at EIP 0x{eip:08X})")

    def _on_bad_mem(self, uc, access, addr, size, value, _):
        eip = uc.reg_read(UC_X86_REG_EIP)
        self.log.append(f"!! unmapped memory access at 0x{addr:08X} from EIP 0x{eip:08X}")
        return False

    def _on_vendor(self, uc, addr, size, _):
        req, value, index, buf, plen, get, cb = (self.arg(i) for i in range(1, 8))
        # UCHAR/USHORT/BOOLEAN arguments are pushed as 32-bit slots with junk in the upper bits.
        req, value, index, get = req & 0xFF, value & 0xFFFF, index & 0xFFFF, get & 0xFF
        length = self.u32(plen) if plen else 0
        target = {0x0000: "bridge", 0x0044: "sensor", 0x0050: "eeprom"}.get(value, f"0x{value:04X}")
        if self.proxy and value != 0x0044 or (self.proxy and not get):
            # Forward to the real camera (tools/EzcamProbe serve). Sensor reads are never forwarded.
            if get:
                data = bytes.fromhex(self.proxy_cmd(f"R {value:04X} {index:04X} {length}"))
                if buf and length:
                    uc.mem_write(buf, data[:length])
                self.log.append(f"HW READ  {target:6} 0x{index:04X} -> {data.hex(' ')}")
            elif value != 0x50:
                data = bytes(uc.mem_read(buf, length)) if buf and length else b""
                self.proxy_cmd(f"W {value:04X} {index:04X} {data.hex()}")
                self.log.append(f"HW WRITE {target:6} 0x{index:04X} = {data.hex(' ')}")
            self._return(0, 9)
            return
        if get:
            if value == 0x50:
                data = bytes(self.eeprom[(index + i) & 0xFF] for i in range(length))
            elif value == 0:
                data = bytes(self.regs.get(index + i, 0) for i in range(length))
            else:
                data = b"\0" * length
            if buf and length:
                uc.mem_write(buf, data)
            self.log.append(f"READ  {target:6} 0x{index:04X} len={length} -> {data.hex(' ')}")
        else:
            data = bytes(uc.mem_read(buf, length)) if buf and length else b""
            if value == 0:
                for i, b in enumerate(data):
                    self.regs[index + i] = b
            elif value == 0x50:
                self.log.append("!! driver tried to WRITE the EEPROM (ignored)")
            self.log.append(f"WRITE {target:6} 0x{index:04X} = {data.hex(' ')}"
                            + (f"  (req=0x{req:02X})" if req else ""))
        if cb:
            self.log.append(f"   (completion callback 0x{cb:08X} not run)")
        self._return(0, 9)

    def _on_submit(self, uc, addr, size, _):
        urb = self.arg(1)
        fn = self.u16(urb + 2)
        if fn in (0x0000, 0x0001):   # SELECT_CONFIGURATION / SELECT_INTERFACE
            iface = urb + (0x18 if fn == 0 else 0x14)
            if fn == 0 and self.u32(urb + 0x10) == 0:
                self.log.append("USB   deconfigure")
                self._return(0, 2)
                return
            alt = self.u8(iface + 3)
            self.alt = alt
            npipes = 2
            self.w32(iface + 8, 0x51F0000 + alt)  # InterfaceHandle
            self.w32(iface + 12, npipes)
            for p, ep in enumerate((0x81, 0x82)):
                pi = iface + 16 + p * 20
                self.w16(pi, ALT_PACKETS.get(alt, (0, 0))[p])
                self.uc.mem_write(pi + 2, bytes([ep, 1]))
                self.w32(pi + 4, 1)                       # UsbdPipeTypeIsochronous
                self.w32(pi + 8, 0x9100000 + ep)          # PipeHandle
            if fn == 0:
                self.w32(urb + 0x14, 0xC0F16)            # ConfigurationHandle
            self.log.append(f"USB   {'select configuration' if fn == 0 else 'select interface'} alt={alt}")
        elif fn == 0x000B:            # GET_DESCRIPTOR_FROM_DEVICE
            dtype, length, buf = self.u8(urb + 0x4B), self.u32(urb + 0x18), self.u32(urb + 0x1C)
            src = {1: bytes(self.eeprom[0:18]), 2: bytes(self.eeprom[18:18 + 101])}.get(dtype, b"")[:length]
            if buf:
                uc.mem_write(buf, src)
            self.w32(urb + 0x18, len(src))
            self.log.append(f"USB   get descriptor type={dtype} len={length}")
        elif fn == 0x000A:
            self.log.append(f"USB   isochronous transfer pipe=0x{self.u32(urb + 0x10):08X} "
                            f"packets={self.u32(urb + 0x4C)}")
        else:
            self.log.append(f"USB   URB function 0x{fn:04X}")
        self.w32(urb + 4, 0)  # Hdr.Status = success
        self._return(0, 2)

    def _on_stub(self, uc, addr, size, _):
        name = self.stubs.get(addr, "?")
        nargs = API_ARGS.get(name, 0)
        ecx, edx = uc.reg_read(UC_X86_REG_ECX), uc.reg_read(UC_X86_REG_EDX)
        r = 0
        if name == "ExAllocatePoolWithTag":
            r = self.alloc(self.arg(1))
        elif name in ("IoAllocateIrp", "IoBuildDeviceIoControlRequest"):
            r = self.make_irp()
        elif name == "IoInitializeIrp":
            self.make_irp(at=self.arg(0))
        elif name == "KeDelayExecutionThread":
            interval = struct.unpack("<q", self.uc.mem_read(self.arg(2), 8))[0]
            self.log.append(f"SLEEP {-interval / 10000:.1f} ms")
        elif name == "KeSetTimer":
            due = struct.unpack("<q", struct.pack("<II", self.arg(1), self.arg(2)))[0]
            self.log.append(f"TIMER set due={-due / 10000:.1f} ms dpc=0x{self.arg(3):08X}")
        elif name == "ExQueueWorkItem":
            item = self.arg(0)
            self.work.append((self.u32(item + 8), self.u32(item + 12)))
        elif name in ("InterlockedIncrement", "InterlockedDecrement"):
            v = self.u32(ecx) + (1 if name == "InterlockedIncrement" else -1)
            self.w32(ecx, v)
            r = v
        elif name == "ExfInterlockedRemoveHeadList":
            first = self.u32(ecx)
            if first == ecx or first == 0:
                r = 0
            else:
                nxt = self.u32(first)
                self.w32(ecx, nxt)
                self.w32(nxt + 4, ecx)
                r = first
        elif name == "ExfInterlockedInsertTailList":
            head, entry = ecx, edx
            if self.u32(head) == 0:
                self.w32(head, head)
                self.w32(head + 4, head)
            tail = self.u32(head + 4)
            self.w32(entry, head)
            self.w32(entry + 4, tail)
            self.w32(tail, entry)
            self.w32(head + 4, entry)
        elif name == "RtlCompareMemory":
            a, b, n = self.arg(0), self.arg(1), self.arg(2)
            x, y = self.uc.mem_read(a, n), self.uc.mem_read(b, n)
            r = next((i for i in range(n) if x[i] != y[i]), n)
        elif name == "wcscmp":
            r = (self.wstr(self.arg(0)) > self.wstr(self.arg(1))) - (self.wstr(self.arg(0)) < self.wstr(self.arg(1)))
        elif name == "RtlInitUnicodeString":
            dst, src = self.arg(0), self.arg(1)
            n = len(self.wstr(src)) * 2 if src else 0
            self.uc.mem_write(dst, struct.pack("<HHI", n, n + 2 if src else 0, src))
        elif name == "RtlQueryRegistryValues":
            self._registry(self.arg(1), self.arg(2))
        elif name == "IoOpenDeviceRegistryKey":
            self.w32(self.arg(3), 0x4E9)
        elif name == "ZwQueryValueKey":
            # (KeyHandle, PUNICODE_STRING ValueName, Class, Info, Length, PULONG ResultLength)
            us = self.arg(1)
            vname = self.wstr(self.u32(us + 4)) if us else ""
            if vname in DEVICE_KEY and self.arg(4) >= 16:
                info = self.arg(3)
                self.uc.mem_write(info, struct.pack("<IIII", 0, 4, 4, DEVICE_KEY[vname]))
                if self.arg(5):
                    self.w32(self.arg(5), 16)
                self.log.append(f"REG   (device key) {vname} = {DEVICE_KEY[vname]}")
                r = 0
            else:
                r = 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND
        elif name in ("_allmul", "_aulldiv"):
            a = self.arg(0) | (self.arg(1) << 32)
            b = self.arg(2) | (self.arg(3) << 32)
            v = (a * b) if name == "_allmul" else (a // b if b else 0)
            uc.reg_write(UC_X86_REG_EDX, (v >> 32) & 0xFFFFFFFF)
            r = v & 0xFFFFFFFF
        elif name in ("KeWaitForSingleObject", "KeReleaseSemaphore", "KeSetEvent"):
            r = 0
        self._return(r, nargs)

    def _registry(self, path_ptr, table):
        path = self.wstr(path_ptr) if path_ptr else ""
        while True:
            routine, flags, name_ptr, ctx, dtype, ddata, dlen = struct.unpack("<7I", self.uc.mem_read(table, 28))
            if routine == 0 and name_ptr == 0:
                break
            name = self.wstr(name_ptr) if name_ptr else ""
            if flags & 0x20 and ctx:  # RTL_QUERY_REGISTRY_DIRECT
                if name in REGISTRY:
                    self.w32(ctx, REGISTRY[name])
                    src = "INF"
                elif dtype == 4 and ddata:
                    self.w32(ctx, self.u32(ddata))
                    src = "default"
                else:
                    src = "unset"
                self.log.append(f"REG   {name} = {self.u32(ctx)} ({src})")
            table += 28
        _ = path

    # ---- running --------------------------------------------------------------------------
    def call(self, func, *args, limit=5_000_000):
        uc = self.uc
        esp = STACK_BASE + STACK_SIZE - 0x1000
        for a in reversed(args):
            esp -= 4
            self.w32(esp, a)
        esp -= 4
        self.w32(esp, RETURN_MAGIC)
        uc.reg_write(UC_X86_REG_ESP, esp)
        try:
            uc.emu_start(func, RETURN_MAGIC, count=limit)
        except UcError as e:
            self.log.append(f"!! emulation stopped in 0x{func:08X}: {e} at EIP 0x{uc.reg_read(UC_X86_REG_EIP):08X}")
        result = uc.reg_read(UC_X86_REG_EAX)
        while self.work:
            routine, param = self.work.pop(0)
            self.log.append(f"WORK  run work item 0x{routine:08X}")
            self.call(routine, param, limit=limit)
        return result


def split_capture(path):
    """Frames from an `EzcamProbe capture` file, split like the driver does: a packet whose
    1-byte header has bit 7 set starts a new frame; the header byte is dropped."""
    data = open(path, "rb").read()
    pos, pipes = 0, {0x81: [], 0x82: []}
    while pos < len(data):
        ep, _, _, _, n = struct.unpack_from("<BIHiH", data, pos)
        pos += 13
        pipes.setdefault(ep, []).append(data[pos:pos + n])
        pos += n
    result = []
    for ep in (0x81, 0x82):
        frames, cur = [], None
        for p in pipes[ep]:
            if not p:
                continue
            if p[0] & 0x80:
                if cur is not None:
                    frames.append(bytes(cur))
                cur = bytearray()
            if cur is not None:
                cur += p[1:]
        result.append(frames)
    return result


def main():
    sys_path, eeprom_path = sys.argv[1], sys.argv[2]
    for a in sys.argv:
        if a.startswith("--reg="):
            k, v = a.split("=", 1)[1].split(":")
            DEVICE_KEY[k] = int(v)
    scenarios = [a for a in sys.argv[3:] if not a.startswith("--reg=")] or ["start"]
    emu = Emu(sys_path, open(eeprom_path, "rb").read())
    ext = emu.alloc(0x4000)       # USBCAMD device extension; camera context lives at ext+0x60
    cam = emu.alloc(0x4000)       # per-device camera state (holds BadPixelStatus at +0x41B)
    emu.w32(ext + 0x54, cam)
    # ctx+0x24 -> USBD_INTERFACE_INFORMATION for interface 0 (normally filled in when the
    # configuration is selected, which happens before sub_16F90 runs).
    iface = emu.alloc(16 + 2 * 20)
    emu.w16(iface, 16 + 2 * 20)
    emu.w32(iface + 12, 2)
    for p, ep in enumerate((0x81, 0x82)):
        emu.uc.mem_write(iface + 16 + p * 20 + 2, bytes([ep, 1]))
        emu.w32(iface + 16 + p * 20 + 4, 1)
        emu.w32(iface + 16 + p * 20 + 8, 0x9100000 + ep)
    emu.w32(ext + 0x60 + 0x24, iface)
    emu.w32(ext + 0x24, 0xC0F16)            # USBD configuration handle
    emu.w32(ext + 0x2C, emu.alloc(0x100))   # USBCAMD's copy of the current interface info
    # cam+0x288 -> selected KS_DATAFORMAT_VIDEOINFOHEADER (bmiHeader at +0x70). Point it at the
    # driver's own built-in format whose BITMAPINFOHEADER sits at FORMATS[name].
    formats = {"cif-i420": 0x22740, "qvga-i420": 0x224F0, "qcif-i420": 0x222A0,
               "qqvga-i420": 0x22990, "vga-i420": 0x22BE0}
    fmt = next((a.split("=", 1)[1] for a in scenarios if a.startswith("--format=")), "cif-i420")
    scenarios = [s for s in scenarios if not s.startswith("--")]
    emu.w32(cam + 0x288, formats[fmt] - 0x70)
    emu.log.append(f"format {fmt}")
    for s in scenarios:
        emu.log.append(f"===== {s} =====")
        if s == "start":
            r = emu.call(0x16F90, ext, cam)
        elif s == "stream-on":
            r = emu.call(0x17660, ext, cam)
        elif s == "stream-off":
            r = emu.call(0x176D0, ext, cam)
        elif s == "power-down":
            r = emu.call(0x10BB0, emu.u32(ext + 0x1C), ext + 0x60)
        elif s == "decode":
            # Feed one captured frame through the driver's own raw->I420 converter (sub_00010C00).
            cap = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--capture="))
            idx = int(next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--frame=")), "3"))
            out_path = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--out=")), "frame.i420")
            y_frames, c_frames = split_capture(cap)
            yf, cf = y_frames[idx], c_frames[idx]
            raw_size = emu.u32(cam + 0x214)
            raw = emu.alloc(raw_size * 2)
            emu.uc.mem_write(raw, yf[:raw_size])
            emu.uc.mem_write(raw + raw_size, cf[:raw_size // 2])
            out_len = 352 * 288 * 3
            out = emu.alloc(out_len)
            frame_ctx = emu.alloc(0x100)
            ret_len = emu.alloc(4)
            emu.log.append(f"decode frame {idx}: luma {len(yf)} bytes, chroma {len(cf)} bytes, raw buffer {raw_size}")
            if emu.u8(cam + 0x41B):   # same order as the work item at sub_000162C0
                emu.call(0x13240, ext + 0x60, cam, out, raw, limit=2_000_000_000)
                emu.log.append("ran sub_00013240 (pre-pass)")
            r = emu.call(0x10C00, 0, ext + 0x60, cam, frame_ctx, out, out_len, raw, 0, 32, len(yf), ret_len,
                         limit=2_000_000_000)
            n = emu.u32(ret_len)
            emu.log.append(f"converter returned 0x{r:08X}, {n} bytes of output")
            with open(out_path, "wb") as f:
                f.write(bytes(emu.uc.mem_read(out, n or 352 * 288 * 3 // 2)))
            emu.log.append(f"wrote {out_path}")
        elif s == "live":
            # Closed loop with the real camera: the original driver's per-frame processing (incl.
            # auto-exposure) runs here, its register traffic goes to the camera via EzcamProbe serve.
            import subprocess
            opt = {a.split("=", 1)[0][2:]: a.split("=", 1)[1] for a in sys.argv if a.startswith("--") and "=" in a}
            emu.proxy = subprocess.Popen(["dotnet", opt["probe"], "serve", opt["seq"]], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True, bufsize=1)
            assert emu.proxy.stdout.readline().strip() == "ready"
            raw_size = emu.u32(cam + 0x214)
            raw = emu.alloc(raw_size * 2)
            out_len = 352 * 288 * 3
            out = emu.alloc(out_len)
            ret_len = emu.alloc(4)
            frame_file = opt.get("frame-file", "captures/live.yc")
            out_dir = opt.get("out-dir", "captures/live")
            os.makedirs(out_dir, exist_ok=True)
            n_iter = int(opt.get("iterations", "40"))
            for i in range(n_iter):
                emu.proxy_cmd(f"F {frame_file}")
                yc = open(frame_file, "rb").read()
                emu.uc.mem_write(raw, yc[:raw_size])
                emu.uc.mem_write(raw + raw_size, yc[raw_size:raw_size + raw_size // 2])
                mark = len(emu.log)
                if emu.u8(cam + 0x41B):
                    emu.call(0x13240, ext + 0x60, cam, out, raw, limit=2_000_000_000)
                emu.call(0x10C00, 0, ext + 0x60, cam, emu.alloc(0x100), out, out_len, raw, 0, 32, raw_size, ret_len,
                         limit=2_000_000_000)
                hw = [l for l in emu.log[mark:] if l.startswith("HW")]
                it = emu.u16(cam + 0x35E)
                gain = emu.u8(cam + 0x360)
                print(f"iter {i:2}: IT={it:3} gain={gain:3}  " + " | ".join(h.replace("HW ", "") for h in hw if "8010" not in h)[:200], flush=True)
                with open(os.path.join(out_dir, f"out{i:02}.i420"), "wb") as f:
                    f.write(bytes(emu.uc.mem_read(out, 352 * 288 * 3 // 2)))
            emu.proxy_cmd("Q")
            r = 0
        elif s == "fields":
            for off in (0x20C, 0x210, 0x214, 0x218, 0x21C, 0x224, 0x228, 0x22C, 0x308, 0x30C,
                        0x32C, 0x364, 0x370, 0x844, 0x848):
                emu.log.append(f"cam+0x{off:03X} = 0x{emu.u32(cam + off):08X} ({emu.u32(cam + off)})")
            r = 0
        else:
            raise SystemExit(f"unknown scenario {s}")
        emu.log.append(f"===== {s} returned 0x{r:08X} =====")
    print("\n".join(emu.log))
    out = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--sequence=")), None)
    if out:
        # Machine-readable replay script for tools/EzcamProbe ("replay" command):
        #   W <value> <index> <hex bytes> | R <value> <index> <len> | ALT <n> | SLEEP <ms> | # comment
        with open(out, "w") as f:
            for line in emu.log:
                t = line.split()
                if not t:
                    continue
                if t[0] == "=====":
                    f.write(f"# {' '.join(t[1:-1])}\n")
                elif t[0] in ("WRITE", "READ"):
                    value = {"bridge": 0x0000, "sensor": 0x0044, "eeprom": 0x0050}.get(t[1], None)
                    if value is None:
                        value = int(t[1], 16)
                    index = int(t[2], 16)
                    if t[0] == "WRITE":
                        f.write(f"W 0x{value:04X} 0x{index:04X} {''.join(t[4:])}\n")
                    else:
                        f.write(f"R 0x{value:04X} 0x{index:04X} {t[3].split('=')[1]}\n")
                elif t[0] == "USB" and t[1] == "select":
                    f.write(f"ALT {t[-1].split('=')[1]}\n")
                elif t[0] == "SLEEP":
                    f.write(f"SLEEP {t[1]}\n")
        print(f"replay sequence written to {out}")


if __name__ == "__main__":
    main()
