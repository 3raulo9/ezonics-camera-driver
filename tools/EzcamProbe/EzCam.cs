using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EzcamProbe;

/// <summary>
/// User-mode access to the Ezonics EZCam II (Conexant CN0352, USB VID 0572 PID 0002) through
/// Microsoft's in-box WinUSB driver.
///
/// Register protocol (recovered from the original usbcone.sys, see docs/FINDINGS.md):
///   every access is a vendor control transfer with bRequest = 0, wLength = 1
///   wValue = 0x0000  -> bridge-chip register, wIndex = register address (e.g. 0xE000)
///   wValue = 0x0044  -> I2C device 0x44 (image sensor), wIndex = sensor register
///   wValue = 0x0050  -> I2C device 0x50 (24Cxx EEPROM), wIndex = EEPROM offset
///   bmRequestType = 0xC0 for reads, 0x40 for writes
/// </summary>
public sealed class EzCam : IDisposable
{
    public const ushort Vid = 0x0572, Pid = 0x0002;
    public const ushort Bridge = 0x0000, Sensor = 0x0044, Eeprom = 0x0050;

    readonly SafeFileHandle _file;
    readonly IntPtr _usb;

    EzCam(SafeFileHandle file, IntPtr usb) { _file = file; _usb = usb; }

    public static string? FindDevicePath()
    {
        var guid = Native.GUID_DEVINTERFACE_USB_DEVICE;
        Native.Check(Native.CM_Get_Device_Interface_List_SizeW(out uint len, ref guid, null, 0));
        var buf = new char[len];
        Native.Check(Native.CM_Get_Device_Interface_ListW(ref guid, null, buf, len, 0));
        string want = $"vid_{Vid:x4}&pid_{Pid:x4}";
        return new string(buf).Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(p => p.Contains(want, StringComparison.OrdinalIgnoreCase));
    }

    public static EzCam Open()
    {
        string path = FindDevicePath() ?? throw new InvalidOperationException(
            $"No USB device VID_{Vid:X4}&PID_{Pid:X4} is plugged in.");
        var file = Native.CreateFile(path, Native.GENERIC_READ | Native.GENERIC_WRITE,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_ATTRIBUTE_NORMAL | Native.FILE_FLAG_OVERLAPPED, IntPtr.Zero);
        if (file.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateFile({path}) failed");
        if (!Native.WinUsb_Initialize(file, out IntPtr usb))
        {
            int err = Marshal.GetLastWin32Error();
            file.Dispose();
            throw new Win32Exception(err,
                "WinUsb_Initialize failed - is the camera bound to WinUSB? (see README, step 1)");
        }
        // Control requests to an unresponsive I2C target otherwise wait for a long time.
        uint timeoutMs = 1000;
        Native.WinUsb_SetPipePolicy(usb, 0x00, Native.PIPE_TRANSFER_TIMEOUT, 4, ref timeoutMs);
        return new EzCam(file, usb);
    }

    /// <summary>Raw vendor control transfer. Returns the bytes actually transferred.</summary>
    public byte[] Control(bool read, ushort value, ushort index, byte[]? data = null, int length = 1)
    {
        var setup = new Native.WINUSB_SETUP_PACKET
        {
            RequestType = (byte)(read ? 0xC0 : 0x40),
            Request = 0,
            Value = value,
            Index = index,
            Length = (ushort)(read ? length : data!.Length),
        };
        byte[] buf = read ? new byte[length] : data!;
        if (!Native.WinUsb_ControlTransfer(_usb, setup, buf, (uint)buf.Length, out uint done, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"{(read ? "read" : "write")} value=0x{value:X4} index=0x{index:X4} failed");
        return buf[..(int)done];
    }

    public byte Read(ushort target, ushort reg)
    {
        // Reading the sensor (I2C 0x44) hangs the bridge's I2C engine and leaves the I2C bus stuck;
        // the camera then fails even USB enumeration until it is power-cycled (unplugged).
        // The original driver only ever writes the sensor.
        if (target == Sensor)
            throw new InvalidOperationException("sensor reads are blocked: they lock up the camera until it is unplugged");
        return Control(true, target, reg) is { Length: > 0 } b ? b[0] : throw new IOException($"short read at 0x{reg:X4}");
    }

    public void Write(ushort target, ushort reg, byte val)
    {
        if (target == Eeprom)
            throw new InvalidOperationException("EEPROM writes are disabled: it holds the camera's calibration.");
        Control(false, target, reg, [val]);
    }

    public byte[] GetDescriptor(byte type, byte index, int length)
    {
        var buf = new byte[length];
        if (!Native.WinUsb_GetDescriptor(_usb, type, index, 0, buf, (uint)length, out uint done))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WinUsb_GetDescriptor failed");
        return buf[..(int)done];
    }

    public IntPtr WinUsbHandle => _usb;

    public void SetAltSetting(byte alt)
    {
        if (!IsoNative.WinUsb_SetCurrentAlternateSetting(_usb, alt))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinUsb_SetCurrentAlternateSetting({alt})");
    }

    public void ResetPipe(byte ep)
    {
        if (!IsoNative.WinUsb_ResetPipe(_usb, ep))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinUsb_ResetPipe(0x{ep:X2})");
    }

    /// <summary>
    /// Runs a replay script produced by re/emu.py --sequence:
    ///   W &lt;value&gt; &lt;index&gt; &lt;hex bytes&gt; | R &lt;value&gt; &lt;index&gt; &lt;len&gt; | ALT &lt;n&gt; | SLEEP &lt;ms&gt; | # comment
    /// EEPROM writes are refused by <see cref="Control"/>'s caller rules.
    /// </summary>
    public void Replay(string path, Action<string>? log = null)
    {
        foreach (var raw in File.ReadLines(path))
        {
            var t = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (t.Length == 0 || t[0].StartsWith('#')) continue;
            switch (t[0])
            {
                case "W":
                    ushort value = Convert.ToUInt16(t[1], 16), index = Convert.ToUInt16(t[2], 16);
                    if (value == Eeprom) throw new InvalidOperationException("replay script tries to write the EEPROM");
                    Control(false, value, index, Convert.FromHexString(t[3]));
                    break;
                case "R":
                    var got = Control(true, Convert.ToUInt16(t[1], 16), Convert.ToUInt16(t[2], 16), length: int.Parse(t[3]));
                    log?.Invoke($"R {t[1]} {t[2]} -> {Convert.ToHexString(got)}");
                    break;
                case "ALT":
                    SetAltSetting(byte.Parse(t[1]));
                    log?.Invoke($"alternate setting {t[1]}");
                    break;
                case "SLEEP":
                    Thread.Sleep((int)Math.Ceiling(double.Parse(t[1], System.Globalization.CultureInfo.InvariantCulture)));
                    break;
                default:
                    throw new FormatException($"bad replay line: {raw}");
            }
        }
    }

    public byte CurrentAltSetting()
    {
        if (!Native.WinUsb_GetCurrentAlternateSetting(_usb, out byte alt))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WinUsb_GetCurrentAlternateSetting failed");
        return alt;
    }

    public void Dispose()
    {
        if (_usb != IntPtr.Zero) Native.WinUsb_Free(_usb);
        _file.Dispose();
    }
}

static class Native
{
    public static Guid GUID_DEVINTERFACE_USB_DEVICE = new("A5DCBF10-6530-11D2-901F-00C04FB951ED");
    public const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80, FILE_FLAG_OVERLAPPED = 0x40000000;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct WINUSB_SETUP_PACKET
    {
        public byte RequestType, Request;
        public ushort Value, Index, Length;
    }

    public static void Check(uint cr)
    {
        if (cr != 0) throw new InvalidOperationException($"Configuration Manager error CR=0x{cr:X}");
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern uint CM_Get_Device_Interface_List_SizeW(out uint len, ref Guid cls, string? deviceId, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern uint CM_Get_Device_Interface_ListW(ref Guid cls, string? deviceId, [Out] char[] buffer, uint len, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_Initialize(SafeFileHandle device, out IntPtr iface);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_Free(IntPtr iface);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_ControlTransfer(IntPtr iface, WINUSB_SETUP_PACKET setup, byte[] buffer, uint length, out uint transferred, IntPtr overlapped);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_GetDescriptor(IntPtr iface, byte type, byte index, ushort langId, byte[] buffer, uint length, out uint transferred);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_GetCurrentAlternateSetting(IntPtr iface, out byte alt);

    public const uint PIPE_TRANSFER_TIMEOUT = 0x03;

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_SetPipePolicy(IntPtr iface, byte pipeId, uint policyType, uint valueLength, ref uint value);
}
