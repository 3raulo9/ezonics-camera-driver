using System.ComponentModel;
using System.Runtime.InteropServices;

namespace EzcamProbe;

/// <summary>One received isochronous packet.</summary>
public readonly record struct IsoPacket(byte Endpoint, uint Transfer, ushort Index, int Status, byte[] Data);

/// <summary>
/// Continuous isochronous IN reader for one pipe using the WinUSB isoch API (Windows 8.1+).
/// Keeps <see cref="Depth"/> transfers of <see cref="PacketsPerTransfer"/> packets in flight.
/// </summary>
public sealed unsafe class IsoReader : IDisposable
{
    const int ERROR_IO_PENDING = 997;
    public const int PacketsPerTransfer = 32;
    public const int Depth = 6;

    readonly IntPtr _usb;
    readonly byte _ep;
    readonly int _maxPacket;
    readonly int _transferBytes;
    readonly byte* _buffer;
    readonly IsoNative.USBD_ISO_PACKET_DESCRIPTOR* _descs;
    readonly NativeOverlapped* _ovl;
    readonly EventWaitHandle[] _events;
    IntPtr _isoHandle;

    public IsoReader(IntPtr usb, byte endpoint, int maxPacket)
    {
        _usb = usb;
        _ep = endpoint;
        _maxPacket = maxPacket;
        _transferBytes = maxPacket * PacketsPerTransfer;
        _buffer = (byte*)NativeMemory.AllocZeroed((nuint)(_transferBytes * Depth));
        _descs = (IsoNative.USBD_ISO_PACKET_DESCRIPTOR*)NativeMemory.AllocZeroed(
            (nuint)(sizeof(IsoNative.USBD_ISO_PACKET_DESCRIPTOR) * PacketsPerTransfer * Depth));
        _ovl = (NativeOverlapped*)NativeMemory.AllocZeroed((nuint)(sizeof(NativeOverlapped) * Depth));
        _events = new EventWaitHandle[Depth];
        for (int i = 0; i < Depth; i++)
        {
            _events[i] = new ManualResetEvent(false);
            _ovl[i].EventHandle = _events[i].SafeWaitHandle.DangerousGetHandle();
        }
        if (!IsoNative.WinUsb_RegisterIsochBuffer(usb, endpoint, (IntPtr)_buffer, (uint)(_transferBytes * Depth), out _isoHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinUsb_RegisterIsochBuffer(0x{endpoint:X2})");
    }

    void Submit(int slot, bool continueStream)
    {
        _events[slot].Reset();
        _ovl[slot].InternalLow = IntPtr.Zero;
        _ovl[slot].InternalHigh = IntPtr.Zero;
        if (!IsoNative.WinUsb_ReadIsochPipeAsap(_isoHandle, (uint)(slot * _transferBytes), (uint)_transferBytes,
                continueStream, PacketsPerTransfer, _descs + slot * PacketsPerTransfer, &_ovl[slot]))
        {
            int err = Marshal.GetLastWin32Error();
            if (err != ERROR_IO_PENDING)
                throw new Win32Exception(err, $"WinUsb_ReadIsochPipeAsap(0x{_ep:X2})");
        }
    }

    /// <summary>Reads until <paramref name="stop"/> is cancelled, calling <paramref name="sink"/> per packet.</summary>
    public void Run(Action<IsoPacket> sink, CancellationToken stop, Action<string>? log = null)
    {
        for (int i = 0; i < Depth; i++) Submit(i, continueStream: i > 0);
        uint transfer = 0;
        int slot = 0;
        while (!stop.IsCancellationRequested)
        {
            bool ok = IsoNative.WinUsb_GetOverlappedResult(_usb, &_ovl[slot], out uint _, true);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                log?.Invoke($"ep 0x{_ep:X2} transfer {transfer} failed: {new Win32Exception(err).Message} ({err})");
            }
            var d = _descs + slot * PacketsPerTransfer;
            // Packet offsets are relative to the start of this transfer, not of the registered buffer.
            byte* transferBase = _buffer + slot * _transferBytes;
            for (int p = 0; p < PacketsPerTransfer; p++)
            {
                int len = (int)d[p].Length;
                var data = new byte[len];
                if (len > 0)
                    new ReadOnlySpan<byte>(transferBase + d[p].Offset, len).CopyTo(data);
                sink(new IsoPacket(_ep, transfer, (ushort)p, d[p].Status, data));
            }
            transfer++;
            try { Submit(slot, continueStream: ok); }
            catch (Win32Exception e)
            {
                log?.Invoke($"ep 0x{_ep:X2} resubmit: {e.Message}; restarting stream");
                Submit(slot, continueStream: false);
            }
            slot = (slot + 1) % Depth;
        }
        IsoNative.WinUsb_AbortPipe(_usb, _ep);
        for (int i = 0; i < Depth; i++)
            IsoNative.WinUsb_GetOverlappedResult(_usb, &_ovl[i], out uint _, true);
    }

    public void Dispose()
    {
        if (_isoHandle != IntPtr.Zero) IsoNative.WinUsb_UnregisterIsochBuffer(_isoHandle);
        foreach (var e in _events) e.Dispose();
        NativeMemory.Free(_buffer);
        NativeMemory.Free(_descs);
        NativeMemory.Free(_ovl);
    }
}

static unsafe class IsoNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct USBD_ISO_PACKET_DESCRIPTOR
    {
        public uint Offset;
        public uint Length;
        public int Status;
    }

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_RegisterIsochBuffer(IntPtr iface, byte pipeId, IntPtr buffer, uint length, out IntPtr isoHandle);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_UnregisterIsochBuffer(IntPtr isoHandle);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_ReadIsochPipeAsap(IntPtr isoHandle, uint offset, uint length, bool continueStream,
        uint numberOfPackets, USBD_ISO_PACKET_DESCRIPTOR* packets, NativeOverlapped* overlapped);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_GetOverlappedResult(IntPtr iface, NativeOverlapped* overlapped, out uint transferred, bool wait);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_AbortPipe(IntPtr iface, byte pipeId);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_ResetPipe(IntPtr iface, byte pipeId);

    [DllImport("winusb.dll", SetLastError = true)]
    public static extern bool WinUsb_SetCurrentAlternateSetting(IntPtr iface, byte setting);
}
