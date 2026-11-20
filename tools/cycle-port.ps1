# Re-enumerates the EZCam II by asking its parent hub to cycle the port (IOCTL_USB_HUB_CYCLE_PORT),
# the software equivalent of unplugging and replugging it. The WinUSB binding survives because
# the device comes back on the same port with the same instance ID.
# Use this when the camera stops answering control requests. May require an elevated prompt.
param(
  [string]$VendorId = '0572',
  [string]$ProductId = '0002'
)
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class HubCycle {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuf, int inLen, byte[] outBuf, int outLen, out int ret, IntPtr ov);
  public static void Cycle(string hubPath, int port) {
    using (var h = CreateFile(hubPath, 0x40000000, 2, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
      if (h.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "open hub");
      byte[] buf = new byte[8];
      BitConverter.GetBytes(port).CopyTo(buf, 0);
      int ret;
      // IOCTL_USB_HUB_CYCLE_PORT
      if (!DeviceIoControl(h, 0x220444, buf, 8, buf, 8, out ret, IntPtr.Zero))
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "IOCTL_USB_HUB_CYCLE_PORT");
    }
  }
}
'@
$dev = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "USB\VID_$VendorId&PID_$ProductId\*" } | Select-Object -First 1
if (-not $dev) { throw "Camera not present." }
$hub  = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_Parent).Data
$loc  = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_LocationInfo).Data
$port = [int]([regex]::Match($loc, 'Port_#(\d+)').Groups[1].Value)
$hubPath = '\\?\' + ($hub -replace '\\','#') + '#{f18a0e88-c30c-11d0-8815-00a0c906bed8}'
"Cycling port $port on $hub"
[HubCycle]::Cycle($hubPath, $port)
Start-Sleep -Seconds 3
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "USB\VID_$VendorId&PID_$ProductId\*" } | Select-Object Status, Class, FriendlyName, InstanceId | Format-List
