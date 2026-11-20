# Dumps the USB device + configuration descriptors of the EZCam II straight from its parent hub.
# Works even when the camera has no driver installed (Device Manager error code 28).
#
# Usage: powershell -ExecutionPolicy Bypass -File tools\dump-desc.ps1 [-VendorId 0572] [-ProductId 0002]
param(
  [string]$VendorId = '0572',
  [string]$ProductId = '0002'
)
$src = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class UsbDesc {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuf, int inLen, byte[] outBuf, int outLen, out int ret, IntPtr ov);
  // IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION
  public static byte[] Get(string hubPath, int port, byte type, byte index, ushort langId, int len) {
    using (var h = CreateFile(hubPath, 0x40000000, 2, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
      if (h.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
      byte[] buf = new byte[12 + len];
      BitConverter.GetBytes(port).CopyTo(buf, 0);
      buf[4] = 0x80; buf[5] = 6; buf[6] = index; buf[7] = type;
      BitConverter.GetBytes(langId).CopyTo(buf, 8);
      BitConverter.GetBytes((ushort)len).CopyTo(buf, 10);
      int ret;
      if (!DeviceIoControl(h, 0x220410, buf, buf.Length, buf, buf.Length, out ret, IntPtr.Zero))
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
      byte[] o = new byte[ret - 12]; Array.Copy(buf, 12, o, 0, o.Length); return o;
    }
  }
}
'@
Add-Type -TypeDefinition $src

$dev = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "USB\VID_$VendorId&PID_$ProductId\*" } | Select-Object -First 1
if (-not $dev) { throw "No present USB device VID_$VendorId&PID_$ProductId found." }
$hub  = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_Parent).Data
$loc  = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_LocationInfo).Data
$Port = [int]([regex]::Match($loc, 'Port_#(\d+)').Groups[1].Value)
"Device: $($dev.InstanceId)  status=$($dev.Status)  hub=$hub  port=$Port"
$hubPath = '\\?\' + ($hub -replace '\\','#') + '#{f18a0e88-c30c-11d0-8815-00a0c906bed8}'

function Hex($b) { ($b | ForEach-Object { $_.ToString('X2') }) -join ' ' }
function Str($idx) {
  if ($idx -eq 0) { return '' }
  try { $s = [UsbDesc]::Get($hubPath, $Port, 3, $idx, 0x0409, 255); [Text.Encoding]::Unicode.GetString($s, 2, $s[0]-2) } catch { "<err: $($_.Exception.Message)>" }
}

$d = [UsbDesc]::Get($hubPath, $Port, 1, 0, 0, 18)
"DEVICE  raw: $(Hex $d)"
"  bcdUSB={0:X4} class={1:X2}/{2:X2}/{3:X2} maxPkt0={4} VID={5:X4} PID={6:X4} bcdDevice={7:X4} numConfigs={8}" -f `
  ([BitConverter]::ToUInt16($d,2)), $d[4], $d[5], $d[6], $d[7], ([BitConverter]::ToUInt16($d,8)), ([BitConverter]::ToUInt16($d,10)), ([BitConverter]::ToUInt16($d,12)), $d[17]
"  Manufacturer='$(Str $d[14])' Product='$(Str $d[15])' Serial='$(Str $d[16])'"

for ($ci = 0; $ci -lt $d[17]; $ci++) {
  $hdr = [UsbDesc]::Get($hubPath, $Port, 2, $ci, 0, 9)
  $total = [BitConverter]::ToUInt16($hdr, 2)
  $c = [UsbDesc]::Get($hubPath, $Port, 2, $ci, 0, $total)
  "CONFIG[$ci] total=$total raw:"
  for ($o = 0; $o -lt $c.Length; $o += 16) { "  " + (Hex $c[$o..([Math]::Min($c.Length,$o+16)-1)]) }
  $o = 0
  while ($o -lt $c.Length -and $c[$o] -gt 0) {
    $len = $c[$o]; $type = $c[$o+1]
    switch ($type) {
      2 { "  CFG  value={0} numIf={1} attr={2:X2} maxPower={3}mA name='{4}'" -f $c[$o+5], $c[$o+4], $c[$o+7], ($c[$o+8]*2), (Str $c[$o+6]) }
      4 { "  IF   num={0} alt={1} numEp={2} class={3:X2}/{4:X2}/{5:X2} name='{6}'" -f $c[$o+2], $c[$o+3], $c[$o+4], $c[$o+5], $c[$o+6], $c[$o+7], (Str $c[$o+8]) }
      5 { $attr = $c[$o+3]; $tt = @('Control','Isoch','Bulk','Interrupt')[$attr -band 3]
          $mps = [BitConverter]::ToUInt16($c, $o+4)
          "    EP addr={0:X2} ({1}) {2} maxPkt={3} (x{4}) interval={5}" -f $c[$o+2], $(if ($c[$o+2] -band 0x80) {'IN'} else {'OUT'}), $tt, ($mps -band 0x7FF), ((($mps -shr 11) -band 3)+1), $c[$o+6] }
      default { "  desc type={0:X2} len={1}: {2}" -f $type, $len, (Hex $c[$o..($o+$len-1)]) }
    }
    $o += $len
  }
}
