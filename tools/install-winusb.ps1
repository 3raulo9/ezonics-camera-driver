# Binds Microsoft's in-box, Microsoft-signed WinUSB driver (C:\Windows\INF\winusb.inf, model
# "WinUsb Device") to the EZCam II. This is the scripted equivalent of Device Manager ->
# Update driver -> Browse -> Let me pick -> Universal Serial Bus devices -> WinUsb Device.
# No custom INF, no self-signed certificates, no test mode.
#
# Must run elevated:  powershell -ExecutionPolicy Bypass -File tools\install-winusb.ps1
# Undo with:          tools\uninstall-winusb.ps1
param(
  [string]$VendorId = '0572',
  [string]$ProductId = '0002',
  [string]$LogPath
)
if ($LogPath) { Start-Transcript -Path $LogPath -Force | Out-Null }
try {
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin) { throw 'Run this script as Administrator.' }

  $dev = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "USB\VID_$VendorId&PID_$ProductId\*" } | Select-Object -First 1
  if (-not $dev) { throw "Camera USB\VID_$VendorId&PID_$ProductId is not plugged in." }
  "Device: $($dev.InstanceId) (status $($dev.Status), class '$($dev.Class)')"

  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WinUsbBinder {
  const uint DI_ENUMSINGLEINF = 0x00010000;
  const uint DI_FLAGSEX_ALLOWEXCLUDEDDRVS = 0x00000800;
  const uint SPDIT_CLASSDRIVER = 1;
  const uint SPDRP_CLASSGUID = 0x08;

  [StructLayout(LayoutKind.Sequential)]
  public struct SP_DEVINFO_DATA { public uint cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct SP_DEVINSTALL_PARAMS {
    public uint cbSize, Flags, FlagsEx; public IntPtr hwndParent, InstallMsgHandler, InstallMsgHandlerContext, FileQueue, ClassInstallReserved;
    public uint Reserved; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DriverPath;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct SP_DRVINFO_DATA {
    public uint cbSize, DriverType; public IntPtr Reserved;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Description;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string MfgName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProviderName;
    public System.Runtime.InteropServices.ComTypes.FILETIME DriverDate; public ulong DriverVersion;
  }

  [DllImport("setupapi.dll", SetLastError = true)] static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr cls, IntPtr hwnd);
  [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiOpenDeviceInfoW(IntPtr set, string id, IntPtr hwnd, uint flags, ref SP_DEVINFO_DATA did);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr set, ref SP_DEVINFO_DATA did, uint prop, byte[] buf, uint size);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiGetDeviceInstallParamsW(IntPtr set, ref SP_DEVINFO_DATA did, ref SP_DEVINSTALL_PARAMS p);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiSetDeviceInstallParamsW(IntPtr set, ref SP_DEVINFO_DATA did, ref SP_DEVINSTALL_PARAMS p);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiBuildDriverInfoList(IntPtr set, ref SP_DEVINFO_DATA did, uint type);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiEnumDriverInfoW(IntPtr set, ref SP_DEVINFO_DATA did, uint type, uint idx, ref SP_DRVINFO_DATA drv);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiSetSelectedDriverW(IntPtr set, ref SP_DEVINFO_DATA did, ref SP_DRVINFO_DATA drv);
  [DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool DiInstallDevice(IntPtr hwnd, IntPtr set, ref SP_DEVINFO_DATA did, ref SP_DRVINFO_DATA drv, uint flags, out bool reboot);

  static void Ok(bool ok, string what) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), what + " failed"); }

  public static string Bind(string instanceId, string infPath, string classGuid, string modelDescription) {
    IntPtr set = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
    if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCreateDeviceInfoList");
    try {
      var did = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA)) };
      Ok(SetupDiOpenDeviceInfoW(set, instanceId, IntPtr.Zero, 0, ref did), "SetupDiOpenDeviceInfo");

      // Put the device in the USBDevice setup class, like picking "Universal Serial Bus devices".
      byte[] g = System.Text.Encoding.Unicode.GetBytes(classGuid + "\0");
      Ok(SetupDiSetDeviceRegistryPropertyW(set, ref did, SPDRP_CLASSGUID, g, (uint)g.Length), "Set class GUID");

      // Only look at the in-box winusb.inf.
      var p = new SP_DEVINSTALL_PARAMS { cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINSTALL_PARAMS)) };
      Ok(SetupDiGetDeviceInstallParamsW(set, ref did, ref p), "SetupDiGetDeviceInstallParams");
      p.Flags |= DI_ENUMSINGLEINF; p.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS; p.DriverPath = infPath;
      Ok(SetupDiSetDeviceInstallParamsW(set, ref did, ref p), "SetupDiSetDeviceInstallParams");
      Ok(SetupDiBuildDriverInfoList(set, ref did, SPDIT_CLASSDRIVER), "SetupDiBuildDriverInfoList");

      string seen = "";
      for (uint i = 0; ; i++) {
        var drv = new SP_DRVINFO_DATA { cbSize = (uint)Marshal.SizeOf(typeof(SP_DRVINFO_DATA)) };
        if (!SetupDiEnumDriverInfoW(set, ref did, SPDIT_CLASSDRIVER, i, ref drv)) break;
        seen += "  [" + i + "] " + drv.Description + " (" + drv.MfgName + ")\n";
        if (!string.Equals(drv.Description, modelDescription, StringComparison.OrdinalIgnoreCase)) continue;
        Ok(SetupDiSetSelectedDriverW(set, ref did, ref drv), "SetupDiSetSelectedDriver");
        bool reboot;
        Ok(DiInstallDevice(IntPtr.Zero, set, ref did, ref drv, 0, out reboot), "DiInstallDevice");
        return seen + "Installed '" + drv.Description + "'" + (reboot ? " (reboot required)" : "");
      }
      throw new InvalidOperationException("Model '" + modelDescription + "' not found in " + infPath + ". Drivers seen:\n" + seen);
    } finally { SetupDiDestroyDeviceInfoList(set); }
  }
}
'@
  [WinUsbBinder]::Bind($dev.InstanceId, "$env:windir\INF\winusb.inf", '{88BAE032-5A81-49F0-BC3D-A4FF138216D6}', 'WinUsb Device')
  Start-Sleep -Seconds 2
  Get-PnpDevice -InstanceId $dev.InstanceId | Select-Object Status, Class, FriendlyName, InstanceId | Format-List
  'Service: ' + (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_Service).Data
}
catch { "ERROR: $($_.Exception.Message)"; exit 1 }
finally { if ($LogPath) { Stop-Transcript | Out-Null } }
