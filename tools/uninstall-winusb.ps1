# Undoes install-winusb.ps1: removes the camera's device node so Windows re-detects it with no
# driver (back to Device Manager error code 28). Must run elevated.
param(
  [string]$VendorId = '0572',
  [string]$ProductId = '0002'
)
$dev = Get-PnpDevice | Where-Object { $_.InstanceId -like "USB\VID_$VendorId&PID_$ProductId\*" }
foreach ($d in $dev) {
  "Removing $($d.InstanceId)"
  pnputil /remove-device "$($d.InstanceId)"
}
pnputil /scan-devices
