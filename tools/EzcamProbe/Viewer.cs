using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace EzcamProbe;

/// <summary>End-user entry point: make sure the camera is set up, then open the live viewer.</summary>
static class Viewer
{
    const string Title = "EZCam II Viewer";

    public static int Run(string sequence, string snapshotDir)
    {
        Application.EnableVisualStyles();
        if (!File.Exists(sequence))
            return Fail($"Missing camera setup file:\n{sequence}");

        if (EzCam.FindDevicePath() == null)
        {
            if (!IsPluggedIn())
                return Fail("The camera isn't plugged in.\n\nPlug in the EZCam II and open the viewer again.");
            // Plugged in but not bound to WinUSB (e.g. moved to another USB port).
            var answer = MessageBox.Show(
                "The camera needs a one-time setup on this USB port.\n\n" +
                "Windows will ask for administrator permission to attach Microsoft's WinUSB driver to it. Continue?",
                Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (answer != DialogResult.Yes) return 1;
            string script = Path.Combine(AppContext.BaseDirectory, "install-winusb.ps1");
            try
            {
                using var p = Process.Start(new ProcessStartInfo("powershell.exe",
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"")
                { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden });
                p?.WaitForExit();
            }
            catch (Exception e) { return Fail($"Setup was cancelled or failed:\n{e.Message}"); }
            for (int i = 0; i < 50 && EzCam.FindDevicePath() == null; i++) Thread.Sleep(200);
            if (EzCam.FindDevicePath() == null)
                return Fail("Setup didn't finish. Unplug and replug the camera, then open the viewer again.");
        }

        try
        {
            using var cam = EzCam.Open();
            try { cam.Replay(sequence); }
            catch (Exception e)
            {
                return Fail("The camera is connected but isn't responding.\n\n" +
                            "Unplug it, wait 5 seconds, plug it back in and open the viewer again.\n\n(" + e.Message + ")");
            }
            var ui = new Thread(() => Application.Run(new PreviewForm(cam, snapshotDir, debug: false)));
            ui.SetApartmentState(ApartmentState.STA);
            ui.Start();
            ui.Join();
            try { cam.SetAltSetting(0); } catch { }
            return 0;
        }
        catch (Exception e) { return Fail($"Couldn't open the camera:\n{e.Message}"); }
    }

    static int Fail(string message)
    {
        MessageBox.Show(message, Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return 2;
    }

    /// <summary>True if a USB device VID_0572&PID_0002 is present, with or without a driver.</summary>
    static bool IsPluggedIn()
    {
        const uint CM_GETIDLIST_FILTER_ENUMERATOR = 0x1, CM_GETIDLIST_FILTER_PRESENT = 0x100;
        uint flags = CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT;
        if (CM_Get_Device_ID_List_SizeW(out uint len, "USB", flags) != 0) return false;
        var buf = new char[len];
        if (CM_Get_Device_ID_ListW("USB", buf, len, flags) != 0) return false;
        return new string(buf).Contains($"VID_{EzCam.Vid:X4}&PID_{EzCam.Pid:X4}", StringComparison.OrdinalIgnoreCase);
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern uint CM_Get_Device_ID_List_SizeW(out uint len, string filter, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern uint CM_Get_Device_ID_ListW(string filter, [Out] char[] buffer, uint len, uint flags);
}
