using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace EzcamProbe;

/// <summary>
/// Assembles frames from the two isochronous pipes. Every packet starts with a 1-byte header:
/// bit 7 = first packet of a frame, bits 0-2 = frame counter. The rest is payload.
/// EP 0x81 carries 176x144 luma (25,344 bytes), EP 0x82 the chroma (12,672 bytes).
/// </summary>
public sealed class FrameAssembler(int frameBytes)
{
    readonly byte[] _buf = new byte[frameBytes];
    int _len = -1;

    /// <summary>Returns a completed frame when <paramref name="packet"/> starts the next one.</summary>
    public byte[]? Push(byte[] packet)
    {
        if (packet.Length == 0) return null;
        byte[]? done = null;
        if ((packet[0] & 0x80) != 0)
        {
            if (_len == _buf.Length) done = (byte[])_buf.Clone();
            _len = 0;
        }
        if (_len < 0) return done;
        int n = Math.Min(packet.Length - 1, _buf.Length - _len);
        if (n > 0) Array.Copy(packet, 1, _buf, _len, n);
        _len += packet.Length - 1;
        return done;
    }
}

/// <summary>
/// Live viewer for testing the camera hardware: grayscale luma at 3x, exposure/gain keys,
/// brightness and noise readouts, snapshot on the camera's button or the S key.
/// </summary>
public sealed class PreviewForm : Form
{
    const int W = 176, H = 144, Zoom = 3, StatusHeight = 46;
    readonly EzCam _cam;
    readonly Bitmap _bmp = new(W, H, PixelFormat.Format32bppRgb);
    readonly System.Windows.Forms.Timer _timer = new() { Interval = 33 };
    readonly CancellationTokenSource _stop = new();
    readonly string _snapDir;
    readonly bool _debug;
    byte[]? _y, _c;
    int _frames, _shownFrames;
    DateTime _fpsStart = DateTime.UtcNow, _lastFrame = DateTime.UtcNow;
    ushort _it = 291;   // where the original driver's auto-exposure settled indoors
    byte _gain = 3;
    string _fps = "", _stats = "", _lastSnap = "";
    int _buttonReads;
    bool _buttonDown;

    public PreviewForm(EzCam cam, string snapDir, bool debug)
    {
        _cam = cam;
        _snapDir = snapDir;
        _debug = debug;
        Text = "EZCam II Viewer";
        ClientSize = new Size(Math.Max(W * Zoom, 640), H * Zoom + StatusHeight);
        DoubleBuffered = true;
        KeyPreview = true;
        KeyDown += OnKey;
        _timer.Tick += (_, _) => Invalidate();
        _timer.Start();
        if (debug)
        {
            var autosave = new System.Windows.Forms.Timer { Interval = 2000 };
            autosave.Tick += (_, _) => Snapshot("latest");
            autosave.Start();
        }
        var stats = new System.Windows.Forms.Timer { Interval = 500 };
        stats.Tick += (_, _) => UpdateStats();
        stats.Start();
        // Snapshot button on the camera: bridge 0xA000 bit 2, active low. Debounced (2 reads).
        var button = new System.Windows.Forms.Timer { Interval = 100 };
        button.Tick += (_, _) =>
        {
            try
            {
                bool pressed = (_cam.Read(EzCam.Bridge, 0xA000) & 0x04) == 0;
                _buttonReads = pressed ? _buttonReads + 1 : 0;
                if (_buttonReads == 2) Snapshot();
                _buttonDown = _buttonReads >= 2;
            }
            catch { }
        };
        button.Start();
        FormClosing += (_, _) => _stop.Cancel();
        StartStreaming();
    }

    void StartStreaming()
    {
        _cam.ResetPipe(0x81);
        _cam.ResetPipe(0x82);
        var ya = new FrameAssembler(W * H);
        var ca = new FrameAssembler(W * H / 2);
        foreach (var (ep, size, asm) in new[] { ((byte)0x81, 546, ya), ((byte)0x82, 273, ca) })
        {
            var reader = new IsoReader(_cam.WinUsbHandle, ep, size);
            new Thread(() =>
            {
                reader.Run(p =>
                {
                    var f = asm.Push(p.Data);
                    if (f == null) return;
                    if (ep == 0x81)
                    {
                        _y = f;
                        _lastFrame = DateTime.UtcNow;
                        Interlocked.Increment(ref _frames);
                    }
                    else _c = f;
                }, _stop.Token);
                reader.Dispose();
            }) { IsBackground = true }.Start();
        }
    }

    /// <summary>
    /// Brightness = mean luma (16 = black, 235 = white). Row noise = spread of the per-row averages,
    /// i.e. how strong the horizontal streaks are; a healthy sensor on a still scene stays low.
    /// Column noise = spread of the per-column averages (vertical bands + real scene detail).
    /// </summary>
    void UpdateStats()
    {
        var y = _y;
        if (y == null) return;
        Span<double> rows = stackalloc double[H];
        Span<double> cols = stackalloc double[W];
        double sum = 0;
        for (int r = 0; r < H; r++)
            for (int x = 0; x < W; x++)
            {
                byte v = y[r * W + x];
                rows[r] += v; cols[x] += v; sum += v;
            }
        double mean = sum / (W * H);
        static double Spread(Span<double> s, int n, double mean)
        {
            double acc = 0;
            foreach (var v in s) acc += (v / n - mean) * (v / n - mean);
            return Math.Sqrt(acc / s.Length);
        }
        _stats = $"brightness {mean:0}   row noise {Spread(rows, W, mean):0.0}   column noise {Spread(cols, H, mean):0.0}";
    }

    void SetExposure()
    {
        // sensor reg 0 = IT low 8 bits, reg 1 bit 0 = IT bit 8; reg 8 = gain, bit 7 = apply strobe
        try
        {
            _cam.Write(EzCam.Sensor, 0x00, (byte)(_it & 0xFF));
            _cam.Write(EzCam.Sensor, 0x01, (byte)((_it >> 8) & 1));
            _cam.Write(EzCam.Sensor, 0x08, (byte)(_gain | 0x80));
            _cam.Write(EzCam.Sensor, 0x08, _gain);
        }
        catch { }
    }

    void OnKey(object? sender, KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Up: _it = (ushort)Math.Min(511, _it + (e.Shift ? 50 : 5)); SetExposure(); break;
            case Keys.Down: _it = (ushort)Math.Max(1, _it - (e.Shift ? 50 : 5)); SetExposure(); break;
            case Keys.Right: _gain = (byte)Math.Min(127, _gain + (e.Shift ? 16 : 1)); SetExposure(); break;
            case Keys.Left: _gain = (byte)Math.Max(1, _gain - (e.Shift ? 16 : 1)); SetExposure(); break;
            case Keys.R: _it = 291; _gain = 3; SetExposure(); break;
            case Keys.S: Snapshot(); break;
            case Keys.Escape: Close(); break;
        }
    }

    void Snapshot(string? name = null)
    {
        var y = _y;
        if (y == null) return;
        try
        {
            Directory.CreateDirectory(_snapDir);
            string stamp = name ?? DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
            // Build the image from the frame itself: the on-screen bitmap is only refreshed when
            // the window paints, which doesn't happen while it's minimized.
            using (var small = new Bitmap(W, H, PixelFormat.Format32bppRgb))
            {
                Fill(small, y);
                using var big = new Bitmap(W * Zoom, H * Zoom, PixelFormat.Format32bppRgb);
                using (var g = Graphics.FromImage(big))
                {
                    g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
                    g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.Half;
                    g.DrawImage(small, 0, 0, W * Zoom, H * Zoom);
                }
                big.Save(Path.Combine(_snapDir, $"ezcam-{stamp}.png"), ImageFormat.Png);
            }
            if (_debug)
            {
                File.WriteAllBytes(Path.Combine(_snapDir, $"ezcam-{stamp}.y"), y);
                if (_c != null) File.WriteAllBytes(Path.Combine(_snapDir, $"ezcam-{stamp}.c"), _c);
            }
            if (name == null) _lastSnap = $"saved ezcam-{stamp}.png";
        }
        catch (Exception ex) { _lastSnap = $"snapshot failed: {ex.Message}"; }
    }

    static unsafe void Fill(Bitmap bmp, byte[] y)
    {
        var data = bmp.LockBits(new Rectangle(0, 0, W, H), ImageLockMode.WriteOnly, PixelFormat.Format32bppRgb);
        for (int row = 0; row < H; row++)
        {
            uint* dst = (uint*)((byte*)data.Scan0 + row * data.Stride);
            for (int x = 0; x < W; x++)
            {
                uint v = y[row * W + x];
                dst[x] = 0xFF000000 | (v << 16) | (v << 8) | v;
            }
        }
        bmp.UnlockBits(data);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var y = _y;
        if (y != null) Fill(_bmp, y);
        e.Graphics.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
        e.Graphics.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.Half;
        e.Graphics.DrawImage(_bmp, 0, 0, W * Zoom, H * Zoom);
        if ((DateTime.UtcNow - _fpsStart).TotalSeconds >= 1)
        {
            _fps = $"{(_frames - _shownFrames) / (DateTime.UtcNow - _fpsStart).TotalSeconds:0.0} fps";
            _shownFrames = _frames;
            _fpsStart = DateTime.UtcNow;
        }
        bool stalled = (DateTime.UtcNow - _lastFrame).TotalSeconds > 3;
        string line1 = stalled
            ? "NO FRAMES - camera unplugged or stuck. Close this window, unplug/replug the camera, reopen."
            : $"{_fps}   {_stats}   button: {(_buttonDown ? "PRESSED" : "up")}   {_lastSnap}";
        string line2 = $"exposure {_it} (Up/Down, Shift = faster)   gain {_gain} (Left/Right)   R = reset   S = snapshot   Esc = quit";
        TextRenderer.DrawText(e.Graphics, line1, Font, new Point(4, H * Zoom + 4), stalled ? Color.Red : Color.Black);
        TextRenderer.DrawText(e.Graphics, line2, Font, new Point(4, H * Zoom + 24), Color.DimGray);
    }
}
