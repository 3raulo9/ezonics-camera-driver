using System.Windows.Forms;
using System.Globalization;
using EzcamProbe;

// Bridge registers the original driver touches during initialization (docs/FINDINGS.md).
ushort[] knownBridgeRegs = [0xE000, 0xE001, 0xE002, 0xA000, 0xB000, 0xC001, 0xC002, 0xC003, 0xC004, 0x1000, 0x2000, 0x9000];

string cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
try
{
    switch (cmd)
    {
        case "find":
            Console.WriteLine(EzCam.FindDevicePath() ?? "camera not found");
            return 0;

        case "info":
            using (var cam = EzCam.Open())
            {
                Console.WriteLine("Device descriptor: " + Hex(cam.GetDescriptor(1, 0, 18)));
                Console.WriteLine("Config descriptor: " + Hex(cam.GetDescriptor(2, 0, 101)));
                Console.WriteLine($"Current alternate setting: {cam.CurrentAltSetting()}");
            }
            return 0;

        case "regs": // read-only sweep of the bridge registers the driver uses
            using (var cam = EzCam.Open())
                foreach (var r in knownBridgeRegs)
                    Console.WriteLine($"bridge[0x{r:X4}] = {TryRead(cam, EzCam.Bridge, r)}");
            return 0;

        case "eeprom": // read-only dump of the 256-byte EEPROM (I2C 0x50)
            using (var cam = EzCam.Open())
            {
                var data = new byte[256];
                for (int i = 0; i < 256; i++) data[i] = cam.Read(EzCam.Eeprom, (ushort)i);
                for (int o = 0; o < 256; o += 16)
                    Console.WriteLine($"{o:X2}: {Hex(data[o..(o + 16)])}");
                if (args.Length > 1)
                {
                    File.WriteAllBytes(args[1], data);
                    Console.WriteLine($"saved to {args[1]}");
                }
            }
            return 0;

        case "read": // read <target: bridge|sensor|eeprom|0xNNNN> <reg>
            using (var cam = EzCam.Open())
                Console.WriteLine($"0x{cam.Read(Target(args[1]), Num(args[2])):X2}");
            return 0;

        case "replay": // replay <sequence file>
            using (var cam = EzCam.Open())
            {
                cam.Replay(args[1], Console.WriteLine);
                Console.WriteLine("replay done");
            }
            return 0;

        case "capture": // capture <sequence file> <seconds> <out.bin>
            using (var cam = EzCam.Open())
            {
                cam.Replay(args[1], Console.WriteLine);
                double seconds = double.Parse(args[2], CultureInfo.InvariantCulture);
                cam.ResetPipe(0x81);
                cam.ResetPipe(0x82);
                // alternate setting 1: EP 0x81 = 546 bytes/ms, EP 0x82 = 273 bytes/ms
                var readers = new[] { new IsoReader(cam.WinUsbHandle, 0x81, 546), new IsoReader(cam.WinUsbHandle, 0x82, 273) };
                using var file = new BinaryWriter(File.Create(args[3]));
                var gate = new object();
                var stats = new Dictionary<byte, (long packets, long bytes, long errors)>();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
                var threads = readers.Select(r => new Thread(() => r.Run(p =>
                {
                    lock (gate)
                    {
                        // record: ep(1) transfer(4) index(2) status(4) length(2) data
                        file.Write(p.Endpoint); file.Write(p.Transfer); file.Write(p.Index);
                        file.Write(p.Status); file.Write((ushort)p.Data.Length); file.Write(p.Data);
                        var s = stats.GetValueOrDefault(p.Endpoint);
                        stats[p.Endpoint] = (s.packets + 1, s.bytes + p.Data.Length, s.errors + (p.Status != 0 ? 1 : 0));
                    }
                }, cts.Token, m => Console.WriteLine(m))) { IsBackground = true }).ToList();
                threads.ForEach(t => t.Start());
                // While streaming, poll the auto-exposure statistics (bridge 0x8010, 8 bytes) and the
                // snapshot button (bridge 0xA000 bit 2, active low), as the original driver does per frame.
                while (threads.Any(t => t.IsAlive))
                {
                    try
                    {
                        var st = cam.Control(true, EzCam.Bridge, 0x8010, length: 8);
                        byte a000 = cam.Read(EzCam.Bridge, 0xA000);
                        Console.WriteLine($"stats 8010: {Convert.ToHexString(st)}  A000={a000:X2} button={((a000 & 4) == 0 ? "PRESSED" : "up")}");
                    }
                    catch (Exception e) { Console.WriteLine($"poll: {e.Message}"); }
                    Thread.Sleep(250);
                }
                threads.ForEach(t => t.Join());
                foreach (var r in readers) r.Dispose();
                cam.SetAltSetting(0);
                foreach (var (ep, s) in stats.OrderBy(k => k.Key))
                    Console.WriteLine($"ep 0x{ep:X2}: {s.packets} packets, {s.bytes} bytes, {s.errors} packets with error status");
                Console.WriteLine($"saved to {args[3]}");
            }
            return 0;

        case "serve": // serve <sequence file> : stream, and execute register commands from stdin
            using (var cam = EzCam.Open())
            {
                // Protocol (one command per line, one reply per line):
                //   R <value> <index> <len>  -> hex bytes      W <value> <index> <hex> -> ok
                //   F <path>                 -> writes latest luma+chroma frame (38,016 bytes) to path, replies "F <counter>"
                //   Q                        -> quit
                cam.Replay(args[1]);
                cam.ResetPipe(0x81);
                cam.ResetPipe(0x82);
                using var stop = new CancellationTokenSource();
                byte[]? lastY = null, lastC = null;
                int counter = 0;
                var threads = new List<Thread>();
                foreach (var (ep, size, frameBytes) in new[] { ((byte)0x81, 546, 176 * 144), ((byte)0x82, 273, 176 * 144 / 2) })
                {
                    var reader = new IsoReader(cam.WinUsbHandle, ep, size);
                    var asm = new FrameAssembler(frameBytes);
                    var t = new Thread(() =>
                    {
                        reader.Run(p =>
                        {
                            var f = asm.Push(p.Data);
                            if (f == null) return;
                            if (ep == 0x81) { lastY = f; Interlocked.Increment(ref counter); } else lastC = f;
                        }, stop.Token);
                        reader.Dispose();
                    }) { IsBackground = true };
                    t.Start();
                    threads.Add(t);
                }
                Console.Out.Flush();
                Console.WriteLine("ready");
                string? line;
                while ((line = Console.ReadLine()) != null)
                {
                    var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    try
                    {
                        switch (t[0])
                        {
                            case "R":
                                Console.WriteLine(Convert.ToHexString(cam.Control(true, Convert.ToUInt16(t[1], 16), Convert.ToUInt16(t[2], 16), length: int.Parse(t[3]))));
                                break;
                            case "W":
                                ushort v = Convert.ToUInt16(t[1], 16);
                                if (v == EzCam.Eeprom) { Console.WriteLine("refused"); break; }
                                cam.Control(false, v, Convert.ToUInt16(t[2], 16), Convert.FromHexString(t[3]));
                                Console.WriteLine("ok");
                                break;
                            case "F":
                                int before = counter;
                                var deadline = DateTime.UtcNow.AddSeconds(2);
                                while (counter == before && DateTime.UtcNow < deadline) Thread.Sleep(5);
                                var y = lastY; var c = lastC;
                                if (y == null || c == null) { Console.WriteLine("nodata"); break; }
                                File.WriteAllBytes(t[1], [.. y, .. c]);
                                Console.WriteLine($"F {counter}");
                                break;
                            case "Q":
                                stop.Cancel();
                                threads.ForEach(th => th.Join(2000));
                                cam.SetAltSetting(0);
                                Console.WriteLine("bye");
                                return 0;
                        }
                    }
                    catch (Exception e) { Console.WriteLine($"error {e.Message}"); }
                }
            }
            return 0;

        case "preview": // preview <sequence file> [snapshot dir]
            using (var cam = EzCam.Open())
            {
                cam.Replay(args[1]);
                RunWindow(() => new PreviewForm(cam, args.Length > 2 ? args[2] : "captures/snaps", debug: true));
                cam.SetAltSetting(0);
            }
            return 0;

        case "viewer": // viewer [init.seq] [snapshot dir] : end-user entry point (desktop shortcut)
            return Viewer.Run(
                args.Length > 1 ? args[1] : Path.Combine(AppContext.BaseDirectory, "init.seq"),
                args.Length > 2 ? args[2] : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "EZCam II"));

        case "write": // write <target: bridge|sensor> <reg> <value>
            using (var cam = EzCam.Open())
            {
                cam.Write(Target(args[1]), Num(args[2]), (byte)Num(args[3]));
                Console.WriteLine("ok");
            }
            return 0;

        default:
            Console.WriteLine("""
                EzcamProbe - talk to an Ezonics EZCam II (P10UC) through WinUSB

                  find                         show the camera's device path
                  info                         descriptors + current alternate setting
                  regs                         read the bridge registers used by the original driver
                  eeprom [file.bin]            dump the 256-byte calibration EEPROM (read only)
                  read  <target> <reg>         target = bridge | eeprom | 0xNNNN (sensor reads are blocked)
                  write <target> <reg> <val>   bridge or sensor only (EEPROM writes are blocked)
                  replay <file.seq>            run a register sequence made by re/emu.py --sequence
                  capture <file.seq> <sec> <out.bin>
                                               replay, then record both isochronous pipes to a file
                  viewer [file.seq] [snapdir]  live viewer (defaults: init.seq next to the exe, Pictures\EZCam II)
                  preview <file.seq> [snapdir] viewer with debug output (autosave, raw .y/.c snapshots)
                  serve <file.seq>             stream, and run register commands from stdin (used by re/emu.py live)
                """);
            return cmd == "help" ? 0 : 1;
    }
}
catch (Exception e)
{
    Console.Error.WriteLine($"error: {e.Message}");
    return 2;
}

static string TryRead(EzCam cam, ushort target, ushort reg)
{
    try { return $"0x{cam.Read(target, reg):X2}"; }
    catch (Exception e) { return $"<{e.Message}>"; }
}

static ushort Target(string s) => s.ToLowerInvariant() switch
{
    "bridge" => EzCam.Bridge,
    "sensor" => EzCam.Sensor,
    "eeprom" => EzCam.Eeprom,
    _ => Num(s),
};

static ushort Num(string s) => s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
    ? ushort.Parse(s[2..], NumberStyles.HexNumber)
    : ushort.Parse(s);

static string Hex(byte[] b) => string.Join(' ', b.Select(x => x.ToString("X2")));

static void RunWindow(Func<Form> make)
{
    var ui = new Thread(() =>
    {
        Application.EnableVisualStyles();
        Application.Run(make());
    });
    ui.SetApartmentState(ApartmentState.STA);
    ui.Start();
    ui.Join();
}
