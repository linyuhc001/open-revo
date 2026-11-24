using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Management;
using System.Net;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Tasks;

namespace BatteryHealthService;

public enum BatteryPowerState { Unknown, Charging, Discharging, PluggedIn }

public record BatterySnapshot(
    string? Name,
    string? Manufacturer,
    uint? DesignedCapacity,
    uint? FullChargedCapacity,
    uint? CycleCount,
    int? ChargePercent,
    BatteryPowerState PowerState,
    double? ChargePowerWatts)
{
    public double? HealthPercent =>
        DesignedCapacity > 0 && FullChargedCapacity.HasValue
            ? Math.Min(100, FullChargedCapacity.Value * 100.0 / DesignedCapacity.Value)
            : (double?)null;

    public uint? WearCapacity =>
        DesignedCapacity is uint design && FullChargedCapacity is uint full
            ? design > full ? design - full : 0U
            : null;

    public string? HealthLabel =>
        HealthPercent switch
        {
            >= 80 => "良好",
            >= 60 => "一般",
            < 60 and > 0 => "较差",
            _ => "未知"
        };

    public string PowerStateLabel => PowerState switch
    {
        BatteryPowerState.Charging => "充电中",
        BatteryPowerState.Discharging => "放电中",
        BatteryPowerState.PluggedIn => "已接通电源",
        _ => "未知状态"
    };
}

public static class BatteryReader
{
    private static readonly Guid BatteryClassGuid = new("72631E54-78A4-11D0-BCF7-00AA00B7B32A");
    private const uint DigcfPresent = 0x2;
    private const uint DigcfDeviceInterface = 0x10;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 1;
    private const uint FileShareWrite = 2;
    private const uint OpenExisting = 3;
    private const uint IoctlQueryTag = 0x00294040;
    private const uint IoctlQueryInformation = 0x00294044;

    public static BatterySnapshot? Read()
    {
        try
        {
            var native = ReadNative();
            if (native is not null) return native;
        }
        catch (Exception)
        {
            // Some OEM battery drivers expose data to WMI but reject direct IOCTL queries.
        }
        return ReadWmi();
    }

    private static BatterySnapshot? ReadNative()
    {
        var set = SetupDiGetClassDevs(ref BatteryClassGuid, null, IntPtr.Zero, DigcfPresent | DigcfDeviceInterface);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            for (uint index = 0; ; index++)
            {
                var data = new SP_DEVICE_INTERFACE_DATA { cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>() };
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref BatteryClassGuid, index, ref data))
                {
                    if (Marshal.GetLastWin32Error() == 259) break;
                    continue;
                }

                SetupDiGetDeviceInterfaceDetail(set, ref data, IntPtr.Zero, 0, out var needed, IntPtr.Zero);
                var detail = Marshal.AllocHGlobal((int)needed);
                try
                {
                    Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                    if (!SetupDiGetDeviceInterfaceDetail(set, ref data, detail, needed, out _, IntPtr.Zero)) continue;

                    var path = Marshal.PtrToStringUni(detail + 4) ?? string.Empty;
                    using var handle = OpenBattery(path);
                    if (handle.IsInvalid) continue;

                    var snapshot = ReadFromHandle(handle);
                    if (snapshot is not null) return snapshot;
                }
                finally { Marshal.FreeHGlobal(detail); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        return null;
    }

    private static SafeFileHandle OpenBattery(string path)
    {
        var handle = CreateFile(path, GenericRead | GenericWrite, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        var sfh = new SafeFileHandle(handle, false);
        if (!sfh.IsInvalid) return sfh;
        sfh.Dispose();
        var handle2 = CreateFile(path, GenericRead, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        return new SafeFileHandle(handle2, false);
    }

    private static BatterySnapshot? ReadFromHandle(IntPtr handle)
    {
        uint wait = 0;
        if (!DeviceIoControl(handle, IoctlQueryTag, ref wait, sizeof(uint), out uint tag, sizeof(uint), out _, IntPtr.Zero) || tag == 0) return null;

        var query = new BATTERY_QUERY_INFORMATION { BatteryTag = tag, InformationLevel = BatteryQueryInformationLevel.BatteryInformation };
        if (!DeviceIoControl(handle, IoctlQueryInformation, ref query, Marshal.SizeOf(), out BATTERY_INFORMATION info, Marshal.SizeOf(), out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var name = QueryString(handle, tag, BatteryQueryInformationLevel.BatteryDeviceName);
        var manufacturer = QueryString(handle, tag, BatteryQueryInformationLevel.BatteryManufactureName);

        var waitStatus = new BATTERY_WAIT_STATUS { BatteryTag = tag };
        BATTERY_STATUS? status = null;
        if (DeviceIoControl(handle, 0x0029404C, ref waitStatus, Marshal.SizeOf(), out BATTERY_STATUS batteryStatus, Marshal.SizeOf(), out _, IntPtr.Zero))
            status = batteryStatus;

        var charge = status is { Capacity: var current } && info.FullChargedCapacity > 0
            ? (int)Math.Max(0, Math.Min(100, current * 100.0 / info.FullChargedCapacity))
            : (int?)null;

        var state = status?.PowerState switch
        {
            uint s when (s & 0x4) != 0 => BatteryPowerState.Charging,
            uint s when (s & 0x2) != 0 => BatteryPowerState.Discharging,
            uint s when (s & 0x1) != 0 => BatteryPowerState.PluggedIn,
            _ => BatteryPowerState.Unknown
        };

        double? chargePower = null;
        if (status is { Rate: var rate } && rate != int.MinValue)
        {
            var positiveRate = Math.Max(0, rate);
            if ((info.Capabilities & 0x40000000) == 0)
                chargePower = positiveRate / 1000.0;
            else if (status.Value.Voltage is var voltage && voltage != uint.MaxValue && voltage > 0)
                chargePower = positiveRate * (double)voltage / 1_000_000.0;
        }

        return new BatterySnapshot(
            name, manufacturer,
            ValidCapacity(info.DesignedCapacity), ValidCapacity(info.FullChargedCapacity),
            info.CycleCount == uint.MaxValue ? null : info.CycleCount,
            charge, state, chargePower);
    }

    private static uint? ValidCapacity(uint value) => value is 0 or uint.MaxValue ? null : value;

    private static string? QueryString(IntPtr handle, uint tag, BatteryQueryInformationLevel level)
    {
        var query = new BATTERY_QUERY_INFORMATION { BatteryTag = tag, InformationLevel = level };
        var buffer = Marshal.AllocHGlobal(512);
        try
        {
            if (!DeviceIoControl(handle, IoctlQueryInformation, ref query, Marshal.SizeOf(), buffer, 512, out _, IntPtr.Zero)) return null;
            return Marshal.PtrToStringUni(buffer)?.TrimEnd('\0');
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static BatterySnapshot? ReadWmi()
    {
        try
        {
            var battery = QueryFirst(@"root\cimv2", "SELECT Name, Status, EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery");
            if (battery is null) return null;

            var name = Convert.ToString(battery["Name"]);
            var charge = ToInt(battery["EstimatedChargeRemaining"]);
            var batteryStatus = ToInt(battery["BatteryStatus"]);
            battery.Dispose();

            var staticData = QueryFirst(@"root\wmi", "SELECT DesignedCapacity, DeviceName, ManufactureName FROM BatteryStaticData");
            var designed = ToUInt(staticData?["DesignedCapacity"]);
            name = Convert.ToString(staticData?["DeviceName"]) ?? name;
            var manufacturer = Convert.ToString(staticData?["ManufactureName"]);
            staticData?.Dispose();

            var fullData = QueryFirst(@"root\wmi", "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity");
            var full = ToUInt(fullData?["FullChargedCapacity"]);
            fullData?.Dispose();

            var cycleData = QueryFirst(@"root\wmi", "SELECT CycleCount FROM BatteryCycleCount");
            var cycles = ToUInt(cycleData?["CycleCount"]);
            cycleData?.Dispose();

            double? chargePower = null;
            try
            {
                var statusData = QueryFirst(@"root\wmi", "SELECT ChargeRate FROM BatteryStatus");
                if (statusData?["ChargeRate"] is object crObj)
                {
                    try
                    {
                        var rateVal = Convert.ToDouble(crObj);
                        if (rateVal >= 0 && rateVal < uint.MaxValue) chargePower = rateVal / 1000.0;
                    } catch { }
                    statusData?.Dispose();
                }
            } catch { }

            return new BatterySnapshot(name, manufacturer, designed, full, cycles, charge, WmiPowerState(batteryStatus), chargePower);
        }
        catch (ManagementException) { return null; }
    }

    private static ManagementObject? QueryFirst(string scope, string query)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (ManagementObject item in searcher.Get()) return item;
            return null;
        }
        catch (ManagementException) { return null; }
    }

    private static uint? ToUInt(object? value)
    {
        if (value is null) return null;
        try { var converted = Convert.ToUInt32(value); return ValidCapacity(converted); }
        catch { return null; }
    }

    private static int? ToInt(object? value)
    {
        if (value is null) return null;
        try { return Convert.ToInt32(value); }
        catch { return null; }
    }

    private static BatteryPowerState WmiPowerState(int? status) => status switch
    {
        1 => BatteryPowerState.Discharging,
        2 or 3 or 11 => BatteryPowerState.PluggedIn,
        >= 6 and <= 9 => BatteryPowerState.Charging,
        _ => BatteryPowerState.Unknown
    };

    private enum BatteryQueryInformationLevel
    {
        BatteryInformation,
        BatteryGranularityInformation,
        BatteryTemperature,
        BatteryEstimatedTime,
        BatteryDeviceName,
        BatteryManufactureDate,
        BatteryManufactureName
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA { public int cbSize; public Guid InterfaceClassGuid; public int Flags; public IntPtr Reserved; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BATTERY_QUERY_INFORMATION { public uint BatteryTag; public BatteryQueryInformationLevel InformationLevel; public int AtRate; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct BATTERY_INFORMATION
    {
        public uint Capabilities;
        public byte Technology;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] public byte[] Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] Chemistry;
        public uint DesignedCapacity;
        public uint FullChargedCapacity;
        public uint DefaultAlert1;
        public uint DefaultAlert2;
        public uint CriticalBias;
        public uint CycleCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BATTERY_WAIT_STATUS { public uint BatteryTag; public uint Timeout; public uint PowerState; public uint LowCapacity; public uint HighCapacity; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BATTERY_STATUS { public uint PowerState; public uint Capacity; public uint Voltage; public int Rate; }

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, string? enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr device, ref Guid guid, uint index, ref SP_DEVICE_INTERFACE_DATA data);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set, ref SP_DEVICE_INTERFACE_DATA data, IntPtr detail, uint size, out uint needed, IntPtr deviceInfo);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr handle, uint code, ref uint input, int inputSize, out uint output, int outputSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr handle, uint code, ref BATTERY_QUERY_INFORMATION input, int inputSize, out BATTERY_INFORMATION output, int outputSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr handle, uint code, ref BATTERY_QUERY_INFORMATION input, int inputSize, IntPtr output, int outputSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr handle, uint code, ref BATTERY_WAIT_STATUS input, int inputSize, out BATTERY_STATUS output, int outputSize, out uint returned, IntPtr overlapped);
}

public static class Program
{
    private const string Url = "http://localhost:58732/";
    private static HttpListener? _listener;
    private static CancellationTokenSource? _cts;

    public static async Task Main()
    {
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Error: This service requires administrator privileges.");
            return;
        }

        // Ensure URL ACLs
        try
        {
            var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"http add urlacl url={Url} user=Everyone",
                UseShellExecute = false,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            proc?.WaitForExit();
        } catch { /* Ignore ACL errors if already set */ }

        _listener = new HttpListener();
        _listener.Prefixes.Add(Url);
        _cts = new CancellationTokenSource();

        var readTask = Task.Run(async () =>
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    await HandleRequest(context);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Request error: {ex.Message}");
                }
            }
        });

        Console.WriteLine("BatteryHealthService started on port 58732");
        Console.WriteLine("Press Ctrl+C to stop.");

        // Auto-refresh loop for telemetry push (optional)
        var refreshTask = Task.Run(async () =>
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                await Task.Delay(5000);
                try
                {
                    var snapshot = BatteryReader.Read();
                    if (snapshot is not null)
                        Console.WriteLine($"[Telemetry] Health={snapshot.HealthPercent:F1}% Cycles={snapshot.CycleCount} Charge={snapshot.ChargePercent}%");
                }
                catch { }
            }
        });

        Console.ReadLine();
        Stop();
    }

    private static async Task HandleRequest(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        if (request.Url?.AbsolutePath == "/health" || request.Url?.AbsolutePath == "/")
        {
            var snapshot = BatteryReader.Read();
            var json = JsonSerializer.Serialize(snapshot ?? new BatterySnapshot(null, null, null, null, null, null, BatteryPowerState.Unknown, null));
            var buffer = System.Text.Encoding.UTF8.GetBytes(json);
            response.ContentType = "application/json";
            response.StatusCode = (int)System.Net.HttpStatusCode.OK;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }
        else if (request.Url?.AbsolutePath == "/status")
        {
            var json = JsonSerializer.Serialize(new { service = "running", timestamp = DateTime.UtcNow.ToString("o") });
            var buffer = System.Text.Encoding.UTF8.GetBytes(json);
            response.ContentType = "application/json";
            response.StatusCode = (int)System.Net.HttpStatusCode.OK;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }
        else
        {
            response.StatusCode = (int)System.Net.HttpStatusCode.NotFound;
        }

        response.Close();
    }

    private static void Stop()
    {
        _cts?.Cancel();
        _listener?.Close();
        Console.WriteLine("BatteryHealthService stopped.");
    }

    private static bool IsAdministrator()
    {
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
