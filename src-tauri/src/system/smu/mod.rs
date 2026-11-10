// OpenRevo - AMD Ryzen SMU (System Management Unit) PBO bridge
// Adapted from ZenStates-Core (SMUDebugTool) command tables and encodings.
//
// Scope: RSMU mailbox only (PawnIO RyzenSMU module limitation).
//   - Curve Optimizer (per-core & all-core)
//   - PBO Scalar
//   - FMax / Boost Limit Frequency
//   - SMU version / code name / PM table reading

mod pawnio;

use pawnio::PawnIo;
use std::sync::{Mutex, OnceLock};

// ---- SMU mailbox function names exported by RyzenSMU.bin ----
const FN_GET_SMU_VERSION: &str = "ioctl_get_smu_version";
const FN_SEND_SMU_COMMAND: &str = "ioctl_send_smu_command";
const FN_RESOLVE_PM_TABLE: &str = "ioctl_resolve_pm_table";
const FN_GET_CODE_NAME: &str = "ioctl_get_code_name";

// ---- SMU status codes ----
pub const SMU_OK: u32 = 0x01;

/// CPU code name enum, matching RyzenSMU PawnIO module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CpuCodeName {
    Undefined = -1,
    Colfax = 0,
    Renoir,
    Picasso,
    Matisse,
    Threadripper,
    CastlePeak,
    RavenRidge,
    RavenRidge2,
    SummitRidge,
    PinnacleRidge,
    Rembrandt,
    Vermeer,
    Vangogh,
    Cezanne,
    Milan,
    Dali,
    Raphael,
    GraniteRidge,
    Naples,
    FireFlight,
    Rome,
    Chagall,
    Lucienne,
    Phoenix,
    Phoenix2,
    Mendocino,
    Genoa,
    StormPeak,
    DragonRange,
    Mero,
    HawkPoint,
    StrixPoint,
    StrixHalo,
    KrackanPoint,
    KrackanPoint2,
    Turin,
    TurinD,
    Bergamo,
    ShimadaPeak,
    Carrizo,
    BristolRidge,
    StoneyRidge,
}

impl CpuCodeName {
    fn from_i64(v: i64) -> CpuCodeName {
        match v {
            0 => CpuCodeName::Colfax,
            1 => CpuCodeName::Renoir,
            2 => CpuCodeName::Picasso,
            3 => CpuCodeName::Matisse,
            4 => CpuCodeName::Threadripper,
            5 => CpuCodeName::CastlePeak,
            6 => CpuCodeName::RavenRidge,
            7 => CpuCodeName::RavenRidge2,
            8 => CpuCodeName::SummitRidge,
            9 => CpuCodeName::PinnacleRidge,
            10 => CpuCodeName::Rembrandt,
            11 => CpuCodeName::Vermeer,
            12 => CpuCodeName::Vangogh,
            13 => CpuCodeName::Cezanne,
            14 => CpuCodeName::Milan,
            15 => CpuCodeName::Dali,
            16 => CpuCodeName::Raphael,
            17 => CpuCodeName::GraniteRidge,
            18 => CpuCodeName::Naples,
            19 => CpuCodeName::FireFlight,
            20 => CpuCodeName::Rome,
            21 => CpuCodeName::Chagall,
            22 => CpuCodeName::Lucienne,
            23 => CpuCodeName::Phoenix,
            24 => CpuCodeName::Phoenix2,
            25 => CpuCodeName::Mendocino,
            26 => CpuCodeName::Genoa,
            27 => CpuCodeName::StormPeak,
            28 => CpuCodeName::DragonRange,
            29 => CpuCodeName::Mero,
            30 => CpuCodeName::HawkPoint,
            31 => CpuCodeName::StrixPoint,
            32 => CpuCodeName::StrixHalo,
            33 => CpuCodeName::KrackanPoint,
            34 => CpuCodeName::KrackanPoint2,
            35 => CpuCodeName::Turin,
            36 => CpuCodeName::TurinD,
            37 => CpuCodeName::Bergamo,
            38 => CpuCodeName::ShimadaPeak,
            39 => CpuCodeName::Carrizo,
            40 => CpuCodeName::BristolRidge,
            41 => CpuCodeName::StoneyRidge,
            _ => CpuCodeName::Undefined,
        }
    }
}

/// RSMU command table for a given CPU generation.
/// Only RSMU mailbox commands are usable through PawnIO.
#[derive(Debug, Clone, Default)]
struct RsmuCommands {
    /// Curve Optimizer: set DLDO PSM margin for a single core.
    set_dldo_psm_margin: u32,
    /// Curve Optimizer: set DLDO PSM margin for all cores.
    set_all_dldo_psm_margin: u32,
    /// Curve Optimizer: read DLDO PSM margin for a single core.
    get_dldo_psm_margin: u32,
    /// PBO scalar (set).
    set_pbo_scalar: u32,
    /// PBO scalar (get).
    get_pbo_scalar: u32,
    /// FMax / boost limit frequency (set all cores).
    set_boost_limit_all_core: u32,
    /// FMax / boost limit frequency (get).
    get_boost_limit_frequency: u32,
    /// Legacy vid override (Zen/Zen+ fallback for negative CO).
    set_overclock_cpu_vid: u32,
}

/// SMU type (generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmuType {
    Cpu0, // Zen (Summit Ridge)
    Cpu1, // Zen+ (Pinnacle Ridge)
    Cpu2, // Zen2 (Matisse)
    Cpu3, // Zen3 (Vermeer)
    Cpu4, // Zen4 (Raphael) / Zen5 (Granite Ridge) — identical RSMU
    Cpu9, // Bristol Ridge (pre-Ryzen)
    Unsupported,
}

/// Determine SMU type and RSMU command table from CPU code name.
fn resolve_commands(code: CpuCodeName) -> (SmuType, RsmuCommands) {
    use CpuCodeName::*;
    let mut c = RsmuCommands::default();
    let t = match code {
        // Zen (Summit Ridge / Naples / Whitehaven)
        SummitRidge | Naples => {
            c.set_dldo_psm_margin = 0x5D;
            c.set_all_dldo_psm_margin = 0x5E;
            c.set_overclock_cpu_vid = 0x17;
            SmuType::Cpu0
        }
        // Zen+ (Pinnacle Ridge / Colfax)
        PinnacleRidge | Colfax => {
            c.set_pbo_scalar = 0x6A;
            c.get_pbo_scalar = 0x6F;
            c.set_overclock_cpu_vid = 0x6E;
            SmuType::Cpu1
        }
        // Zen2 (Matisse / CastlePeak / Rome)
        Matisse | CastlePeak | Rome => {
            c.set_dldo_psm_margin = 0x0A; // "Not sure"
            c.set_all_dldo_psm_margin = 0x0B; // "Not sure"
            c.get_dldo_psm_margin = 0x7C; // "Not sure"
            c.set_pbo_scalar = 0x58;
            c.get_pbo_scalar = 0x6C;
            c.get_boost_limit_frequency = 0x6E;
            c.set_overclock_cpu_vid = 0x61;
            SmuType::Cpu2
        }
        // Zen3 (Vermeer / Chagall / Milan)
        Vermeer | Chagall | Milan => {
            c.set_dldo_psm_margin = 0x35;
            c.set_all_dldo_psm_margin = 0x36;
            SmuType::Cpu3
        }
        // Zen4 (Raphael / Genoa / StormPeak / DragonRange)
        // Zen5 (Granite Ridge / Turin / TurinD / Bergamo / ShimadaPeak) — same RSMU as Zen4
        Raphael | Genoa | StormPeak | DragonRange | GraniteRidge | Turin | TurinD | Bergamo
        | ShimadaPeak => {
            c.set_dldo_psm_margin = 0x06;
            c.set_all_dldo_psm_margin = 0x07;
            c.get_dldo_psm_margin = 0xD5;
            c.set_pbo_scalar = 0x5B;
            c.get_pbo_scalar = 0x6D;
            c.get_boost_limit_frequency = 0x6E;
            c.set_boost_limit_all_core = 0x70;
            c.set_overclock_cpu_vid = 0x61;
            SmuType::Cpu4
        }
        // Bristol Ridge / Carrizo / Stoney Ridge (pre-Ryzen)
        BristolRidge | Carrizo | StoneyRidge => SmuType::Cpu9,
        _ => SmuType::Unsupported,
    };
    (t, c)
}

/// The global SMU bridge (lazy-initialized).
static SMU_BRIDGE: OnceLock<Mutex<Option<SmuBridge>>> = OnceLock::new();

struct SmuBridge {
    pawn: PawnIo,
    code_name: CpuCodeName,
    smu_type: SmuType,
    commands: RsmuCommands,
    smu_version: u32,
    pm_table_version: u32,
    pm_table_size: u32,
    dram_base: u64,
}

impl SmuBridge {
    /// Sends an RSMU command with up to 6 args.
    ///
    /// The PawnIO module returns SMU status via the IOCTL HRESULT (0 = SMU_OK),
    /// NOT via the out array. The out array holds the 6 SMU argument registers.
    /// Returns Ok(args) when the command succeeded, Err otherwise.
    fn send_rsmu_command(&self, command: u32, args: &[u32; 6]) -> Result<[u32; 6], String> {
        let mut input = [0u64; 7];
        input[0] = command as u64;
        for i in 0..6 {
            input[i + 1] = args[i] as u64;
        }
        let (hr, out) = self.pawn.execute_hr(FN_SEND_SMU_COMMAND, &input, 6)?;
        if hr != 0 {
            return Err(format!("SMU command 0x{:02X} rejected (HRESULT 0x{:08X})", command, hr));
        }
        let mut result = [0u32; 6];
        for i in 0..6 {
            result[i] = (out[i] & 0xFFFF_FFFF) as u32;
        }
        Ok(result)
    }
}

// ---- Encoding helpers (ported from ZenStates-Core Utils.cs) ----

/// CO margin encoding: 16-bit, negative margin gets 0x100000 offset.
fn make_psm_margin_arg(margin: i32) -> u32 {
    let offset = if margin < 0 { 0x100000u32 } else { 0 };
    offset.wrapping_add(margin as u32) & 0xFFFF
}

/// Core mask encoding:
///   family > 17h: (ccd << 28) | ((core % 8) << 20)
///   otherwise:    (ccd << 28) | ((ccx % 2) << 24) | ((core % 4) << 20)
fn make_core_mask(core: u32, ccd: u32, ccx: u32, family_gt_17h: bool) -> u32 {
    if family_gt_17h {
        (ccd << 28) | ((core % 8) << 20)
    } else {
        (ccd << 28) | ((ccx % 2) << 24) | ((core % 4) << 20)
    }
}

/// Clamp CO margin to [-50, 50].
fn clamp_margin(margin: i32) -> i32 {
    margin.clamp(-50, 50)
}

fn is_family_gt_17h(t: SmuType) -> bool {
    // Zen2 and newer are family 17h/19h; the "> 17h" check in ZenStates uses family,
    // but for the core-mask encoding, Zen3+ use the (core % 8) form.
    // Zen/Zen+ (Cpu0/Cpu1) use the (ccx, core % 4) form.
    matches!(t, SmuType::Cpu2 | SmuType::Cpu3 | SmuType::Cpu4)
}

// ---- Public API ----

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmuInfo {
    pub supported: bool,
    pub code_name: String,
    pub smu_type: u32,
    pub smu_version: u32,
    pub pm_table_version: u32,
    pub pm_table_size: u32,
    pub dram_base: u64,
    pub curve_optimizer_supported: bool,
    pub pbo_scalar_supported: bool,
    pub fmax_supported: bool,
}

impl SmuBridge {
    fn summary(&self) -> SmuInfo {
        SmuInfo {
            supported: self.smu_type != SmuType::Unsupported,
            code_name: format!("{:?}", self.code_name),
            smu_type: smu_type_u32(self.smu_type),
            smu_version: self.smu_version,
            pm_table_version: self.pm_table_version,
            pm_table_size: self.pm_table_size,
            dram_base: self.dram_base,
            curve_optimizer_supported: self.commands.set_dldo_psm_margin != 0
                || self.commands.set_all_dldo_psm_margin != 0
                || self.commands.set_overclock_cpu_vid != 0,
            pbo_scalar_supported: self.commands.set_pbo_scalar != 0,
            fmax_supported: self.commands.get_boost_limit_frequency != 0
                || self.commands.set_boost_limit_all_core != 0,
        }
    }
}

fn smu_type_u32(t: SmuType) -> u32 {
    match t {
        SmuType::Cpu0 => 0,
        SmuType::Cpu1 => 1,
        SmuType::Cpu2 => 2,
        SmuType::Cpu3 => 3,
        SmuType::Cpu4 => 4,
        SmuType::Cpu9 => 9,
        SmuType::Unsupported => 0xFF,
    }
}

/// Initialize the SMU bridge. Returns a summary on success.
pub fn init_smu() -> Result<SmuInfo, String> {
    let slot = SMU_BRIDGE.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().map_err(|_| "SMU bridge lock poisoned".to_string())?;

    if let Some(b) = guard.as_ref() {
        return Ok(b.summary());
    }

    let blob: &[u8] = include_bytes!("../../../assets/smu/RyzenSMU.bin");
    let pawn = PawnIo::load_module_from_bytes(blob)?;

    let code_name = {
        let out = pawn.execute(FN_GET_CODE_NAME, &[], 1)?;
        // Driver returns the code name as a signed 32-bit int (0xFFFFFFFF = -1 = Undefined).
        CpuCodeName::from_i64((out[0] & 0xFFFF_FFFF) as i32 as i64)
    };

    let (smu_type, commands) = resolve_commands(code_name);
    if smu_type == SmuType::Unsupported {
        return Err(format!("Unsupported CPU code name: {:?}", code_name));
    }

    let smu_version = {
        let out = pawn.execute(FN_GET_SMU_VERSION, &[], 1)?;
        (out[0] & 0xFFFF_FFFF) as u32
    };

    let (pm_table_version, dram_base) = match pawn.execute(FN_RESOLVE_PM_TABLE, &[], 2) {
        Ok(out) if out.len() >= 2 => ((out[0] & 0xFFFF_FFFF) as u32, out[1]),
        _ => (0, 0),
    };

    let pm_table_size = default_pm_table_size(code_name, pm_table_version);

    let bridge = SmuBridge {
        pawn,
        code_name,
        smu_type,
        commands,
        smu_version,
        pm_table_version,
        pm_table_size,
        dram_base,
    };

    let summary = bridge.summary();
    *guard = Some(bridge);
    Ok(summary)
}

fn default_pm_table_size(code: CpuCodeName, version: u32) -> u32 {
    use CpuCodeName::*;
    match code {
        Matisse => match version {
            0x240902 => 0x514,
            0x240903 => 0x518,
            0x240802 => 0x7E0,
            0x240803 => 0x7E4,
            _ => 0x994,
        },
        Vermeer => match version {
            0x2D0903 => 0x594,
            0x380904 => 0x5A4,
            0x380905 => 0x5D0,
            0x2D0803 => 0x894,
            0x380804 => 0x8A4,
            0x380805 => 0x8F0,
            _ => 0x994,
        },
        Raphael | GraniteRidge => match version {
            0x00540004 => 0x948,
            0x00540104 => 0x950,
            0x00620205 => 0x994,
            _ => 0x994,
        },
        _ => 0x994,
    }
}

fn with_bridge<T>(f: impl FnOnce(&SmuBridge) -> Result<T, String>) -> Result<T, String> {
    let slot = SMU_BRIDGE.get_or_init(|| Mutex::new(None));
    let guard = slot.lock().map_err(|_| "SMU bridge lock poisoned".to_string())?;
    let bridge = guard.as_ref().ok_or("SMU bridge not initialized")?;
    f(bridge)
}

/// Set Curve Optimizer margin for a single core. Returns SMU status (1 = OK).
pub fn set_co_single_core(core: u32, ccd: u32, ccx: u32, margin: i32) -> Result<u32, String> {
    with_bridge(|b| {
        if b.commands.set_dldo_psm_margin == 0 {
            return Err("Curve Optimizer not supported on this CPU".into());
        }
        let margin = clamp_margin(margin);
        let mask = make_core_mask(core, ccd, ccx, is_family_gt_17h(b.smu_type));
        let m = make_psm_margin_arg(margin);
        let arg = (mask & 0xFFF0_0000) | m;
        let args = [arg, 0, 0, 0, 0, 0];
        b.send_rsmu_command(b.commands.set_dldo_psm_margin, &args)?;
        Ok(SMU_OK)
    })
}

/// Set Curve Optimizer margin for all cores. Returns SMU status (1 = OK).
pub fn set_co_all_cores(margin: i32) -> Result<u32, String> {
    with_bridge(|b| {
        let margin = clamp_margin(margin);
        if b.commands.set_all_dldo_psm_margin != 0 {
            let arg = make_psm_margin_arg(margin);
            let args = [arg, 0, 0, 0, 0, 0];
            b.send_rsmu_command(b.commands.set_all_dldo_psm_margin, &args)?;
            Ok(SMU_OK)
        } else if b.commands.set_overclock_cpu_vid != 0 {
            // Legacy path (Zen/Zen+): vid override.
            let vid = curve_optimizer_to_vid(margin);
            let args = [vid, 0, 0, 0, 0, 0];
            b.send_rsmu_command(b.commands.set_overclock_cpu_vid, &args)?;
            Ok(SMU_OK)
        } else {
            Err("Curve Optimizer not supported on this CPU".into())
        }
    })
}

/// Set PBO scalar. Input is scalar*1000 (e.g. 1500 = 1.5x). Returns SMU status.
pub fn set_pbo_scalar(scalar_x1000: u32) -> Result<u32, String> {
    with_bridge(|b| {
        if b.commands.set_pbo_scalar == 0 {
            return Err("PBO Scalar not supported on this CPU".into());
        }
        // ZenStates uses `arg` as an integer multiplier where 1 = 1.0x (then *100 -> 100).
        let scalar_int = (scalar_x1000 / 1000).max(1);
        let limit = scalar_int * 100;
        let args = [limit, 0, 0, 0, 0, 0];
        b.send_rsmu_command(b.commands.set_pbo_scalar, &args)?;
        Ok(SMU_OK)
    })
}

/// Get current PBO scalar (returns float as x1000 int, e.g. 1000 = 1.0x).
pub fn get_pbo_scalar() -> Result<u32, String> {
    with_bridge(|b| {
        if b.commands.get_pbo_scalar == 0 {
            return Err("PBO Scalar not supported on this CPU".into());
        }
        let args = [0; 6];
        let out = b.send_rsmu_command(b.commands.get_pbo_scalar, &args)?;
        // Response is an IEEE754 float in args[0].
        let scalar = f32::from_bits(out[0]);
        if scalar >= 1.0 && scalar <= 10.0 {
            Ok((scalar * 1000.0) as u32)
        } else {
            Ok(1000) // default 1.0x
        }
    })
}

/// Set FMax / boost limit frequency (MHz). Returns SMU status.
pub fn set_fmax(frequency_mhz: u32) -> Result<u32, String> {
    with_bridge(|b| {
        if b.commands.set_boost_limit_all_core == 0 {
            return Err("FMax not supported on this CPU".into());
        }
        let args = [frequency_mhz & 0xFFFFF, 0, 0, 0, 0, 0];
        b.send_rsmu_command(b.commands.set_boost_limit_all_core, &args)?;
        Ok(SMU_OK)
    })
}

/// Get current FMax / boost limit frequency (MHz). Returns 0 if unsupported.
pub fn get_fmax() -> Result<u32, String> {
    with_bridge(|b| {
        if b.commands.get_boost_limit_frequency == 0 {
            return Ok(0);
        }
        let args = [0; 6];
        let out = b.send_rsmu_command(b.commands.get_boost_limit_frequency, &args)?;
        Ok(out[0])
    })
}

/// Curve optimizer -> VID conversion (legacy Zen/Zen+ fallback).
fn curve_optimizer_to_vid(co: i32) -> u32 {
    let co = co.clamp(-50, 50);
    let base_voltage = 1.30f64;
    let max_offset = 0.200f64;
    let gamma = 1.7f64;
    let normalized = (co as f64).abs() / 50.0;
    let curve = normalized.powf(gamma);
    let mut delta = curve * max_offset;
    if co < 0 {
        delta = -delta;
    }
    let target = base_voltage + delta;
    voltage_to_vid(target)
}

fn voltage_to_vid(voltage: f64) -> u32 {
    // Zen/Zen+ VID encoding: 1.55V = 0, 0.80V = ~0x7F (inverse linear).
    let vid = ((1.55 - voltage) / 0.00625).round() as i32;
    vid.clamp(0, 0xFF) as u32
}
