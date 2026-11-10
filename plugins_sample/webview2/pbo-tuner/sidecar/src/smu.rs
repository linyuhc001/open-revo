// OpenRevo PBO service - AMD Ryzen SMU (System Management Unit) bridge
// Adapted from ZenStates-Core (SMUDebugTool) command tables and encodings.
//
// Scope: RSMU mailbox only (PawnIO RyzenSMU module limitation).
//   - Curve Optimizer (per-core & all-core)
//   - PBO Scalar
//   - FMax / Boost Limit Frequency
//   - SMU version / code name / PM table reading
//
// Moved out of the OpenRevo host so the whole feature ships inside the plugin.

use crate::pawnio::PawnIo;
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
    /// Zen5 mobile HX die ("Fire Range"): 9955HX / 9955HX3D and friends.
    /// RyzenSMU collapses family 1Ah model 44h into `GraniteRidge` because the
    /// silicon is the mobile variant of the same die, but the SKUs and their
    /// cache layout are different, so we keep them apart. Never produced by
    /// `from_i64` — only by CPUID identification.
    FireRange,
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

/// RSMU command table shared by Zen4 (Raphael/Genoa/DragonRange) and Zen5
/// (Granite Ridge / Fire Range / Turin) — the mailbox layout and message ids
/// are identical across those families.
fn zen45_commands() -> RsmuCommands {
    RsmuCommands {
        set_dldo_psm_margin: 0x06,
        set_all_dldo_psm_margin: 0x07,
        get_dldo_psm_margin: 0xD5,
        set_pbo_scalar: 0x5B,
        get_pbo_scalar: 0x6D,
        get_boost_limit_frequency: 0x6E,
        set_boost_limit_all_core: 0x70,
        set_overclock_cpu_vid: 0x61,
    }
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
        // Zen5 (Granite Ridge / Fire Range / Turin / TurinD / Bergamo / ShimadaPeak)
        Raphael | Genoa | StormPeak | DragonRange | GraniteRidge | FireRange | Turin | TurinD
        | Bergamo | ShimadaPeak => {
            c = zen45_commands();
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

// ---- CPU topology detection ----

// kernel32 imports for counting physical cores (RelationProcessorCore entries).
#[link(name = "kernel32")]
extern "system" {
    fn GetLogicalProcessorInformation(buffer: *mut u8, returned_length: *mut u32) -> i32;
}

// SYSTEM_LOGICAL_PROCESSOR_INFORMATION layout.
//
// x64: ULONG_PTR ProcessorMask (8) + RELATIONSHIP (4) + padding (4) + union (16) = 32 bytes.
// The union holds `ULONG64 Reserved[2]`, so it is 8-byte aligned and 16 bytes wide —
// NOT the 4 bytes a naive `{ usize, u32, u32 }` struct would give. Parsing with the
// wrong stride silently reads the union as if it were the next entry, so the stride
// below has to match the real ABI.
const RELATION_PROCESSOR_CORE: u32 = 0;
const RELATION_CACHE: u32 = 2;
const CACHE_UNIFIED: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct SystemLogicalProcessorInformation {
    processor_mask: usize,
    relationship: u32,
    _reserved: u32,
    /// union bytes 0..8 — for caches: Level | Assoc<<8 | LineSize<<16 | CacheSize<<32
    payload0: u64,
    /// union bytes 8..16 — for caches: low dword is PROCESSOR_CACHE_TYPE
    payload1: u64,
}

/// One physical core as reported by Windows, plus the L3 it shares.
#[derive(Clone, Copy)]
struct WinCoreInfo {
    l3_kb: u32,
    /// Cache descriptor mask of the L3 slice this core reports into.
    /// 0 when Windows did not describe an L3 for it.
    l3_mask: usize,
}

/// Read the full logical-processor topology from the kernel.
fn read_topology() -> Option<Vec<SystemLogicalProcessorInformation>> {
    unsafe {
        let mut needed: u32 = 0;
        GetLogicalProcessorInformation(std::ptr::null_mut(), &mut needed);
        if needed == 0 {
            return None;
        }
        let byte_len = needed as usize;
        let mut buf: Vec<u8> = vec![0u8; byte_len];
        if GetLogicalProcessorInformation(buf.as_mut_ptr(), &mut needed) == 0 {
            return None;
        }

        let elem_size = std::mem::size_of::<SystemLogicalProcessorInformation>();
        let count = byte_len / elem_size;
        if count == 0 || byte_len % elem_size != 0 {
            // Layout mismatch — refuse to parse rather than return garbage.
            return None;
        }

        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            out.push(*(buf.as_ptr().add(i * elem_size)
                as *const SystemLogicalProcessorInformation));
        }
        Some(out)
    }
}

fn smt_heuristic_core_count() -> u32 {
    let logical = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0) as u32;
    if logical > 0 {
        (logical + 1) / 2
    } else {
        0
    }
}

// ---- CPUID identification (fallback when RyzenSMU.bin predates the SKU) ----

/// (family, model, package type) of the current CPU.
fn cpuid_identity() -> Option<(u32, u32, u32)> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let leaf1 = core::arch::x86_64::__cpuid(1);
        let base_family = (leaf1.eax >> 8) & 0xF;
        let base_model = (leaf1.eax >> 4) & 0xF;
        let ext_family = (leaf1.eax >> 20) & 0xFF;
        let ext_model = (leaf1.eax >> 16) & 0xF;
        let family = if base_family == 0xF {
            base_family + ext_family
        } else {
            base_family
        };
        let model = if base_family == 0xF || base_family == 0x6 {
            (ext_model << 4) | base_model
        } else {
            base_model
        };
        let ext = core::arch::x86_64::__cpuid(0x8000_0001);
        let pkg = (ext.ecx >> 28) & 0xFF;
        Some((family, model, pkg))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Marketing name from the CPUID brand string ("AMD Ryzen 9 9955HX3D …").
fn cpuid_brand_string() -> String {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut bytes = [0u8; 48];
        for (i, leaf) in [0x8000_0002u32, 0x8000_0003, 0x8000_0004]
            .iter()
            .enumerate()
        {
            let r = core::arch::x86_64::__cpuid(*leaf);
            let chunk = [r.eax, r.ebx, r.ecx, r.edx];
            for (j, v) in chunk.iter().enumerate() {
                bytes[i * 16 + j * 4..i * 16 + j * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        String::from_utf8_lossy(&bytes)
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        String::new()
    }
}

/// Marketing name for the health endpoint and startup logs.
pub fn cpu_name() -> String {
    cpuid_brand_string()
}

/// Map CPUID family/model to a code name for parts the installed RyzenSMU blob
/// may not know about. Covers the Zen4/Zen5 server and consumer lines; anything
/// else falls through to `Undefined`.
fn detect_code_name_from_cpuid() -> CpuCodeName {
    use CpuCodeName::*;
    let Some((family, model, pkg)) = cpuid_identity() else {
        return Undefined;
    };
    match (family, model) {
        // Zen5 (family 1Ah)
        (0x1A, 0x02) => Turin,
        (0x1A, 0x08) => ShimadaPeak,
        (0x1A, 0x11) => TurinD,
        (0x1A, 0x20) | (0x1A, 0x24) => StrixPoint,
        // Fire Range — the mobile HX die used by 9955HX / 9955HX3D. RyzenSMU
        // reports this as GraniteRidge, which is why the name is resolved here
        // instead of trusting the driver.
        (0x1A, 0x44) => FireRange,
        (0x1A, 0x60) => KrackanPoint,
        (0x1A, 0x68) => KrackanPoint2,
        (0x1A, 0x70) => StrixHalo,
        // Zen4 (family 19h)
        (0x19, 0x00) | (0x19, 0x01) => Milan,
        (0x19, 0x08) => Chagall,
        (0x19, 0x11) => Genoa,
        (0x19, 0x18) => StormPeak,
        (0x19, 0x20) | (0x19, 0x21) => Vermeer,
        (0x19, 0x44) => Rembrandt,
        (0x19, 0x50) => Cezanne,
        (0x19, 0x61) => {
            if pkg == 1 {
                DragonRange
            } else {
                Raphael
            }
        }
        (0x19, 0x74) | (0x19, 0x75) => Phoenix,
        (0x19, 0x78) => Phoenix2,
        (0x19, 0x7C) => HawkPoint,
        (0x19, 0xA0) => Bergamo,
        // Zen/Zen+/Zen2 (family 17h) — the driver handles these correctly too,
        // but keeping them here means one code path decides the name everywhere.
        (0x17, 0x01) => SummitRidge,
        (0x17, 0x08) => PinnacleRidge,
        (0x17, 0x11) => RavenRidge,
        (0x17, 0x18) => Picasso,
        (0x17, 0x20) => Dali,
        (0x17, 0x31) => Rome,
        (0x17, 0x60) => Renoir,
        (0x17, 0x68) => Lucienne,
        (0x17, 0x71) => Matisse,
        (0x17, 0x90) | (0x17, 0x91) => Vangogh,
        (0x17, 0x98) => Mero,
        (0x17, 0xA0) => Mendocino,
        _ => Undefined,
    }
}

/// Enumerate physical cores with the size of the L3 slice each one sees.
///
/// The L3 grouping is what tells a X3D part apart from a plain one: on a
/// dual-CCD X3D (e.g. 9955HX3D) one CCD reports a ~96 MB unified L3 while the
/// other reports 32 MB.
fn detect_cores() -> Vec<WinCoreInfo> {
    let Some(entries) = read_topology() else {
        return Vec::new();
    };

    let mut core_masks: Vec<usize> = Vec::new();
    let mut l3_slices: Vec<(usize, u32)> = Vec::new();

    for e in &entries {
        match e.relationship {
            RELATION_PROCESSOR_CORE => core_masks.push(e.processor_mask),
            RELATION_CACHE => {
                let level = (e.payload0 & 0xFF) as u32;
                let size_bytes = ((e.payload0 >> 32) & 0xFFFF_FFFF) as u32;
                let cache_type = (e.payload1 & 0xFFFF_FFFF) as u32;
                if level == 3 && cache_type == CACHE_UNIFIED {
                    l3_slices.push((e.processor_mask, size_bytes / 1024));
                }
            }
            _ => {}
        }
    }

    // GetLogicalProcessorInformation lists cores in LP order; sort defensively so
    // core index == position in the returned vec.
    core_masks.sort_unstable();

    core_masks
        .into_iter()
        .map(|mask| {
            let slice = l3_slices.iter().find(|(m, _)| (m & mask) != 0);
            let (l3_kb, l3_mask) = match slice {
                Some((m, kb)) => (*kb, *m),
                None => (0, 0),
            };
            WinCoreInfo { l3_kb, l3_mask }
        })
        .collect()
}

/// Count physical cores via GetLogicalProcessorInformation (RelationProcessorCore).
fn detect_physical_core_count() -> u32 {
    let cores = detect_cores();
    if !cores.is_empty() {
        return cores.len() as u32;
    }
    smt_heuristic_core_count()
}

/// Build the per-core (core, ccd, ccx) placement table.
///
/// CCD membership is taken from the L3 slice each core reports into, which is
/// exact instead of guessed: on a 9955HX3D the two slices are 96 MB (3D V-Cache
/// CCD) and 32 MB, and Windows tags every core with the slice it belongs to.
/// When the L3 information is unavailable we fall back to the classic 8
/// cores-per-CCD arithmetic used by every Ryzen desktop/mobile HX part.
pub fn get_core_layout() -> Vec<CorePlacement> {
    let cores = detect_cores();
    // A single L3 slice is a valid answer too: a 1-CCD part (9800X3D, 9700X,
    // Strix Point / Strix Halo APUs) reports exactly one slice, and the slice
    // count alone must not push us onto the 8-cores-per-CCD arithmetic, which
    // would invent a second CCD on any 1-CCD part with more than 8 cores.
    let l3_grouping_usable = !cores.is_empty() && cores.iter().all(|c| c.l3_mask != 0);

    // Order the L3 slices by the smallest core index inside them so CCD 0 is
    // always the one containing core 0, matching what Ryzen Master reports.
    let mut slice_order: Vec<usize> = Vec::new();
    if l3_grouping_usable {
        let mut seen = std::collections::BTreeSet::new();
        for c in &cores {
            if seen.insert(c.l3_mask) {
                slice_order.push(c.l3_mask);
            }
        }
    }

    let is_zen3_plus = {
        let slot = SMU_BRIDGE.get();
        slot.and_then(|m| m.lock().ok())
            .and_then(|g| g.as_ref().map(|b| b.smu_type))
            .map(|t| matches!(t, SmuType::Cpu3 | SmuType::Cpu4))
            .unwrap_or(true)
    };

    let core_count = if cores.is_empty() {
        let fallback = smt_heuristic_core_count();
        if fallback == 0 {
            return Vec::new();
        }
        fallback
    } else {
        cores.len() as u32
    };

    (0..core_count)
        .map(|core| {
            let info = cores.get(core as usize);
            let ccd = match info {
                Some(c) if l3_grouping_usable => slice_order
                    .iter()
                    .position(|m| *m == c.l3_mask)
                    .unwrap_or((core / 8) as usize) as u32,
                _ => core / 8,
            };
            let ccx = if is_zen3_plus { ccd } else { core / 4 };
            CorePlacement {
                core,
                ccd,
                ccx,
                l3_kb: info.map(|c| c.l3_kb).unwrap_or(0),
            }
        })
        .collect()
}

// ---- Public API ----

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmuInfo {
    pub supported: bool,
    pub code_name: String,
    /// Marketing name read from the CPUID brand string.
    pub cpu_name: String,
    pub smu_type: u32,
    pub smu_version: u32,
    pub pm_table_version: u32,
    pub pm_table_size: u32,
    pub dram_base: u64,
    pub physical_core_count: u32,
    pub curve_optimizer_supported: bool,
    pub pbo_scalar_supported: bool,
    pub fmax_supported: bool,
}

/// One physical core's topological placement (which CCD/CCX it belongs to).
/// Mirrors ZenStates-Core's `CoreListItem` / `ApobCoreMapCore`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct CorePlacement {
    /// Logical (OS-visible) core index, 0-based.
    pub core: u32,
    /// Physical CCD this core lives on.
    pub ccd: u32,
    /// Physical CCX within the CCD.
    pub ccx: u32,
    /// Size of the L3 slice this core shares, in KB (0 when unknown).
    /// A large value on a dual-CCD part marks the 3D V-Cache CCD.
    pub l3_kb: u32,
}

impl SmuBridge {
    fn summary(&self) -> SmuInfo {
        SmuInfo {
            supported: self.smu_type != SmuType::Unsupported,
            code_name: display_code_name(self.code_name),
            cpu_name: cpuid_brand_string(),
            smu_type: smu_type_u32(self.smu_type),
            smu_version: self.smu_version,
            pm_table_version: self.pm_table_version,
            pm_table_size: self.pm_table_size,
            dram_base: self.dram_base,
            physical_core_count: detect_physical_core_count(),
            curve_optimizer_supported: self.commands.set_dldo_psm_margin != 0
                || self.commands.set_all_dldo_psm_margin != 0
                || self.commands.set_overclock_cpu_vid != 0,
            pbo_scalar_supported: self.commands.set_pbo_scalar != 0,
            fmax_supported: self.commands.get_boost_limit_frequency != 0
                || self.commands.set_boost_limit_all_core != 0,
        }
    }
}

/// Human-readable code name. `Debug` alone prints `FireRange`, but the SKU
/// family is called "Fire Range".
fn display_code_name(code: CpuCodeName) -> String {
    match code {
        CpuCodeName::FireRange => "Fire Range".to_string(),
        other => format!("{:?}", other),
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

    let blob: &[u8] = include_bytes!("../RyzenSMU.bin");
    let pawn = PawnIo::load_module_from_bytes(blob)?;

    let driver_code = {
        match pawn.execute(FN_GET_CODE_NAME, &[], 1) {
            Ok(out) => {
                // Driver returns the code name as a signed 32-bit int (0xFFFFFFFF = -1 = Undefined).
                CpuCodeName::from_i64((out[0] & 0xFFFF_FFFF) as i32 as i64)
            }
            Err(e) => {
                // Never let an unknown-code-name IOCTL failure sink the whole bridge:
                // CPUID can identify the part on its own.
                eprintln!("[smu] ioctl_get_code_name failed: {e}");
                CpuCodeName::Undefined
            }
        }
    };

    // CPUID wins over the driver. RyzenSMU.bin collapses several SKUs into one
    // name — family 1Ah model 44h (Fire Range: 9955HX/9955HX3D) comes back as
    // GraniteRidge because it is the mobile variant of that die — and older blob
    // builds predate newer parts entirely. Only fall back to the driver value
    // for platforms the CPUID table does not cover (Zen1…Zen3).
    let cpuid_code = detect_code_name_from_cpuid();
    let code_name = if cpuid_code != CpuCodeName::Undefined {
        if cpuid_code != driver_code {
            eprintln!(
                "[smu] code name from CPUID: {:?} (driver said {:?})",
                cpuid_code, driver_code
            );
        }
        cpuid_code
    } else {
        driver_code
    };

    // Still nothing? Probe the RSMU directly rather than refusing to start.
    let (mut smu_type, mut commands) = resolve_commands(code_name);
    if smu_type == SmuType::Unsupported {
        // Last resort: family 19h/1Ah all speak the same RSMU dialect, so try the
        // Zen4/Zen5 table rather than refusing to start on an unrecognised SKU.
        if let Some((family, model, _)) = cpuid_identity() {
            if family == 0x19 || family == 0x1A {
                eprintln!(
                    "[smu] unsupported code name {:?} (family {:#x} model {:#x}), using generic Zen4/5 RSMU table",
                    code_name, family, model
                );
                smu_type = SmuType::Cpu4;
                commands = zen45_commands();
            }
        }
    }
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

/// Read the Curve Optimizer margin currently applied to a single core.
///
/// Uses the RSMU `GetDldoPsmMargin` mailbox command. The SMU echoes back the
/// same 16-bit encoding used on write, so a negative margin arrives as
/// `(0x100000 + margin) & 0xFFFF`, which decodes cleanly through `i16`.
pub fn get_co_single_core(core: u32, ccd: u32, ccx: u32) -> Result<i32, String> {
    with_bridge(|b| {
        if b.commands.get_dldo_psm_margin == 0 {
            return Err("Reading Curve Optimizer is not supported on this CPU".into());
        }
        let mask = make_core_mask(core, ccd, ccx, is_family_gt_17h(b.smu_type));
        let args = [mask, 0, 0, 0, 0, 0];
        let out = b.send_rsmu_command(b.commands.get_dldo_psm_margin, &args)?;
        let raw = (out[0] & 0xFFFF) as u16;
        let margin = raw as i16 as i32;
        // Reject implausible answers (unsupported slot / firmware noise) instead
        // of surfacing a bogus offset in the UI.
        if (-50..=50).contains(&margin) {
            Ok(margin)
        } else {
            Ok(0)
        }
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
