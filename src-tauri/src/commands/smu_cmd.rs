// OpenRevo - AMD Ryzen SMU / PBO IPC Commands
// Exposes the PawnIO-backed SMU bridge to the plugin frontend.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CoSetRequest {
    pub core: u32,
    pub ccd: u32,
    pub ccx: u32,
    pub margin: i32,
}

#[tauri::command]
pub fn smu_init() -> Result<crate::system::smu::SmuInfo, String> {
    crate::system::smu::init_smu()
}

#[tauri::command]
pub fn smu_get_core_layout() -> Result<Vec<crate::system::smu::CorePlacement>, String> {
    // Try to bring the bridge up first so the SMU generation is known, but do
    // NOT fail when it is unavailable: the physical-core topology is derived
    // from GetLogicalProcessorInformation and stays valid without the driver.
    let _ = crate::system::smu::init_smu();
    Ok(crate::system::smu::get_core_layout())
}

#[tauri::command]
pub fn smu_set_co_single_core(request: CoSetRequest) -> Result<u32, String> {
    crate::system::smu::set_co_single_core(request.core, request.ccd, request.ccx, request.margin)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoReadRequest {
    pub core: u32,
    pub ccd: u32,
    pub ccx: u32,
}

/// Read the Curve Optimizer margin currently applied to one core.
#[tauri::command]
pub fn smu_get_co_single_core(request: CoReadRequest) -> Result<i32, String> {
    crate::system::smu::get_co_single_core(request.core, request.ccd, request.ccx)
}

#[tauri::command]
pub fn smu_set_co_all_cores(margin: i32) -> Result<u32, String> {
    crate::system::smu::set_co_all_cores(margin)
}

#[tauri::command]
pub fn smu_set_pbo_scalar(scalar_x1000: u32) -> Result<u32, String> {
    crate::system::smu::set_pbo_scalar(scalar_x1000)
}

#[tauri::command]
pub fn smu_get_pbo_scalar() -> Result<u32, String> {
    crate::system::smu::get_pbo_scalar()
}

#[tauri::command]
pub fn smu_set_fmax(frequency_mhz: u32) -> Result<u32, String> {
    crate::system::smu::set_fmax(frequency_mhz)
}

#[tauri::command]
pub fn smu_get_fmax() -> Result<u32, String> {
    crate::system::smu::get_fmax()
}

// ---- PBO profile persistence ----

/// Where the user's last PBO profile lives.
/// Kept next to the app config (not inside the plugin folder) so reinstalling
/// or updating the plugin never wipes the user's tuning.
fn profile_path() -> std::path::PathBuf {
    crate::system::config::get_config_dir().join("pbo_tuner_profile.json")
}

/// Persist a PBO profile (opaque JSON produced by the plugin UI).
#[tauri::command]
pub fn smu_profile_save(content: String) -> Result<String, String> {
    // Reject anything that is not valid JSON so a malformed payload can never
    // leave an unreadable profile behind.
    serde_json::from_str::<serde_json::Value>(&content)
        .map_err(|e| format!("invalid profile JSON: {e}"))?;

    let path = profile_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

/// Load the persisted PBO profile. Returns an empty string when none exists.
#[tauri::command]
pub fn smu_profile_load() -> Result<String, String> {
    let path = profile_path();
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

/// Apply the saved profile at startup, but only when the user opted in.
///
/// The plugin page only runs while its tab is open, so "auto apply on boot" has
/// to live in the host: this is called from the setup hook on a background
/// thread after the kernel drivers are up. Every failure is reported as a
/// string, never as a panic — a broken profile must not affect app startup.
pub fn auto_apply_profile() -> Result<String, String> {
    let path = profile_path();
    if !path.exists() {
        return Ok("no profile saved".into());
    }

    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let profile: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("profile corrupt: {e}"))?;

    if profile.get("autoApply").and_then(|v| v.as_bool()) != Some(true) {
        return Ok("auto-apply is off for this profile".into());
    }

    let info = crate::system::smu::init_smu()?;
    if !info.curve_optimizer_supported {
        return Err(format!("{} does not expose Curve Optimizer", info.code_name));
    }

    let layout = crate::system::smu::get_core_layout();
    if layout.is_empty() {
        return Err("core topology unavailable".into());
    }

    let co = profile
        .get("co")
        .and_then(|v| v.as_object())
        .ok_or("profile has no core map")?;

    let (mut applied, mut failed) = (0usize, 0usize);
    for core in &layout {
        let Some(margin) = co
            .get(&core.core.to_string())
            .and_then(|v| v.as_i64())
        else {
            continue;
        };
        match crate::system::smu::set_co_single_core(
            core.core,
            core.ccd,
            core.ccx,
            margin as i32,
        ) {
            Ok(_) => applied += 1,
            Err(_) => failed += 1,
        }
    }

    if let Some(fmax) = profile.get("fmax").and_then(|v| v.as_i64()) {
        if fmax > 0 && info.fmax_supported {
            let _ = crate::system::smu::set_fmax(fmax as u32);
        }
    }
    if let Some(scalar) = profile.get("scalar").and_then(|v| v.as_i64()) {
        if scalar >= 1 && info.pbo_scalar_supported {
            let _ = crate::system::smu::set_pbo_scalar((scalar as u32) * 1000);
        }
    }

    Ok(format!("applied {applied} cores ({failed} failed)"))
}

/// Kick off the boot-time profile re-apply on a detached thread.
///
/// The spawn lives here because OpenRevo has two mutually exclusive entry points
/// (`run_slint_pure_daemon`, which is the default, and `run_tauri_runtime` for
/// `use_classic_webview`), and they share no setup closure. Hanging this off the
/// Tauri setup hook only silently skipped it on every default install. The delay
/// gives PawnIO and the SMU mailbox time to come up; failures are logged, never
/// propagated, so a broken profile can never affect startup.
pub fn spawn_auto_apply_on_boot() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(8));
        let outcome = match auto_apply_profile() {
            Ok(msg) => format!("ok: {msg}"),
            Err(e) => format!("skipped: {e}"),
        };
        crate::log_info!("PBO_AUTO", "profile auto-apply: {}", outcome);
        append_auto_apply_trace(&outcome);
    });
}

/// Append the auto-apply outcome to `pbo_auto_apply.log` in the config dir.
///
/// The default log level writes nothing to disk, so without this trace a silent
/// skip is indistinguishable from a working apply. Kept tiny and append-only.
fn append_auto_apply_trace(outcome: &str) {
    use std::io::Write;
    let path = crate::system::config::get_config_dir().join("pbo_auto_apply.log");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "[{ts}] {outcome}");
    }
}
