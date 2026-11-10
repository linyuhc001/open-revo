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
