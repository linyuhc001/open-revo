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
    // Ensure the bridge is initialized first so we know the SMU generation.
    let _ = crate::system::smu::init_smu()?;
    Ok(crate::system::smu::get_core_layout())
}

#[tauri::command]
pub fn smu_set_co_single_core(request: CoSetRequest) -> Result<u32, String> {
    crate::system::smu::set_co_single_core(request.core, request.ccd, request.ccx, request.margin)
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
