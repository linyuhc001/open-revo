// Windows-specific helpers: job-object-tied child processes, silent console
// spawn, WinINET system proxy (per-user registry + refresh broadcast).

use std::os::windows::process::CommandExt;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

/// Sendable wrapper for a child-process HANDLE. The raw pointer is only ever
/// used on the service's own threads, but `thread::spawn` needs `State` to be
/// `Send`, so the handle has to opt in explicitly.
pub struct CoreHandle(pub HANDLE);
unsafe impl Send for CoreHandle {}

/// Spawn silently (no console window) and tie the child to a job object that
/// kills it when our own process dies — mirrors what v2rayN's
/// WindowsJobService does so xray.exe never outlives the plugin service.
/// The child starts suspended so the job assignment can never race a grandchild.
pub fn spawn_tracked(cmd: &str, args: &[&str], workdir: Option<&std::path::Path>) -> Result<HANDLE, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let mut cmdline = cmd.to_string();
    for a in args {
        cmdline.push(' ');
        cmdline.push_str(a);
    }
    let mut wcmd: Vec<u16> = OsStr::new(&cmdline).encode_wide().chain([0]).collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let cwd: std::path::PathBuf = match workdir {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().map_err(|e| e.to_string())?,
    };
    let cwd_w: Vec<u16> = OsStr::new(&cwd).encode_wide().chain([0]).collect();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            wcmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            false as i32,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            std::ptr::null(),
            cwd_w.as_ptr(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(format!("CreateProcessW 失败: {}", unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }

    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job != std::ptr::null_mut() {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as _, std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32);
            AssignProcessToJobObject(job, pi.hProcess);
        }
    }
    unsafe {
        ResumeThread(pi.hThread);
        windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
    }
    // Leak the (job, process) handle pair so the kernel handles stay valid for
    // the child's lifetime; TerminateProcess via kill() is the explicit path.
    std::mem::forget(Box::new((job, pi.hProcess)));
    Ok(pi.hProcess)
}

pub fn is_running(handle: HANDLE) -> bool {
    let mut code: u32 = 0;
    unsafe {
        if GetExitCodeProcess(handle, &mut code) != 0 && code != 259 {
            return false;
        }
    }
    true
}

pub fn kill(handle: HANDLE) {
    unsafe {
        TerminateProcess(handle, 1);
        WaitForSingleObject(handle, 3000);
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
}

/// Run a program and capture stdout (used for `xray.exe version`).
pub fn capture_output(exe: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("无法执行 {exe}: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------- system proxy (WinINET, per-user) ----------

const SUBKEY: &[u16] = &utf16(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings");

const fn utf16(s: &str) -> [u16; 128] {
    // compile-time-ish helper: build a padded wide buffer
    let mut out = [0u16; 128];
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // input is ASCII-only for these constants
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

fn open_key(write: bool) -> Result<HANDLE, String> {
    let mut key: HANDLE = std::ptr::null_mut();
    let rc = unsafe {
        RegOpenKeyExW(HKEY_CURRENT_USER, SUBKEY.as_ptr(), 0, if write { KEY_SET_VALUE | KEY_READ } else { KEY_READ }, &mut key)
    };
    if rc != 0 {
        return Err(format!("RegOpenKeyExW rc={rc}"));
    }
    Ok(key)
}

fn set_dword(key: HANDLE, name: &str, v: u32) -> Result<(), String> {
    let n = wide(name);
    let rc = unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_DWORD, &v as *const u32 as _, 4) };
    if rc != 0 { return Err(format!("RegSetValueExW({name}) rc={rc}")); }
    Ok(())
}

fn set_str(key: HANDLE, name: &str, v: &str) -> Result<(), String> {
    let n = wide(name);
    let data = wide(v);
    let bytes = (data.len() * 2) as u32;
    let rc = unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_SZ, data.as_ptr() as _, bytes) };
    if rc != 0 { return Err(format!("RegSetValueExW({name}) rc={rc}")); }
    Ok(())
}

fn get_dword(key: HANDLE, name: &str) -> Option<u32> {
    let n = wide(name);
    let mut v: u32 = 0;
    let mut size: u32 = 4;
    let mut typ: u32 = 0;
    let rc = unsafe { RegQueryValueExW(key, n.as_ptr(), std::ptr::null(), &mut typ, &mut v as *mut u32 as _, &mut size) };
    if rc == 0 && typ == REG_DWORD { Some(v) } else { None }
}

fn get_str(key: HANDLE, name: &str) -> Option<String> {
    let n = wide(name);
    let mut buf = [0u16; 512];
    let mut size: u32 = (buf.len() * 2) as u32;
    let mut typ: u32 = 0;
    let rc = unsafe { RegQueryValueExW(key, n.as_ptr(), std::ptr::null(), &mut typ, buf.as_mut_ptr() as _, &mut size) };
    if rc == 0 && typ == REG_SZ {
        let len = (size as usize) / 2;
        let s = String::from_utf16_lossy(&buf[..len]);
        return Some(s.trim_end_matches('\0').into());
    }
    None
}

fn proxy_override() -> String {
    "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>".into()
}

pub fn set_system_proxy(on: bool, http_port: u16) -> Result<(), String> {
    let key = open_key(true)?;
    let r = if on {
        let a = set_dword(key, "ProxyEnable", 1);
        let b = set_str(key, "ProxyServer", &format!("127.0.0.1:{http_port}"));
        let c = set_str(key, "ProxyOverride", &proxy_override());
        a.and(b).and(c)
    } else {
        set_dword(key, "ProxyEnable", 0)
    };
    unsafe { RegCloseKey(key) };
    r?;
    refresh_wininet();
    Ok(())
}

pub fn system_proxy_state(http_port: u16) -> (bool, bool) {
    // (enabled, points at us)
    if let Ok(key) = open_key(false) {
        let enabled = get_dword(key, "ProxyEnable").unwrap_or(0) == 1;
        let server = get_str(key, "ProxyServer").unwrap_or_default();
        unsafe { RegCloseKey(key) };
        (enabled, server == format!("127.0.0.1:{http_port}"))
    } else {
        (false, false)
    }
}

fn refresh_wininet() {
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}
