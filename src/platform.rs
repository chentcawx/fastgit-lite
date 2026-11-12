//! Windows platform glue: GUI subsystem, single instance, silent startup,
//! shutdown signals, parent-process watchdog and a few Win32 helpers.
//!
//! This module never allocates a console, never shows a dialog and never
//! requests UAC elevation. See `resources/app.manifest` and the crate-level
//! `#![windows_subsystem = "windows"]` in `main.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn shutdown_flag() -> &'static AtomicBool {
    &SHUTDOWN
}

pub fn is_shutting_down() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

#[derive(Debug, Clone, Default)]
pub struct Cli {
    pub command: Option<String>,
    pub parent_process_id: u32,
    pub udp_logger_port: Option<u16>,
    /// Arbitrary `Key=Value` overrides, e.g. `FastGithub.HttpProxyPort=38458`.
    pub overrides: Vec<(String, String)>,
}

pub fn parse_args() -> Cli {
    let mut cli = Cli::default();
    for arg in std::env::args().skip(1) {
        if ["start", "stop", "regen-ca", "renew-ca"]
            .iter()
            .any(|c| arg.eq_ignore_ascii_case(c))
        {
            cli.command = Some(arg.to_ascii_lowercase());
            continue;
        }
        if let Some((k, v)) = arg.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "parentprocessid" => cli.parent_process_id = v.trim().parse().unwrap_or(0),
                "udploggerport" => cli.udp_logger_port = v.trim().parse().ok(),
                _ => cli.overrides.push((k.trim().to_string(), v.trim().to_string())),
            }
        }
    }
    cli
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;

    pub type Handle = *mut c_void;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    pub struct SystemTime {
        pub year: u16,
        pub month: u16,
        pub day_of_week: u16,
        pub day: u16,
        pub hour: u16,
        pub minute: u16,
        pub second: u16,
        pub milliseconds: u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleFileNameW(module: Handle, buf: *mut u16, size: u32) -> u32;
        fn CreateMutexW(attrs: *mut c_void, initial_owner: i32, name: *const u16) -> Handle;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: Handle) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
        fn FreeConsole() -> i32;
        fn GetTickCount64() -> u64;
        fn GetLocalTime(out: *mut SystemTime);
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    #[link(name = "dnsapi")]
    extern "system" {
        fn DnsFlushResolverCache() -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
        SHUTDOWN.store(true, Ordering::SeqCst);
        1
    }

    pub fn init() {
        // A GUI-subsystem process has no console; this is a defensive no-op
        // for the case where one was inherited from a launcher.
        unsafe { FreeConsole() };
        unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
    }

    pub fn exe_dir() -> PathBuf {
        let mut buf = vec![0u16; 32_768];
        let len = unsafe { GetModuleFileNameW(ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 || len as usize >= buf.len() {
            return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        }
        buf.truncate(len as usize);
        let path = PathBuf::from(std::ffi::OsString::from_wide(&buf));
        path.parent().map(PathBuf::from).unwrap_or(path)
    }

    /// `Global\FastGithub`, matching the original single-instance mutex.
    /// The handle is intentionally leaked: it lives for the whole process.
    pub fn acquire_singleton() -> bool {
        let name = wide("Global\\FastGithub");
        let h = unsafe { CreateMutexW(ptr::null_mut(), 1, name.as_ptr()) };
        if h.is_null() {
            return false;
        }
        const ERROR_ALREADY_EXISTS: u32 = 183;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(h) };
            return false;
        }
        true
    }

    pub fn parent_exited(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const WAIT_OBJECT_0: u32 = 0;
        let h = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
        if h.is_null() {
            return true;
        }
        let state = unsafe { WaitForSingleObject(h, 0) };
        unsafe { CloseHandle(h) };
        state == WAIT_OBJECT_0
    }

    pub fn flush_dns_cache() {
        unsafe { DnsFlushResolverCache() };
    }

    pub fn tick_ms() -> u64 {
        unsafe { GetTickCount64() }
    }

    pub fn local_time() -> SystemTime {
        let mut t = SystemTime::default();
        unsafe { GetLocalTime(&mut t) };
        t
    }

    pub fn is_elevated() -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }

    pub fn create_hidden_process(_path: &str) -> bool {
        // Intentionally unused: the Rust rewrite never spawns helper processes.
        false
    }
}

#[cfg(not(windows))]
mod fallback {
    use super::*;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

    pub fn init() {}
    pub fn exe_dir() -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }
    pub fn acquire_singleton() -> bool {
        true
    }
    pub fn parent_exited(_pid: u32) -> bool {
        false
    }
    pub fn flush_dns_cache() {}
    pub fn tick_ms() -> u64 {
        START.get_or_init(Instant::now).elapsed().as_millis() as u64
    }
    pub fn local_time() -> (u32, u32, u32, u32, u32, u32) {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y as u32, m as u32, d as u32, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
    }
    pub fn is_elevated() -> bool {
        false
    }

    fn civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let mut y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = mp + if mp < 10 { 3 } else { -9 };
        y += if m <= 2 { 1 } else { 0 };
        (y, m, d)
    }
}

#[cfg(windows)]
pub use win::*;
#[cfg(not(windows))]
pub use fallback::*;

/// `YYYY-MM-DD HH:MM:SS.mmm` for log lines, without pulling in a date crate.
pub fn timestamp() -> String {
    #[cfg(windows)]
    {
        let t = local_time();
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            t.year, t.month, t.day, t.hour, t.minute, t.second, t.milliseconds
        )
    }
    #[cfg(not(windows))]
    {
        let (y, m, d, h, mi, s) = local_time();
        format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}.000")
    }
}

/// `YYYY-MM-DD` for the rolling log file name.
pub fn date_stamp() -> String {
    timestamp()[..10].to_string()
}
