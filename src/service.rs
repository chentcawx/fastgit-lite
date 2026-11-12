//! Windows service support (explicit `start` / `stop` commands only).
//!
//! The original installs itself as a Windows service via
//! `Microsoft.Extensions.Hosting.WindowsServices`. This rewrite implements the
//! SCM handshake natively so a service instance runs in Session 0 with no
//! console, no window and no interaction. Nothing is installed automatically.

use crate::logger;
use crate::platform::{self, Cli};
use std::path::PathBuf;

pub fn maybe_run_as_service(cli: &Cli) -> bool {
    let wants_service = std::env::args().any(|a| a == "--service" || a.eq_ignore_ascii_case("service"));
    if !wants_service { return false; }
    let _ = cli;
    #[cfg(windows)]
    {
        return win::dispatch();
    }
    #[cfg(not(windows))]
    {
        logger::warn("Windows 服务模式仅支持 Windows 平台");
        false
    }
}

pub fn handle_command(command: &str) {
    match command {
        "start" => install(),
        "stop" => uninstall(),
        _ => logger::warn(&format!("未知命令: {command}")),
    }
}

fn service_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p: PathBuf| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "fastgithub".into())
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    type Handle = *mut c_void;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }

    #[repr(C)]
    struct ServiceTableEntry {
        name: *mut u16,
        proc: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }

    const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
    const SERVICE_AUTO_START: u32 = 0x0000_0002;
    const SERVICE_ERROR_NORMAL: u32 = 0x0000_0001;
    const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
    const SERVICE_STOPPED: u32 = 0x0000_0001;
    const SERVICE_START_PENDING: u32 = 0x0000_0002;
    const SERVICE_STOP_PENDING: u32 = 0x0000_0003;
    const SERVICE_RUNNING: u32 = 0x0000_0004;
    const SERVICE_ACCEPT_STOP: u32 = 0x0000_0001;
    const NO_ERROR: u32 = 0;

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
        fn CreateServiceW(
            scm: Handle,
            name: *const u16,
            display: *const u16,
            access: u32,
            service_type: u32,
            start_type: u32,
            error_control: u32,
            binary_path: *const u16,
            load_order_group: *const u16,
            tag_id: *mut u32,
            dependencies: *const u16,
            service_start_name: *const u16,
            password: *const u16,
        ) -> Handle;
        fn OpenServiceW(scm: Handle, name: *const u16, access: u32) -> Handle;
        fn StartServiceW(service: Handle, argc: u32, argv: *const *const u16) -> i32;
        fn ControlService(service: Handle, control: u32, status: *mut ServiceStatus) -> i32;
        fn DeleteService(service: Handle) -> i32;
        fn CloseServiceHandle(handle: Handle) -> i32;
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntry) -> i32;
        fn RegisterServiceCtrlHandlerW(name: *const u16, handler: Option<unsafe extern "system" fn(u32)>) -> Handle;
        fn SetServiceStatus(handle: Handle, status: *const ServiceStatus) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    static STATUS_HANDLE: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

    unsafe extern "system" fn ctrl_handler(control: u32) {
        if control == SERVICE_CONTROL_STOP {
            let h = STATUS_HANDLE.load(std::sync::atomic::Ordering::Relaxed) as Handle;
            set_status(h, SERVICE_STOP_PENDING, NO_ERROR);
            platform::shutdown_flag().store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn set_status(handle: Handle, state: u32, code: u32) {
        if handle.is_null() { return; }
        let accepts = if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP } else { 0 };
        let s = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: state,
            controls_accepted: accepts,
            win32_exit_code: code,
            ..Default::default()
        };
        unsafe { SetServiceStatus(handle, &s) };
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = wide(&service_name());
        let h = RegisterServiceCtrlHandlerW(name.as_ptr(), Some(ctrl_handler));
        STATUS_HANDLE.store(h as isize, std::sync::atomic::Ordering::Relaxed);
        set_status(h, SERVICE_START_PENDING, NO_ERROR);
        set_status(h, SERVICE_RUNNING, NO_ERROR);
        crate::run_app(Cli::default());
        set_status(h, SERVICE_STOPPED, NO_ERROR);
    }

    pub fn dispatch() -> bool {
        // Leak the name: SERVICE_TABLE_ENTRY must stay valid for the process.
        let name: &'static mut [u16] = Box::leak(wide(&service_name()).into_boxed_slice());
        let table = [
            ServiceTableEntry { name: name.as_mut_ptr(), proc: Some(service_main) },
            ServiceTableEntry { name: ptr::null_mut(), proc: None },
        ];
        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok == 0 {
            logger::warn("未由服务控制管理器启动，回退为普通后台进程");
            return false;
        }
        true
    }

    pub(super) fn install_impl() {
        let name = wide(&service_name());
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("fastgithub.exe"));
        let binary = wide(&format!("\"{}\" --service", exe.display()));
        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
        if scm.is_null() {
            logger::error("安装服务失败：无法打开服务控制管理器（通常需要管理员权限，本程序不会触发 UAC）");
            return;
        }
        let mut service = unsafe { OpenServiceW(scm, name.as_ptr(), SERVICE_ALL_ACCESS) };
        if service.is_null() {
            service = unsafe {
                CreateServiceW(
                    scm,
                    name.as_ptr(),
                    name.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    binary.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                )
            };
        }
        if service.is_null() {
            logger::error("安装服务失败：CreateService 被拒绝（无管理员权限？）");
        } else {
            let started = unsafe { StartServiceW(service, 0, ptr::null()) };
            if started == 0 { logger::warn("服务已安装，但立即启动失败（可能已在运行）"); }
            else { logger::info("服务安装并启动成功"); }
            unsafe { CloseServiceHandle(service) };
        }
        unsafe { CloseServiceHandle(scm) };
    }

    pub(super) fn uninstall_impl() {
        let name = wide(&service_name());
        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
        if scm.is_null() {
            logger::error("卸载服务失败：无法打开服务控制管理器");
            return;
        }
        let service = unsafe { OpenServiceW(scm, name.as_ptr(), SERVICE_ALL_ACCESS) };
        if service.is_null() {
            logger::info("服务不存在，无需卸载");
        } else {
            let mut status = ServiceStatus::default();
            if status.current_state != SERVICE_STOPPED && status.current_state != SERVICE_STOP_PENDING {
                unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) };
            }
            let deleted = unsafe { DeleteService(service) };
            logger::info(&format!("服务删除{}", if deleted != 0 { "成功" } else { "失败" }));
            unsafe { CloseServiceHandle(service) };
        }
        unsafe { CloseServiceHandle(scm) };
    }
}

#[cfg(windows)]
fn install() { win::install_impl(); }
#[cfg(windows)]
fn uninstall() { win::uninstall_impl(); }

#[cfg(not(windows))]
fn install() { logger::warn("服务安装仅支持 Windows"); }
#[cfg(not(windows))]
fn uninstall() { logger::warn("服务卸载仅支持 Windows"); }
