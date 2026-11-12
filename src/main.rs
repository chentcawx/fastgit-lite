// The shipped binary is a GUI-subsystem app (no console window).
// The test harness must keep the console subsystem so libtest can print and
// so the linker does not look for WinMain-style entry semantics.
#![cfg_attr(not(test), windows_subsystem = "windows")]
#![allow(dead_code)]

//! FastGithub 2.1.5 — Rust rewrite for Windows 10 32-bit (x86).
//!
//! Silent background operation:
//!  * `#![windows_subsystem = "windows"]` => no console window is created;
//!  * manifest is `asInvoker` => no UAC dialog;
//!  * no MessageBox / no prompt / no stdout-stderr output;
//!  * long-lived listener threads keep the process resident.

mod certs;
mod config;
mod dns;
mod logger;
mod platform;
mod proxy;
mod resolver;
mod servers;
mod service;
mod stats;
mod tls;
mod tls_sni;

use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub config: Arc<config::ConfigStore>,
    pub resolver: Arc<resolver::Resolver>,
    pub stats: Arc<stats::Stats>,
    pub certs: Option<Arc<certs::CertAuthority>>,
}

fn main() {
    platform::init();
    let cli = platform::parse_args();
    let root = platform::exe_dir();
    let _ = std::env::set_current_dir(&root);

    // Bootstrap logging before anything else can fail. Configuration may
    // subsequently reconfigure level / UDP sink via `logger::configure`.
    logger::init(&root, cli.udp_logger_port.unwrap_or(38457), false, "Information");

    // Windows service entry point (only reached with `--service`).
    if service::maybe_run_as_service(&cli) {
        return;
    }
    // Explicit `regen-ca` / `renew-ca`: rotate the local CA and exit. This is
    // a one-shot maintenance command; the process never touches the OS
    // certificate store (use scripts\install-ca.ps1 for that).
    if let Some(cmd) = cli.command.as_deref() {
        if cmd == "regen-ca" || cmd == "renew-ca" {
            let ca_dir = cli
                .overrides
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("FastGithub.Silent.Mitm.CaDir"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "cacert".to_string());
            match certs::regenerate(&root, &ca_dir) {
                Ok(dir) => logger::info(&format!(
                    "本地 CA 已轮换：{}；所有客户端必须重新导入新的 fastgithub.cer",
                    dir.display()
                )),
                Err(e) => logger::error(&format!("本地 CA 轮换失败: {e}")),
            }
            return;
        }
        service::handle_command(cmd);
        return;
    }

    run_app(cli);
}

pub fn run_app(cli: platform::Cli) {
    let root = platform::exe_dir();
    let _ = std::env::set_current_dir(&root);

    let config_store = match config::ConfigStore::load(&root, cli) {
        Ok(c) => c,
        Err(e) => {
            logger::error(&format!("配置加载失败，程序静默退出: {e}"));
            return;
        }
    };
    let cfg = config_store.current();
    logger::configure(
        cfg.udp_logger_port,
        cfg.silent.udp_log,
        cfg.silent.log_to_file,
        &cfg.silent.log_level,
    );

    if cfg.silent.single_instance && !platform::acquire_singleton() {
        logger::warn("系统已运行其它实例，本实例静默退出");
        return;
    }

    logger::info(&format!(
        "======[ FastGithub 启动完成，当前版本为 V{} ]======",
        env!("CARGO_PKG_VERSION")
    ));
    logger::info(&format!(
        "pid={} 32bit={} elevated={} mode={}",
        std::process::id(),
        cfg!(target_pointer_width = "32"),
        platform::is_elevated(),
        cfg.silent.mode
    ));
    if platform::is_elevated() {
        logger::warn("当前以管理员权限运行；本程序不会主动修改 hosts、注册表或证书存储");
    }

    let resolver = resolver::Resolver::new(config_store.clone(), &root);
    let stats = Arc::new(stats::Stats::default());
    let certs = if cfg.silent.is_mitm() {
        match certs::CertAuthority::load(&root, &cfg.silent.mitm.ca_dir) {
            Ok(c) => Some(c),
            Err(e) => {
                logger::error(&format!("本地 CA 初始化失败，HTTPS 降级为透传: {e}"));
                None
            }
        }
    } else {
        None
    };
    let state = Arc::new(AppState {
        config: config_store.clone(),
        resolver: resolver.clone(),
        stats,
        certs,
    });

    config_store.start_watcher(cfg.silent.watch_config);
    resolver.start();
    servers::start_all(state);

    let parent_pid = cfg.parent_process_id;
    while !platform::is_shutting_down() {
        if parent_pid > 0 && platform::parent_exited(parent_pid) {
            logger::info(&format!("父进程 {parent_pid} 已退出，主动关闭"));
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    platform::shutdown_flag().store(true, std::sync::atomic::Ordering::SeqCst);
    logger::info("FastGithub 已停止");
}
