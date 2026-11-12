//! Silent logging. Nothing is ever written to stdout/stderr and no UI is shown.
//!
//! Sinks (both optional, both failure-tolerant):
//! * rolling daily file `logs/log-YYYY-MM-DD.txt`
//! * UDP datagram to 127.0.0.1:<UdpLoggerPort> (legacy UI log sink compatibility)

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::platform;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Debug => "DBG",
            Level::Info => "INF",
            Level::Warn => "WRN",
            Level::Error => "ERR",
        }
    }
    fn from_text(s: &str) -> Level {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Level::Debug,
            "warn" | "warning" => Level::Warn,
            "error" => Level::Error,
            _ => Level::Info,
        }
    }
}

struct Logger {
    dir: PathBuf,
    min_level: AtomicU8,
    file_enabled: AtomicBool,
    udp: Mutex<Option<UdpSocket>>,
    file: Mutex<Option<File>>,
    date: Mutex<String>,
}

static LOG: OnceLock<Logger> = OnceLock::new();

pub fn init(root: &Path, udp_port: u16, udp_enabled: bool, level_text: &str) {
    let dir = root.join("logs");
    let _ = fs::create_dir_all(&dir);
    let udp = if udp_enabled {
        UdpSocket::bind("127.0.0.1:0")
            .ok()
            .and_then(|s| s.connect(("127.0.0.1", udp_port)).map(|_| s).ok())
    } else {
        None
    };
    let _ = LOG.set(Logger {
        dir,
        min_level: AtomicU8::new(Level::from_text(level_text) as u8),
        file_enabled: AtomicBool::new(true),
        udp: Mutex::new(udp),
        file: Mutex::new(None),
        date: Mutex::new(String::new()),
    });
}

/// Apply settings that are only known after the configuration file was read.
pub fn configure(udp_port: u16, udp_enabled: bool, file_enabled: bool, level_text: &str) {
    let Some(logger) = LOG.get() else { return };
    logger.min_level.store(Level::from_text(level_text) as u8, Ordering::Relaxed);
    logger.file_enabled.store(file_enabled, Ordering::Relaxed);
    let udp = if udp_enabled {
        UdpSocket::bind("127.0.0.1:0")
            .ok()
            .and_then(|s| s.connect(("127.0.0.1", udp_port)).map(|_| s).ok())
    } else {
        None
    };
    if let Ok(mut guard) = logger.udp.lock() { *guard = udp; }
}

pub fn set_level(level_text: &str) {
    if let Some(l) = LOG.get() {
        l.min_level.store(Level::from_text(level_text) as u8, Ordering::Relaxed);
    }
}

pub fn debug(msg: &str) { write(Level::Debug, msg); }
pub fn info(msg: &str) { write(Level::Info, msg); }
pub fn warn(msg: &str) { write(Level::Warn, msg); }
pub fn error(msg: &str) { write(Level::Error, msg); }

fn write(level: Level, msg: &str) {
    let Some(logger) = LOG.get() else { return };
    if (level as u8) < logger.min_level.load(Ordering::Relaxed) {
        return;
    }
    let ts = platform::timestamp();
    let line = format!("{ts} [{}] {}\n", level.label(), msg);

    // File sink: roll over at local midnight.
    if logger.file_enabled.load(Ordering::Relaxed) {
        let date = platform::date_stamp();
        if let Ok(mut guard) = logger.file.lock() {
            let mut roll = false;
            if let Ok(d) = logger.date.lock() {
                roll = d.as_str() != date;
            }
            if roll || guard.is_none() {
                *guard = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(logger.dir.join(format!("log-{date}.txt")))
                    .ok();
                if let Ok(mut d) = logger.date.lock() {
                    *d = date;
                }
            }
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
    }

    // UDP sink: one JSON line per event, matching the Serilog UDP sink shape
    // closely enough for a log viewer. Never blocks startup.
    if let Ok(guard) = logger.udp.lock() {
        if let Some(sock) = guard.as_ref() {
            let escaped = msg.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ");
            let json = format!(
                "{{\"Timestamp\":\"{ts}\",\"Level\":\"{}\",\"Message\":\"{escaped}\"}}",
                level.label()
            );
            let _ = sock.send(json.as_bytes());
        }
    }
}
