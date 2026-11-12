//! 5-second sliding-window flow statistics, exposed as `/flowStatistics`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::platform;

const WINDOW_MS: u64 = 5_000;

#[derive(Debug, Default)]
struct Window {
    items: VecDeque<(u64, u64)>, // (tick_ms, bytes)
}

impl Window {
    fn push(&mut self, tick: u64, n: u64) {
        self.clean(tick);
        self.items.push_back((tick, n));
    }
    fn clean(&mut self, now: u64) {
        while let Some((t, _)) = self.items.front() {
            if now.saturating_sub(*t) > WINDOW_MS {
                self.items.pop_front();
            } else {
                break;
            }
        }
    }
    fn rate(&mut self, now: u64) -> f64 {
        self.clean(now);
        let sum: u64 = self.items.iter().map(|(_, n)| *n).sum();
        sum as f64 / 5.0
    }
}

pub struct Stats {
    total_read: AtomicU64,
    total_write: AtomicU64,
    reads: Mutex<Window>,
    writes: Mutex<Window>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_read: AtomicU64::new(0),
            total_write: AtomicU64::new(0),
            reads: Mutex::new(Window::default()),
            writes: Mutex::new(Window::default()),
        }
    }
}

impl Stats {
    pub fn on_flow(&self, is_read: bool, n: usize) {
        if n == 0 { return; }
        let tick = platform::tick_ms();
        let amount = n as u64;
        if is_read {
            self.total_read.fetch_add(amount, Ordering::Relaxed);
            if let Ok(mut w) = self.reads.lock() { w.push(tick, amount); }
        } else {
            self.total_write.fetch_add(amount, Ordering::Relaxed);
            if let Ok(mut w) = self.writes.lock() { w.push(tick, amount); }
        }
    }

    pub fn json(&self) -> String {
        let now = platform::tick_ms();
        let read_rate = self.reads.lock().map(|mut w| w.rate(now)).unwrap_or(0.0);
        let write_rate = self.writes.lock().map(|mut w| w.rate(now)).unwrap_or(0.0);
        serde_json::json!({
            "totalRead": self.total_read.load(Ordering::Relaxed),
            "totalWrite": self.total_write.load(Ordering::Relaxed),
            "readRate": read_rate,
            "writeRate": write_rate
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_direct_responses_and_reports_rates() {
        let s = Stats::default();
        let empty: serde_json::Value = serde_json::from_str(&s.json()).unwrap();
        assert_eq!(empty["totalRead"], 0);
        assert_eq!(empty["totalWrite"], 0);

        // Client-bound bytes (PAC / Response / error responses) and
        // upstream-bound bytes are accounted in separate counters.
        s.on_flow(true, 250);
        s.on_flow(false, 80);
        s.on_flow(true, 50);
        let j: serde_json::Value = serde_json::from_str(&s.json()).unwrap();
        assert_eq!(j["totalRead"], 300);
        assert_eq!(j["totalWrite"], 80);
        assert_eq!(j["readRate"].as_f64().unwrap(), 60.0); // 300 bytes / 5s
        assert_eq!(j["writeRate"].as_f64().unwrap(), 16.0); // 80 bytes / 5s
        assert!(j.get("totalRead").is_some() && j.get("totalWrite").is_some()
            && j.get("readRate").is_some() && j.get("writeRate").is_some());
    }

    #[test]
    fn zero_length_flow_is_ignored() {
        let s = Stats::default();
        s.on_flow(true, 0);
        let j: serde_json::Value = serde_json::from_str(&s.json()).unwrap();
        assert_eq!(j["totalRead"], 0);
        assert_eq!(j["readRate"].as_f64().unwrap(), 0.0);
    }
}
