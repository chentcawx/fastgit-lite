//! Minimal DNS wire codec (A / AAAA) and a blocking client.
//!
//! Behaviour mirrors `FastGithub.DomainResolve.DnsClient`: query A and AAAA,
//! reject loopback answers, honour record TTL. No external DNS crate is used so
//! the 32-bit build stays dependency-light.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, Copy)]
pub struct Answer {
    pub ip: IpAddr,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub raw_questions: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Encoding / decoding helpers
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    fn byte(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes([self.byte()?, self.byte()?]))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes([self.byte()?, self.byte()?, self.byte()?, self.byte()?]))
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    /// Advance past a possibly-compressed domain name.
    fn skip_name(&mut self) -> Option<()> {
        let mut jumps = 0;
        loop {
            let len = self.byte()?;
            if len == 0 { return Some(()); }
            if len & 0xC0 == 0xC0 {
                self.pos += 1;
                return Some(());
            }
            self.pos += len as usize;
            jumps += 1;
            if jumps > 64 { return None; }
        }
    }
    fn read_name(&mut self) -> Option<String> {
        let mut labels: Vec<String> = Vec::new();
        let mut jumps = 0;
        let mut end: Option<usize> = None;
        loop {
            let len = self.byte()?;
            if len == 0 { break; }
            if len & 0xC0 == 0xC0 {
                let hi = self.byte()? as u16;
                let ptr = (((len as u16) & 0x3F) << 8) | hi;
                if end.is_none() { end = Some(self.pos); }
                jumps += 1;
                if jumps > 16 { return None; }
                self.pos = ptr as usize;
                continue;
            }
            let bytes = self.take(len as usize)?;
            labels.push(String::from_utf8_lossy(bytes).to_string());
        }
        if let Some(e) = end { self.pos = e; }
        Some(labels.join("."))
    }
}

pub fn build_query(id: u16, domain: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1, standard query
    out.extend_from_slice(&1u16.to_be_bytes());     // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());     // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());     // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());     // ARCOUNT
    let trimmed = domain.trim_end_matches('.');
    for label in trimmed.split('.') {
        if label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS 标签过长"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Parse a DNS query packet (used by the local DNS listener).
pub fn parse_query(data: &[u8]) -> Option<Query> {
    let mut r = Reader::new(data);
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let _an = r.u16()?;
    let _ns = r.u16()?;
    let _ar = r.u16()?;
    let q_start = r.pos;
    let mut questions = Vec::new();
    for _ in 0..qd.min(16) {
        let name = r.read_name()?;
        let qtype = r.u16()?;
        let qclass = r.u16()?;
        questions.push(Question { name, qtype, qclass });
    }
    let q_end = r.pos;
    Some(Query {
        id,
        flags,
        questions,
        raw_questions: data.get(q_start..q_end)?.to_vec(),
    })
}

/// Build a DNS response containing one A/AAAA loopback record (TTL in seconds).
pub fn build_loopback_response(query: &Query, qtype: u16, ttl: u32) -> Option<Vec<u8>> {
    let q = query.questions.first()?;
    let mut out = Vec::with_capacity(64 + query.raw_questions.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, rcode=0
    out.extend_from_slice(&(query.questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query.raw_questions);
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer to question
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    if qtype == TYPE_A {
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    } else if qtype == TYPE_AAAA {
        out.extend_from_slice(&16u16.to_be_bytes());
        out.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    } else {
        return None;
    }
    let _ = q;
    Some(out)
}

/// Parse A/AAAA answers from a DNS response.
pub fn parse_response(data: &[u8]) -> Vec<Answer> {
    let mut r = Reader::new(data);
    let _id = match r.u16() { Some(v) => v, None => return Vec::new() };
    let flags = match r.u16() { Some(v) => v, None => return Vec::new() };
    if flags & 0x8000 == 0 || flags & 0x000F != 0 { return Vec::new(); }
    let qd = r.u16().unwrap_or(0);
    let an = r.u16().unwrap_or(0);
    let _ns = r.u16().unwrap_or(0);
    let _ar = r.u16().unwrap_or(0);
    for _ in 0..qd.min(32) {
        if r.skip_name().is_none() || r.u16().is_none() || r.u16().is_none() { return Vec::new(); }
    }
    let mut answers = Vec::new();
    for _ in 0..an.min(128) {
        if r.skip_name().is_none() { break; }
        let rtype = match r.u16() { Some(v) => v, None => break };
        let class = match r.u16() { Some(v) => v, None => break };
        let ttl = match r.u32() { Some(v) => v, None => break };
        let len = match r.u16() { Some(v) => v as usize, None => break };
        let rdata = match r.take(len) { Some(v) => v, None => break };
        if class != CLASS_IN { continue; }
        let ip = match rtype {
            TYPE_A if rdata.len() == 4 => IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            TYPE_AAAA if rdata.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => continue,
        };
        if ip.is_loopback() { continue; } // original explicitly rejects loopback answers
        answers.push(Answer { ip, ttl });
    }
    answers
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Query one DNS server. Port 53 prefers TCP (as the original does), other
/// ports prefer UDP; the other transport is used as a fallback.
pub fn query(server: SocketAddr, domain: &str, qtype: u16, timeout: Duration) -> io::Result<Vec<Answer>> {
    if server.port() == 53 {
        query_tcp(server, domain, qtype, timeout)
            .or_else(|_| query_udp(server, domain, qtype, timeout))
    } else {
        query_udp(server, domain, qtype, timeout)
            .or_else(|_| query_tcp(server, domain, qtype, timeout))
    }
}

fn query_tcp(server: SocketAddr, domain: &str, qtype: u16, timeout: Duration) -> io::Result<Vec<Answer>> {
    let mut stream = TcpStream::connect_timeout(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let pkt = build_query(rand_id(), domain, qtype)?;
    let len = (pkt.len() as u16).to_be_bytes();
    let mut framed = Vec::with_capacity(pkt.len() + 2);
    framed.extend_from_slice(&len);
    framed.extend_from_slice(&pkt);
    stream.write_all(&framed)?;
    let mut size = [0u8; 2];
    stream.read_exact(&mut size)?;
    let n = u16::from_be_bytes(size) as usize;
    if n == 0 || n > 65535 { return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS 响应长度异常")); }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(parse_response(&buf))
}

fn query_udp(server: SocketAddr, domain: &str, qtype: u16, timeout: Duration) -> io::Result<Vec<Answer>> {
    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let pkt = build_query(rand_id(), domain, qtype)?;
    sock.send_to(&pkt, server)?;
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf)?;
    Ok(parse_response(&buf[..n]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let pkt = build_query(0x1234, "api.github.com", TYPE_A).unwrap();
        let q = parse_query(&pkt).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.questions.len(), 1);
        assert_eq!(q.questions[0].name, "api.github.com");
        assert_eq!(q.questions[0].qtype, TYPE_A);
    }

    #[test]
    fn loopback_response_contains_127_0_0_1() {
        let q = parse_query(&build_query(7, "github.com", TYPE_A).unwrap()).unwrap();
        let r = build_loopback_response(&q, TYPE_A, 300).unwrap();
        assert_eq!(&r[0..2], &7u16.to_be_bytes());
        assert_eq!(r[3] & 0x0F, 0); // flags low byte: rcode = 0
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1); // ANCOUNT
        assert!(r.windows(4).any(|w| w == [127, 0, 0, 1]));
    }

    #[test]
    fn response_parser_extracts_a_record_and_rejects_loopback() {
        let q = parse_query(&build_query(9, "github.com", TYPE_A).unwrap()).unwrap();
        let mut r = build_loopback_response(&q, TYPE_A, 60).unwrap();
        // Replace rdata with a public IP; loopback answers must be discarded.
        let n = r.len();
        r[n - 4..].copy_from_slice(&[140, 82, 112, 3]);
        let answers = parse_response(&r);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].ip.to_string(), "140.82.112.3");
        assert_eq!(answers[0].ttl, 60);
        let loopback = build_loopback_response(&q, TYPE_A, 60).unwrap();
        assert!(parse_response(&loopback).is_empty());
    }
}

fn rand_id() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEED: AtomicU32 = AtomicU32::new(0x9E37_79B9);
    let mut x = SEED.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    SEED.store(x, Ordering::Relaxed);
    x as u16
}
