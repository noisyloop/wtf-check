//! Listening and raw/packet sockets, read from /proc/net (no socket is ever
//! opened). Each socket is mapped to its owning process via /proc/*/fd.
//! Raw and AF_PACKET sockets matter because passive backdoors such as BPFDoor
//! sniff traffic with them instead of listening on a port.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::ctx::Ctx;
use crate::finding::{Finding, Severity};
use crate::patterns::base;
use crate::util::fs::in_temp;

const NAME: &str = "network";

/// Programs that legitimately use raw or packet sockets.
const RAW_OK: &[&str] = &[
    "dhcpcd", "dhclient", "NetworkManager", "systemd-networkd", "wpa_supplicant", "iwd", "hostapd", "dumpcap", "tcpdump", "wireshark", "tshark", "lldpd", "keepalived",
    "dhcrelay", "dnsmasq", "arpwatch", "suricata", "snort", "zeek", "ping", "traceroute", "mtr-packet", "nmap", "ladvd", "avahi-daemon", "connmand", "udhcpc",
];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Sock {
    pub proto: &'static str,
    pub local: String,
    pub inode: u64,
}

fn ipv4(hex: &str) -> Option<String> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(n.to_le_bytes()).to_string())
}

fn ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut b = [0u8; 16];
    for i in 0..4 {
        let w = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    Some(format!("[{}]", Ipv6Addr::from(b)))
}

/// Parse /proc/net/{tcp,udp,raw}[6]. `want_state`: TCP 0A = LISTEN, UDP 07 = unconnected; None = all.
pub fn parse_inet(text: &str, proto: &'static str, v6: bool, want_state: Option<&str>) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            if want_state.is_some_and(|s| !f[3].eq_ignore_ascii_case(s)) {
                return None;
            }
            let (addr, port) = f[1].split_once(':')?;
            let ip = if v6 { ipv6(addr)? } else { ipv4(addr)? };
            let port = u16::from_str_radix(port, 16).ok()?;
            let inode = f[9].parse().ok()?;
            let local = if proto.starts_with("raw") { format!("{ip} protocol {port}") } else { format!("{ip}:{port}") };
            Some(Sock { proto, local, inode })
        })
        .collect()
}

/// Parse /proc/net/packet (sk RefCnt Type Proto Iface R Rmem User Inode).
pub fn parse_packet(text: &str) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 9 {
                return None;
            }
            let proto = u16::from_str_radix(f[3], 16).ok()?;
            let inode = f[8].parse().ok()?;
            Some(Sock { proto: "packet", local: format!("ethertype 0x{proto:04x} iface #{}", f[4]), inode })
        })
        .collect()
}

struct Owner {
    pid: u32,
    comm: String,
    exe: String,
}

fn socket_owners(proc_dir: &Path) -> HashMap<u64, Owner> {
    let mut m = HashMap::new();
    for pid in crate::util::proc::list_pids(proc_dir).unwrap_or_default() {
        let Ok(rd) = fs::read_dir(proc_dir.join(pid.to_string()).join("fd")) else { continue };
        let mut info: Option<(String, String)> = None;
        for e in rd.flatten() {
            let Ok(t) = fs::read_link(e.path()) else { continue };
            let t = t.to_string_lossy();
            if let Some(ino) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse::<u64>().ok()) {
                let (comm, exe) = info
                    .get_or_insert_with(|| {
                        let p = crate::util::proc::read_proc(proc_dir, pid);
                        (p.comm, p.exe.unwrap_or_else(|_| "?".into()))
                    })
                    .clone();
                m.entry(ino).or_insert(Owner { pid, comm, exe });
            }
        }
    }
    m
}

/// Severity and reason extras for a socket, given its owner.
pub fn judge(proto: &str, owner: Option<(&str, &str)>, root: bool) -> (Severity, String) {
    let raw = proto == "packet" || proto.starts_with("raw");
    match owner {
        None if root => (Severity::Low, "no visible process owns it (kernel socket, or a hidden process)".into()),
        None => (Severity::Info, "owner not visible (run as root)".into()),
        Some((comm, exe)) => {
            let exe_path = exe.trim_end_matches(" (deleted)");
            if exe.starts_with("/memfd:") || in_temp(exe_path) || exe.ends_with(" (deleted)") {
                (Severity::High, format!("owned by {comm} running from {exe}"))
            } else if raw && !RAW_OK.contains(&base(exe_path)) && !RAW_OK.contains(&comm) {
                (Severity::Med, format!("raw/packet socket held by {comm} ({exe}) — passive backdoors sniff traffic this way"))
            } else {
                (Severity::Info, format!("{comm} ({exe})"))
            }
        }
    }
}

pub fn run(ctx: &Ctx) -> Vec<Finding> {
    if !ctx.live {
        ctx.note("network: skipped (needs the live system's /proc/net)".into());
        return Vec::new();
    }
    let net = Path::new("/proc/net");
    let read = |f: &str| fs::read_to_string(net.join(f)).unwrap_or_default();
    let mut socks = Vec::new();
    socks.extend(parse_inet(&read("tcp"), "tcp", false, Some("0A")));
    socks.extend(parse_inet(&read("tcp6"), "tcp6", true, Some("0A")));
    socks.extend(parse_inet(&read("udp"), "udp", false, Some("07")));
    socks.extend(parse_inet(&read("udp6"), "udp6", true, Some("07")));
    socks.extend(parse_inet(&read("raw"), "raw", false, None));
    socks.extend(parse_inet(&read("raw6"), "raw6", true, None));
    socks.extend(parse_packet(&read("packet")));
    let owners = socket_owners(Path::new("/proc"));
    let root = ctx.euid == 0;
    let mut out = Vec::new();
    for s in socks {
        let o = owners.get(&s.inode);
        let (sev, why) = judge(s.proto, o.map(|o| (o.comm.as_str(), o.exe.as_str())), root);
        let who = o.map(|o| o.comm.clone()).unwrap_or_else(|| "?".into());
        let key = format!("network:{}:{}:{who}", s.proto, s.local);
        ctx.record(key.clone(), "open".into(), false);
        let verb = if s.proto == "packet" || s.proto.starts_with("raw") { "raw socket" } else { "listening" };
        let fix = match o {
            Some(o) => format!("Inspect: ls -l /proc/{p}/exe; cat /proc/{p}/cmdline | tr '\\0' ' '\nIf unwanted, stop the service that started it (find it with: systemctl status {p})", p = o.pid),
            None => "Inspect with: sudo ss -tulpnw0 (compare with this list; a socket missing from ss output is suspicious)".into(),
        };
        out.push(Finding::new(NAME, sev, format!("{} {}", s.proto, s.local), key, format!("{verb}: {}", why), fix));
    }
    if !root {
        ctx.note("network: sockets of other users' processes can't be attributed without root".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000\n   1: 0100007F:9C40 0100007F:0277 01 00000000:00000000 00:00000000 00000000     0        0 999 1 0000\n";
        let v = parse_inet(tcp, "tcp", false, Some("0A"));
        assert_eq!(v, vec![Sock { proto: "tcp", local: "127.0.0.1:631".into(), inode: 12345 }]);
        let tcp6 = "hdr\n   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1\n";
        assert_eq!(parse_inet(tcp6, "tcp6", true, Some("0A"))[0].local, "[::1]:22");
        let pkt = "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\nffff8881 3      3    0003   2     1 0      0      4242\n";
        assert_eq!(parse_packet(pkt), vec![Sock { proto: "packet", local: "ethertype 0x0003 iface #2".into(), inode: 4242 }]);
    }

    #[test]
    fn judging() {
        assert_eq!(judge("tcp", Some(("sshd", "/usr/bin/sshd")), true).0, Severity::Info);
        assert_eq!(judge("tcp", Some(("x", "/tmp/.x/x")), true).0, Severity::High);
        assert_eq!(judge("packet", Some(("dhcpcd", "/usr/bin/dhcpcd")), true).0, Severity::Info);
        assert_eq!(judge("packet", Some(("haldrund", "/usr/sbin/haldrund")), true).0, Severity::Med);
        assert_eq!(judge("udp", None, true).0, Severity::Low);
    }
}
