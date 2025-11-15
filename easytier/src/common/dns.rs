use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::Resolver;  // ← 必须是 hickory，不是 trust_dns
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig};
use hickory_proto::rr::RecordType;

pub fn resolve_addr(addr: &str) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("[DNS] 解析地址：{}（优先IPv6）", addr);

    if let Ok(socket_addr) = SocketAddr::from_str(addr) {
        eprintln!("[DNS] 直接解析IP成功：{}", socket_addr);
        return Ok(socket_addr);
    }

    let (domain, port_str) = addr.split_once(':')
        .ok_or_else(|| format!("无效地址格式：{}（需为 域名:端口 或 IP:端口）", addr))?;
    let port = port_str.parse::<u16>()
        .map_err(|e| format!("端口解析失败：{}（{}）", port_str, e))?;

    let dns_servers = [
        ("2606:4700:4700::1111", 53),
        ("1.1.1.1", 53)
    ];
    let mut dns_config = ResolverConfig::new();
    for (dns_ip, dns_port) in dns_servers {
        dns_config.add_name_server(NameServerConfig::udp((dns_ip, dns_port).into()));
    }

    let mut dns_opts = ResolverOpts::default();
    dns_opts.timeout = Duration::from_secs(5);
    dns_opts.attempts = 2;
    dns_opts.rotate_servers = true;
    dns_opts.use_hosts_file = false;

    let resolver = Resolver::tokio(dns_config, dns_opts);

    let mut ip: Option<IpAddr> = None;

    if let Ok(lookup) = resolver.lookup(domain, RecordType::AAAA) {
        ip = lookup.iter().find_map(|r| r.data().map(|d| d.into()));
        if ip.is_some() {
            eprintln!("[DNS] IPv6解析成功：{} → {}", domain, ip.unwrap());
        }
    }

    if ip.is_none() {
        eprintln!("[DNS] IPv6解析失败，尝试IPv4");
        if let Ok(lookup) = resolver.lookup(domain, RecordType::A) {
            ip = lookup.iter().find_map(|r| r.data().map(|d| d.into()));
        }
    }

    let ip = ip.ok_or_else(|| format!("域名{}未解析到有效IP", domain))?;
    let socket_addr = SocketAddr::new(ip, port);
    eprintln!("[DNS] 解析成功：{} → {}", addr, socket_addr);

    Ok(socket_addr)
}

pub fn resolve_addrs(addrs: &[&str]) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut result = Vec::new();
    for addr in addrs {
        result.push(resolve_addr(addr)?);
    }
    Ok(result)
}
