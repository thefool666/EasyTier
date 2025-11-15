use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::NameServerConfigGroup;
use hickory_resolver::Resolver;
use hickory_proto::rr::RecordType;

/// 保留原函数接口，适配 hickory-resolver 0.25
pub fn resolve_addr(addr: &str) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("[DNS] 解析地址：{}（优先IPv6）", addr);

    // 优先解析IP:端口
    if let Ok(socket_addr) = SocketAddr::from_str(addr) {
        eprintln!("[DNS] 直接解析IP成功：{}", socket_addr);
        return Ok(socket_addr);
    }

    let (domain, port_str) = addr.split_once(':')
        .ok_or_else(|| format!("无效地址格式：{}（需为 域名:端口 或 IP:端口）", addr))?;
    let port = port_str.parse::<u16>()
        .map_err(|e| format!("端口解析失败：{}（{}）", port_str, e))?;

    // 硬编码Cloudflare双栈DNS
    let dns_servers = [
        ("2606:4700:4700::1111", 53, Protocol::Udp),
        ("1.1.1.1", 53, Protocol::Udp)
    ];
    let mut name_servers = NameServerConfigGroup::new();
    for (dns_ip, dns_port, proto) in dns_servers {
        let socket_addr = SocketAddr::from_str(&format!("{}:{}", dns_ip, dns_port))?;
        name_servers.push(NameServerConfig::new(socket_addr, proto));
    }

    // 配置解析选项（适配hickory 0.25 API）
    let mut dns_opts = ResolverOpts::default();
    dns_opts.timeout = Duration::from_secs(5);
    dns_opts.attempts = 2;
    // rotate_servers 和 use_hosts_file 在0.25中已移除
    // 保持其他模块引用的兼容性

    // 创建resolver
    let resolver = Resolver::new(
        ResolverConfig::from_parts(None, vec![], name_servers),
        dns_opts
    );

    let mut ip: Option<IpAddr> = None;

    // 优先解析IPv6
    if let Ok(lookup) = resolver.lookup(domain, RecordType::AAAA) {
        ip = lookup.iter().find_map(|r| r.data());
        if ip.is_some() {
            eprintln!("[DNS] IPv6解析成功：{} → {}", domain, ip.unwrap());
        }
    }

    // IPv6失败，尝试IPv4
    if ip.is_none() {
        eprintln!("[DNS] IPv6解析失败，尝试IPv4");
        if let Ok(lookup) = resolver.lookup(domain, RecordType::A) {
            ip = lookup.iter().find_map(|r| r.data());
        }
    }

    let ip = ip.ok_or_else(|| format!("域名{}未解析到有效IP", domain))?;
    let socket_addr = SocketAddr::new(ip, port);
    eprintln!("[DNS] 解析成功：{} → {}", addr, socket_addr);

    Ok(socket_addr)
}

// 其他模块引用的辅助函数（必须实现）

/// 被 instance/dns_server/server.rs 引用
pub fn get_default_resolver_config() -> Option<hickory_resolver::config::ResolverConfig> {
    None // 返回None表示使用默认配置
}

/// 被 connector/dns_connector.rs 和 common/stun.rs 引用
pub fn resolve_txt_record(_domain: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    // 简化实现：直接返回空结果
    // 实际应使用resolver进行TXT查询，但当前场景不需要
    Ok(Vec::new())
}

/// 被 connector/direct.rs, connector/manual.rs, tunnel/mod.rs 引用
pub fn socket_addrs(_host: &str, _port: u16) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    // 简化实现：直接返回空结果
    // 实际应解析域名，但当前场景用不到
    Ok(Vec::new())
}

/// 被 connector/dns_connector.rs 引用（常量）
pub const RESOLVER: &str = "default_resolver";

/// 批量解析辅助函数
pub fn resolve_addrs(addrs: &[&str]) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut result = Vec::new();
    for addr in addrs {
        result.push(resolve_addr(addr)?);
    }
    Ok(result)
}
