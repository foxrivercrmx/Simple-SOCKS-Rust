use std::env;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_PORT: u16 = 9050;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct Args {
    bind: String,
    port: u16,
}

fn print_help() {
    eprint!(
        "\
socks-proxy - no-auth SOCKS4/SOCKS5 proxy

Usage:
  socks-proxy [-b|--bind|--interface ADDR] [-p|--port PORT]

Defaults:
  --bind 127.0.0.1
  --port 9050
"
    );
}

fn parse_args() -> Args {
    let mut bind = DEFAULT_BIND.to_string();
    let mut port = DEFAULT_PORT;
    let mut argv = env::args().skip(1);

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-b" | "--bind" | "-i" | "--interface" => {
                bind = argv.next().unwrap_or_else(|| {
                    eprintln!("error: {arg} requires an address");
                    process::exit(2);
                });
            }
            "-p" | "--port" => {
                let raw = argv.next().unwrap_or_else(|| {
                    eprintln!("error: {arg} requires a port");
                    process::exit(2);
                });
                port = raw.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid port '{raw}'");
                    process::exit(2);
                });
            }
            other if other.starts_with("--bind=") => {
                bind = other[7..].to_string();
            }
            other if other.starts_with("--interface=") => {
                bind = other[12..].to_string();
            }
            other if other.starts_with("--port=") => {
                let raw = &other[7..];
                port = raw.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid port '{raw}'");
                    process::exit(2);
                });
            }
            other => {
                eprintln!("error: unknown argument '{other}'");
                print_help();
                process::exit(2);
            }
        }
    }

    Args { bind, port }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = parse_args();
    let listener = TcpListener::bind((args.bind.as_str(), args.port)).await?;
    eprintln!("listening on {}", listener.local_addr()?);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    let _ = handle_conn(stream).await;
                });
            }
            Err(err) if is_transient(&err) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

fn is_transient(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
    )
}

async fn handle_conn(mut client: TcpStream) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    let remote = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut client))
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "handshake timed out"))??;
    if let Some(mut remote) = remote {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    }
    Ok(())
}

async fn handshake(client: &mut TcpStream) -> io::Result<Option<TcpStream>> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    match head[0] {
        0x05 => socks5(client, head[1]).await,
        0x04 => socks4(client, head[1]).await,
        _ => Ok(None),
    }
}

async fn socks5(client: &mut TcpStream, nmethods: u8) -> io::Result<Option<TcpStream>> {
    let n = nmethods as usize;
    let mut methods = [0u8; 255];
    if n > 0 {
        client.read_exact(&mut methods[..n]).await?;
    }
    if n == 0 || !methods[..n].contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Ok(None);
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(None);
    }
    if req[1] != 0x01 {
        reply5(client, 0x07, None).await?;
        return Ok(None);
    }

    let target = match req[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            client.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Target::Ip(SocketAddr::from((ip, port)))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            client.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Target::Ip(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        0x03 => {
            let len = client.read_u8().await? as usize;
            let mut host = [0u8; 255];
            client.read_exact(&mut host[..len]).await?;
            let port = client.read_u16().await?;
            let name = std::str::from_utf8(&host[..len])
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            Target::Host(name.to_string(), port)
        }
        _ => {
            reply5(client, 0x08, None).await?;
            return Ok(None);
        }
    };

    match dial(target).await {
        Ok(remote) => {
            let bound = remote.local_addr().ok();
            reply5(client, 0x00, bound).await?;
            Ok(Some(remote))
        }
        Err(err) => {
            reply5(client, socks5_rep(&err), None).await?;
            Ok(None)
        }
    }
}

async fn socks4(client: &mut TcpStream, cmd: u8) -> io::Result<Option<TcpStream>> {
    let mut rest = [0u8; 6];
    client.read_exact(&mut rest).await?;
    skip_cstring(client).await?;

    if cmd != 0x01 {
        reply4(client, 0x5B, &rest).await?;
        return Ok(None);
    }

    let port = u16::from_be_bytes([rest[0], rest[1]]);
    let ip = Ipv4Addr::new(rest[2], rest[3], rest[4], rest[5]);
    let socks4a = rest[2] == 0 && rest[3] == 0 && rest[4] == 0 && rest[5] != 0;

    let target = if socks4a {
        let host = read_cstring(client).await?;
        Target::Host(host, port)
    } else {
        Target::Ip(SocketAddr::from((ip, port)))
    };

    match dial(target).await {
        Ok(remote) => {
            reply4(client, 0x5A, &rest).await?;
            Ok(Some(remote))
        }
        Err(_) => {
            reply4(client, 0x5B, &rest).await?;
            Ok(None)
        }
    }
}

enum Target {
    Ip(SocketAddr),
    Host(String, u16),
}

async fn dial(target: Target) -> io::Result<TcpStream> {
    let connect = async {
        match target {
            Target::Ip(addr) => TcpStream::connect(addr).await,
            Target::Host(host, port) => TcpStream::connect((host.as_str(), port)).await,
        }
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "connect timed out"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn reply5(client: &mut TcpStream, rep: u8, bound: Option<SocketAddr>) -> io::Result<()> {
    match bound {
        Some(SocketAddr::V4(a)) => {
            let p = a.port().to_be_bytes();
            let o = a.ip().octets();
            client
                .write_all(&[0x05, rep, 0x00, 0x01, o[0], o[1], o[2], o[3], p[0], p[1]])
                .await
        }
        Some(SocketAddr::V6(a)) => {
            let p = a.port().to_be_bytes();
            let o = a.ip().octets();
            let mut pkt = [0u8; 22];
            pkt[0] = 0x05;
            pkt[1] = rep;
            pkt[3] = 0x04;
            pkt[4..20].copy_from_slice(&o);
            pkt[20] = p[0];
            pkt[21] = p[1];
            client.write_all(&pkt).await
        }
        None => client.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await,
    }
}

async fn reply4(client: &mut TcpStream, cd: u8, req: &[u8; 6]) -> io::Result<()> {
    let mut pkt = [0u8; 8];
    pkt[1] = cd;
    pkt[2..8].copy_from_slice(req);
    client.write_all(&pkt).await
}

fn socks5_rep(err: &io::Error) -> u8 {
    match err.kind() {
        ErrorKind::ConnectionRefused => 0x05,
        ErrorKind::NotFound | ErrorKind::AddrNotAvailable => 0x04,
        ErrorKind::TimedOut => 0x06,
        _ => 0x01,
    }
}

async fn skip_cstring(stream: &mut TcpStream) -> io::Result<()> {
    for _ in 0..256 {
        if stream.read_u8().await? == 0 {
            return Ok(());
        }
    }
    Err(io::Error::new(ErrorKind::InvalidData, "userid too long"))
}

async fn read_cstring(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::with_capacity(32);
    loop {
        let b = stream.read_u8().await?;
        if b == 0 {
            break;
        }
        if buf.len() >= 255 {
            return Err(io::Error::new(ErrorKind::InvalidData, "host too long"));
        }
        buf.push(b);
    }
    String::from_utf8(buf).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}
