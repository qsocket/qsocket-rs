use anyhow::anyhow;
use rustls::client::*;
use rustls::*;
use std::fmt::Arguments;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::net::TcpStream;
use std::result::Result;
use std::sync::Arc;
use std::time::Duration;

// Qsocket constants
pub const QSRN_GATE: &str = "gate.qsocket.io";
pub const QSRN_PORT: u32 = 80;
pub const QSRN_TLS_PORT: u32 = 443;
// Errors
pub const ERR_KNOCK_FAILED: &str = "Connection refused.";
pub const ERR_KNOCK_BUSY: &str = "Socket busy.";
pub const ERR_INVALID_KNOCK_RESPONSE: &str = "Invalid response.";
pub const ERR_NO_PEER_CERT: &str = "Failed retrieving peer certificate.";
pub const ERR_CERT_FINGERPRINT_MISMATCH: &str = "Certificate fingerprint mismatch!";
pub const ERR_SOCKET_NOT_INITIALIZED: &str = "Socket not initialized!";
pub const ERR_SOCKET_NOT_CONNECTED: &str = "Socket not connected.";

// Knock tags
// 00 00 0000
// |  |  |
// [OS]  |
//    |  |
//    [ARCH]
//       |
//       [UTIL]
// 2 OS bits...
// TAG_OS_OTHER   = 0x20 // 00XXXXXX => Other (FreeBSD,OpenBSD,NetBSD,Solaris,AIX,Dragonfly,Illumos)
pub const TAG_OS_LINUX: u8 = 0xC0; // 11000000 => Linux
pub const TAG_OS_WINDOWS: u8 = 0x80; // 10000000 => Windows
pub const TAG_OS_DARWIN: u8 = 0x40; // 01000000 => Darwin

// 2 Arch bits...
// TAG_ARCH_OTHER = 0x08 // 0000XXXX => Other (ARM,MIPS,MIPS64,MIPSLE,MIPS64LE,PPC,PPC64LE,X360)
pub const TAG_ARCH_AMD64: u8 = 0x30; // 00110000 => AMD64
pub const TAG_ARCH_386: u8 = 0x20; // 00100000 => 386
pub const TAG_ARCH_ARM64: u8 = 0x10; // 00010000 => ARM64

// 4 ID bits...
pub const TAG_ID_NC: u8 = 0x0F; // 00001111 => NC
pub const TAG_ID_PROXY: u8 = 0x0E; // 00001110 => PROXY
pub const TAG_ID_SFTP: u8 = 0x0D; // 00001101 => SFTP
pub const TAG_ID_MIC: u8 = 0x0C; // 00001100 => MIC
pub const TAG_ID_VNC: u8 = 0x0B; // 00001011 => VNC
pub const TAG_ID_CAM: u8 = 0x0A; // 00001010 => CAM
                                 // TO BE CONTINUED...

// qsocket.io TLS certificate fingerprint
const QSRN_CERT_FINGERPRINT: &str =
    "32ADEB12BA582C97E157D10699080C1598ECC3793C09D19020EDF51CDC67C145";

// Knock constants
pub const KNOCK_HEADER_B1: u8 = 0xC0;
pub const KNOCK_HEADER_B2: u8 = 0xDE;
pub const KNOCK_CHECKSUM_BASE: u8 = 0xEE;
pub const KNOCK_SUCCESS: u8 = 0xE0;
pub const KNOCK_FAIL: u8 = 0xE1;
pub const KNOCK_BUSY: u8 = 0xE2;

pub enum SocketType {
    TLS,
    TCP,
}

pub struct Stream {
    connected: bool,
    socket_type: SocketType,
    tcp_stream: Option<TcpStream>,
    tls_stream: Option<StreamOwned<ClientConnection, TcpStream>>,
}

impl Stream {
    fn new() -> Self {
        Self {
            socket_type: SocketType::TCP,
            connected: false,
            tcp_stream: None,
            tls_stream: None,
        }
    }

    fn connect(&mut self, gate: &str) -> anyhow::Result<()> {
        let tcp_stream = TcpStream::connect(gate)?;
        self.tcp_stream = Some(tcp_stream);
        self.connected = true;
        Ok(())
    }

    fn upgrade_to_tls(&mut self) -> anyhow::Result<()> {
        if !self.connected {
            return Err(anyhow!(ErrorKind::NotConnected));
        }
        let mut client = rustls::ClientConnection::new(
            Arc::new(new_tls_config()),
            QSRN_GATE.try_into().unwrap(),
        )?;
        while client.wants_write() {
            client.write_tls(self.tcp_stream.as_mut().unwrap())?;
        }
        self.tcp_stream.as_mut().unwrap().flush()?;
        while client.is_handshaking() && client.peer_certificates().is_none() {
            client.read_tls(self.tcp_stream.as_mut().unwrap())?;
            client.process_new_packets()?;
        }
        let stream =
            rustls::StreamOwned::new(client, self.tcp_stream.as_mut().unwrap().try_clone()?);

        self.tls_stream = Some(stream);
        self.socket_type = SocketType::TLS;
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read(buf),
        }
    }

    pub fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read_vectored(bufs),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read_vectored(bufs),
        }
    }

    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read_to_end(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read_to_end(buf),
        }
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read_exact(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read_exact(buf),
        }
    }

    pub fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read_to_string(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read_to_string(buf),
        }
    }

    pub fn is_read_vectored(&mut self) -> bool {
        false
    }

    pub fn write(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write(buf),
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write_all(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write_all(buf),
        }
    }
    pub fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write_vectored(bufs),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write_vectored(bufs),
        }
    }

    pub fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write_fmt(fmt),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write_fmt(fmt),
        }
    }

    pub fn is_write_vectored(&mut self) -> bool {
        false
    }

    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        self.tcp_stream.as_mut().unwrap().set_read_timeout(dur)
    }

    pub fn set_write_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        self.tcp_stream.as_mut().unwrap().set_write_timeout(dur)
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().flush(),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().flush(),
        }
    }
}

pub struct Qsocket {
    tag: u8,
    secret: String,
    stream: Stream,
}

impl Qsocket {
    pub fn new(secret: &str, user_tag: u8) -> Self {
        let mut tag = get_default_tag();
        if user_tag != 0 {
            tag |= user_tag;
        }
        Self {
            tag,
            secret: String::from(secret),
            stream: Stream::new(),
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
    pub fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.stream.read_vectored(bufs)
    }
    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.stream.read_to_end(buf)
    }
    pub fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.stream.read_to_string(buf)
    }
    pub fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.stream.read_exact(buf)
    }
    pub fn write(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(buf)
    }
    pub fn write_fmt(&mut self, fmt: Arguments<'_>) -> std::io::Result<()> {
        self.stream.write_fmt(fmt)
    }
    pub fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.stream.write_vectored(bufs)
    }
    pub fn is_write_vectored(&mut self) -> bool {
        self.stream.is_write_vectored()
    }
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(dur)
    }
    pub fn set_write_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(dur)
    }
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }

    pub fn dial_tcp(&mut self) -> Result<(), anyhow::Error> {
        self.stream
            .connect(format!("{QSRN_GATE}:{QSRN_PORT}").as_str())?;
        let knock = new_knock_sequence(&self.secret, self.tag)?;
        self.stream.write_all(knock.as_ref())?;
        let mut resp: [u8; 1] = [0];
        self.stream.read_exact(resp.as_mut())?;
        match resp[0] {
            KNOCK_SUCCESS => Ok(()),
            KNOCK_BUSY => Err(anyhow::anyhow!(ERR_KNOCK_BUSY)),
            KNOCK_FAIL => Err(anyhow::anyhow!(ERR_KNOCK_FAILED)),
            _ => Err(anyhow::anyhow!(ERR_INVALID_KNOCK_RESPONSE)),
        }
    }

    pub fn dial_tls(&mut self, verify_cert: bool) -> Result<(), anyhow::Error> {
        self.stream
            .connect(format!("{QSRN_GATE}:{QSRN_TLS_PORT}").as_str())?;
        self.stream.upgrade_to_tls()?;
        if verify_cert {
            let conn = &self.stream.tls_stream.as_ref().unwrap().conn;
            let certs = conn.peer_certificates();
            let cert_hash = sha256::digest_bytes(certs.unwrap()[0].0.as_slice());
            if cert_hash != QSRN_CERT_FINGERPRINT.to_lowercase() {
                return Err(anyhow!(ERR_CERT_FINGERPRINT_MISMATCH));
            }
        }
        let knock = new_knock_sequence(&self.secret, self.tag)?;
        self.stream.write_all(knock.as_ref())?;

        let mut resp = vec![1];
        self.stream.read_exact(resp.as_mut())?;
        match resp[0] {
            KNOCK_SUCCESS => Ok(()),
            KNOCK_BUSY => Err(anyhow!(ERR_KNOCK_BUSY)),
            KNOCK_FAIL => Err(anyhow!(ERR_KNOCK_FAILED)),
            _ => Err(anyhow!(ERR_INVALID_KNOCK_RESPONSE)),
        }
    }

    pub fn dial(&mut self, tls: bool, verify_cert: bool) -> Result<(), anyhow::Error> {
        if tls {
            return self.dial_tls(verify_cert);
        }
        self.dial_tcp()
    }
}

impl Write for Qsocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write(buf.to_owned().as_mut())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.write_vectored(bufs)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.write_all(buf)
    }

    fn write_fmt(&mut self, fmt: Arguments<'_>) -> std::io::Result<()> {
        self.write_fmt(fmt)
    }

    fn by_ref(&mut self) -> &mut Self {
        self
    }
}

impl Read for Qsocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.read_vectored(bufs)
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.read_to_end(buf)
    }
    fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.read_to_string(buf)
    }

    fn by_ref(&mut self) -> &mut Self {
        self
    }
}

pub struct NoCertificateVerification {}
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn new_tls_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
    config
}

pub fn new_knock_sequence(secret: &str, tag: u8) -> Result<[u8; 20], std::io::Error> {
    let digest = md5::compute(secret);
    let mut knock: [u8; 20] = Default::default();
    knock[0] = KNOCK_HEADER_B1;
    knock[1] = KNOCK_HEADER_B2;
    knock[2] = calc_checksum(digest.as_slice(), KNOCK_CHECKSUM_BASE);
    digest.as_slice().read_exact(knock[3..19].as_mut())?;
    knock[19] = tag;
    Ok(knock)
}

pub fn calc_checksum(data: &[u8], base: u8) -> u8 {
    let mut checksum: u32 = 0;
    for i in data {
        checksum += *i as u32;
    }
    (checksum % (base as u32)) as u8
}

#[cfg(test)]
mod tests {
    use crate::{new_knock_sequence, Qsocket};
    use core::panic;

    #[test]
    fn test_new_knock_sequence() {
        let test_secret = "123";
        let test_tag = 1;
        let knock = new_knock_sequence(test_secret, test_tag).unwrap();
        let test_case: [u8; 20] = [
            0xC0, 0xDE, 0x30, 0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07,
            0x15, 0x2d, 0x23, 0x4b, 0x70, 0x1,
        ];

        for i in 0..knock.len() {
            assert_eq!(test_case[i], knock[i]);
        }
    }

    #[test]
    fn test_dial() {
        std::thread::spawn(|| {
            let mut qs = Qsocket::new("123", 1);
            match qs.dial(false, false) {
                std::result::Result::Ok(_) => (),
                Err(e) => panic!("{:?}", e),
            };
        });

        let mut qs = Qsocket::new("123", 1);
        match qs.dial(false, false) {
            std::result::Result::Ok(_) => (),
            Err(e) => panic!("{:?}", e),
        };
    }
    #[test]
    fn test_dial_tls() {
        std::thread::spawn(|| {
            let mut qs = Qsocket::new("123", 1);
            match qs.dial(true, false) {
                std::result::Result::Ok(_) => (),
                Err(e) => panic!("{:?}", e),
            };
        });
        let mut qs = Qsocket::new("123", 1);
        match qs.dial(true, false) {
            std::result::Result::Ok(_) => (),
            Err(e) => panic!("{:?}", e),
        };
    }

    #[test]
    fn test_dial_cert_verify() {
        std::thread::spawn(|| {
            let mut qs = Qsocket::new("123", 1);
            match qs.dial(true, true) {
                std::result::Result::Ok(_) => (),
                Err(e) => panic!("{:?}", e),
            };
        });
        let mut qs = Qsocket::new("123", 1);
        match qs.dial(true, true) {
            std::result::Result::Ok(_) => (),
            Err(e) => panic!("{:?}", e),
        };
    }
}

pub fn get_default_tag() -> u8 {
    let mut tag: u8 = 0;
    // Determine OS...
    if cfg!(target_os = "linux") {
        tag |= TAG_OS_LINUX;
    }
    if cfg!(target_os = "windows") {
        tag |= TAG_OS_LINUX;
    }
    if cfg!(target_os = "macos") {
        tag |= TAG_OS_DARWIN;
    }
    // Determine architecture...
    if cfg!(target_arch = "x86_64") {
        tag |= TAG_ARCH_AMD64;
    }
    if cfg!(target_arch = "i686") {
        tag |= TAG_ARCH_386;
    }
    if cfg!(target_arch = "aarch64") {
        tag |= TAG_ARCH_ARM64;
    }
    tag
}
