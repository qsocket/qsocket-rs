use base64::{engine::general_purpose, Engine as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hex::FromHexError;
use rustls::client::*;
use rustls::*;
use sha2::{Digest, Sha256};
use std::io;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::net::{AddrParseError, SocketAddr};
use std::result::Result;
use std::string::FromUtf8Error;
use std::sync::mpsc::RecvError;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

mod device;
mod pake;

// QSocket constants
/// Hardcoded QSocket relay network gate address.
pub const QSRN_GATE: &str = "gate.qsocket.io";
/// Raw connection port for the QSRN.
pub const QSRN_PORT: u32 = 80;
/// TLS connection port for the QSRN.
pub const QSRN_TLS_PORT: u32 = 443;
// Knock constants
/// Base value for calculating knock packet checksum.
pub const KNOCK_CHECKSUM_BASE: u8 = 0xEE;
/// Default socket read/write timeout duration.

#[derive(Error, Debug)]
pub enum QSocketError {
    #[error("Knock failed (no peer listening)")]
    KnockFail,
    #[error("Socket busy (another server is listening)")]
    KnockBusy,
    #[error("Invalid knock response")]
    InvalidKnockResponse,
    #[error("Certificate fingerprint mismatch")]
    CertificateFingerprintMismatch,
    #[error("Socket not connected")]
    NotConnected,
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    TlsError(#[from] rustls::Error),
    #[error(transparent)]
    FromHex(#[from] FromHexError),
    #[error(transparent)]
    AddrParseFail(#[from] AddrParseError),
    #[error(transparent)]
    HttpParseFail(#[from] httparse::Error),
    #[error(transparent)]
    Base64DecodeFail(#[from] base64::DecodeError),
    #[error(transparent)]
    FromUtf8Fail(#[from] FromUtf8Error),
    #[error(transparent)]
    RecvFail(#[from] RecvError),
    #[error("PAKE handshake failed")]
    PakeError,
}

enum KnockStatus {
    Success = 0xE0,
    Forward,
    Fail,
    Busy,
}

struct KnockResponse {
    status: KnockStatus,
    data: String,
}

#[derive(PartialEq)]
pub enum SocketType {
    TCP,
    TLS,
    E2E,
}

#[derive(PartialEq, Copy, Clone)]
pub enum PeerType {
    Server = 0,
    Client,
}

pub struct Stream {
    connected: bool,
    socket_type: SocketType,
    cipher: Option<ChaCha20>,
    tcp_stream: Option<TcpStream>,
    tls_stream: Option<StreamOwned<ClientConnection, TcpStream>>,
}

impl Stream {
    fn new() -> Self {
        Self {
            socket_type: SocketType::TCP,
            connected: false,
            cipher: None,
            tcp_stream: None,
            tls_stream: None,
        }
    }

    fn connect(&mut self, gate: &str) -> Result<(), QSocketError> {
        let tcp_stream = TcpStream::connect(gate)?;
        self.tcp_stream = Some(tcp_stream);
        self.connected = true;
        Ok(())
    }

    fn upgrade_to_tls(&mut self) -> Result<(), QSocketError> {
        if !self.connected {
            return Err(QSocketError::NotConnected);
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

    fn read_enc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        let n = match &self.socket_type {
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read(buf)?,
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read(buf)?,
            SocketType::E2E => {
                if self.tls_stream.is_some() {
                    self.tls_stream.as_mut().unwrap().read(buf)?
                } else {
                    self.tcp_stream.as_mut().unwrap().read(buf)?
                }
            }
        };
        self.cipher.as_mut().unwrap().apply_keystream(&mut buf[..n]);
        Ok(n)
    }

    fn write_enc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        let mut my_buf = Vec::new();
        my_buf.copy_from_slice(buf);
        self.cipher.as_mut().unwrap().apply_keystream(&mut my_buf);

        match &self.socket_type {
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write(my_buf.as_slice()),
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write(my_buf.as_slice()),
            SocketType::E2E => {
                if self.tls_stream.is_some() {
                    self.tls_stream.as_mut().unwrap().write(my_buf.as_slice())
                } else {
                    self.tcp_stream.as_mut().unwrap().write(my_buf.as_slice())
                }
            }
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write(buf),
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write(buf),
            SocketType::E2E => self.write_enc(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().flush(),
            SocketType::TLS => self.tls_stream.as_mut().unwrap().flush(),
            SocketType::E2E => {
                if self.tls_stream.is_some() {
                    return self.tls_stream.as_mut().unwrap().flush();
                } else {
                    return self.tcp_stream.as_mut().unwrap().flush();
                }
            }
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read(buf),
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read(buf),
            SocketType::E2E => self.read_enc(buf),
        }
    }
}

pub struct QSocket {
    /// `secret` value can be considered as the password for the QSocket connection,
    /// It will be used for generating a 128bit unique identifier (UID) for the connection.
    secret: String,
    /// `session_key` contains the shared secret key derived by performing PAKE.
    session_key: Option<Vec<u8>>,
    /// `device_arch` value is used internally for QoS purposes.
    /// It specifies the device architecture, the relay server uses these
    /// values for optimizing the connection performance.
    device_os: device::DeviceOS,
    /// `device_os` value is used internally for QoS purposes.
    /// It specifies the device operating system, the relay server uses these
    /// values for optimizing the connection performance.   
    device_arch: device::DeviceArch,
    /// `peer_type` value is used for specifying the peer type Client/Server.
    peer_type: PeerType,
    /// `forward_addr` value is used for specifying the forward address for QSocket server.
    forward_addr: Option<SocketAddr>,
    /// `cert_fingerprint` value is used for TLS certificate fingerprint verification. (a.k.a. SSL pinning)
    cert_fingerprint: Option<String>,
    /// `stream` contains the underlying TCP/TLS/E2E connection streams.
    stream: Stream,
    // cipher: Option<ChaCha20>,
}

impl Write for QSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Read for QSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl QSocket {
    /// Creates a new quantum socket instance.
    ///
    /// `secret` value can be considered as the password for the QSocket connection,
    /// It will be used for generating a 128bit unique identifier (UID) for the connection.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    ///
    /// let mut qsock = qsocket::QSocket::new(PeerType::Client, "my-secret");
    /// ```
    pub fn new(peer_type: PeerType, secret: &str) -> Self {
        Self {
            peer_type,
            device_os: device::get_device_os(),
            device_arch: device::get_device_arch(),
            cert_fingerprint: None,
            forward_addr: None,
            secret: String::from(secret),
            session_key: None,
            stream: Stream::new(),
        }
    }

    /// Create a new knock packet structure with the given secret and tag.
    ///
    /// `secret` value can be considered as the password for the QSocket connection,
    /// It will be used for generating a 128bit unique identifier (UID) for the connection.
    ///
    /// `tag` value is used internally for QoS purposes.
    /// It specifies the type of connection to the relay server for
    /// more optimized connection performance.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use qsocket;
    /// use std::iter::Iterator;
    ///
    /// let test_case: [u8; 20] = [
    ///     0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07,
    ///     0x15, 0x2d, 0x23, 0x4b, 0x70, 0x00, 0x00, 0x00, 0x01
    /// ];
    ///
    /// let qsock = qsocket::QSocket::new(PeerType::Client, "my-secret");
    /// let knock = qsock.new_knock_sequence()?;
    /// assert!(knock[0..15].eq(test_case[0..15]);
    /// assert!(knock[16], 0x00);
    /// assert!(knock[19], PeerType::Client as u8);
    /// ```
    fn new_knock_sequence(&self) -> Result<[u8; 20], QSocketError> {
        let mut knock: [u8; 20] = Default::default();
        let digest = md5::compute(self.secret.clone());
        digest.as_slice().read_exact(knock[1..17].as_mut())?;
        knock[17] = self.device_arch as u8;
        knock[18] = self.device_os as u8;
        knock[19] = self.peer_type as u8;
        knock[0] = calc_checksum(&knock[1..], KNOCK_CHECKSUM_BASE);
        Ok(knock)
    }

    /// Set a TLS certificate fingerprint for verification.
    ///
    /// `fp` value is the hex encoded 32 byte certificate fingerprint.
    ///
    /// # Examples
    /// ```no_run
    ///use qsocket;
    ///
    ///let mut qsock - qsocket::QSocket::new(PeerType::Client, "my-secret");
    ///qsock.set_cert_fingerprint("32ADEB12BA582C97E157D10699080C1598ECC3793C09D19020EDF51CDC67C145")
    /// ```
    pub fn set_cert_fingerprint(&mut self, fp: &str) -> Result<(), QSocketError> {
        hex::decode(fp)?; // Check if it is valid hex
        self.cert_fingerprint = Some(fp.to_uppercase().to_string()); // normalize to uppercase
        Ok(())
    }

    /// Returns true if the QSocket is set to client mode.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    ///
    /// let mut qsock = qsocket::QSocket::new(PeerType::Client, "my-secret");
    /// assert_eq!(qsock.is_client(), true);
    /// ```
    pub fn is_client(&self) -> bool {
        self.peer_type == PeerType::Client
    }

    /// Returns true if the QSocket is set to server mode.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    ///
    /// let mut qsock = qsocket::QSocket::new(PeerType::Server, "my-secret");
    /// assert_eq!(qsock.is_server(), true);
    /// ```
    pub fn is_server(&self) -> bool {
        self.peer_type == PeerType::Server
    }

    /// Sets the forward address to QSocket.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    /// let mut qsock = qsocket::QSocket::new(PeerType::Client, "my-secret");
    /// qsock.set_forward_addr("127.0.0.1:22")?;
    /// ```
    pub fn set_forward_addr(&mut self, addr: String) -> Result<(), QSocketError> {
        self.forward_addr = Some(addr.parse()?);
        Ok(())
    }

    /// Gets the forward address of QSocket.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    /// let mut qsock = qsocket::QSocket::new(PeerType::Client, "my-secret");
    /// qsock.set_forward_addr("127.0.0.:22")?
    /// assert_eq!(qsock.get_forward_addr().unwrap().to_string(), "127.0.0.1:22");
    /// ```
    pub fn get_forward_addr(&self) -> Option<SocketAddr> {
        self.forward_addr
    }

    /// Opens a E2E encrypted connection to the QSRN.
    ///
    /// If the connection fails due to network related errors,
    /// function will return the corresponding error, in the case of
    /// QSRN related errors the function will return one the ERR_KNOCK_* errors.
    ///
    /// Examples
    /// ```no_run
    /// use qsocket;
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// qsock.dial()?;           
    /// ```
    pub fn dial(&mut self) -> Result<(), QSocketError> {
        self.dial_with(SocketType::E2E)
    }

    /// Opens connection to the QSRN with the given SocketType.
    ///
    /// The`conn_type` parameter is used for specifying the socket type
    /// that will be used for creating a connection.
    ///
    /// If the connection fails due to network related errors,
    /// function will return the corresponding error, in the case of
    /// QSRN related errors the function will return one the ERR_KNOCK_* errors.
    ///
    /// Examples
    /// ```no_run
    /// use qsocket;
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// qsock.dial_with(qsocket::SocketType::TLS)?;           
    /// ```
    pub fn dial_with(&mut self, conn_type: SocketType) -> Result<(), QSocketError> {
        self.stream
            .connect(format!("{QSRN_GATE}:{QSRN_TLS_PORT}").as_str())?;

        if conn_type != SocketType::TCP {
            self.stream.upgrade_to_tls()?;
            if self.cert_fingerprint.is_some() {
                let conn = &self.stream.tls_stream.as_ref().unwrap().conn;
                let certs = conn.peer_certificates();
                let mut hasher = Sha256::new();
                hasher.update(certs.unwrap()[0].0.as_slice());
                let cert_hash = format!("{:X}", hasher.finalize());
                if cert_hash != self.cert_fingerprint.clone().unwrap() {
                    return Err(QSocketError::CertificateFingerprintMismatch);
                }
            }
        }

        // let knock = self.new_knock_sequence()?;
        // self.stream.write_all(knock.as_ref())?;
        self.stream
            .write_all(self.new_proto_switch_req()?.as_bytes())?;
        let mut buf = vec![0; 4096];
        let n = self.stream.read(buf.as_mut())?;
        if n == 0 {
            return Err(QSocketError::InvalidKnockResponse);
        }
        let resp = parse_knock_response(&buf)?;

        match resp.status {
            KnockStatus::Success => (),
            KnockStatus::Forward => self.set_forward_addr(resp.data)?,
            KnockStatus::Fail => return Err(QSocketError::KnockFail),
            KnockStatus::Busy => return Err(QSocketError::KnockBusy),
        };

        if conn_type == SocketType::E2E {
            // Begin PAKE exchange...
            let session_key = match self.peer_type {
                PeerType::Server => pake::init_pake_handshake(
                    pake::PakeMode::Client,
                    &mut self.stream,
                    self.secret.clone(),
                )?,
                PeerType::Client => pake::init_pake_handshake(
                    pake::PakeMode::Server,
                    &mut self.stream,
                    self.secret.clone(),
                )?,
            };
            self.session_key = Some(session_key);
            let nonce = [0x00; 12]; // Fixed empty nonce, this could be improved...
            self.stream.cipher = Some(ChaCha20::new(
                self.session_key.clone().unwrap().as_slice().into(),
                &nonce.into(),
            ));
        }
        Ok(())
    }

    /// Sets the read timeout to the timeout specified.
    ///
    /// If the value specified is [`None`], then [`read`] calls will block
    /// indefinitely. An [`Err`] is returned if the zero [`Duration`] is
    /// passed to this method.
    ///
    /// # Platform-specific behavior
    ///
    /// Platforms may return a different error code whenever a read times out as
    /// a result of setting this option. For example Unix typically returns an
    /// error of the kind [`WouldBlock`], but Windows may return [`TimedOut`].
    ///
    /// [`read`]: Read::read
    /// [`WouldBlock`]: std::io::ErrorKind::WouldBlock
    /// [`TimedOut`]: std::io::ErrorKind::TimedOut
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use qsocket;
    /// use core::time::Duration;
    /// use std::io::ErrorKind::InvalidInput;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// qsock.dial(qsocket::SocketType::E2E)?;
    /// let result = qsock.set_read_timeout(Some(Duration::new(0, 0)));
    /// let err = result.unwrap_err();
    /// assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput)
    /// ```
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> Result<(), QSocketError> {
        if !self.stream.connected {
            return Err(QSocketError::NotConnected);
        }
        self.stream
            .tcp_stream
            .as_mut()
            .unwrap()
            .set_read_timeout(dur)?;
        Ok(())
    }

    /// Sets the write timeout to the timeout specified.
    ///
    /// If the value specified is [`None`], then [`write`] calls will block
    /// indefinitely. An [`Err`] is returned if the zero [`Duration`] is
    /// passed to this method.
    ///
    /// # Platform-specific behavior
    ///
    /// Platforms may return a different error code whenever a write times out
    /// as a result of setting this option. For example Unix typically returns
    /// an error of the kind [`WouldBlock`], but Windows may return [`TimedOut`].
    ///
    /// [`write`]: Write::write
    /// [`WouldBlock`]: std::io::ErrorKind::WouldBlock
    /// [`TimedOut`]: std::io::ErrorKind::TimedOut
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use qsocket;
    /// use core::time::Duration;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// qsock.dial()?;
    /// let result = qsock.set_read_timeout(Some(Duration::new(0, 0)));
    /// qsock.set_write_timeout(None).expect("set_write_timeout call failed");
    /// ```
    pub fn set_write_timeout(&mut self, dur: Option<Duration>) -> Result<(), QSocketError> {
        if !self.stream.connected {
            return Err(QSocketError::NotConnected);
        }
        self.stream
            .tcp_stream
            .as_mut()
            .unwrap()
            .set_write_timeout(dur)?;
        Ok(())
    }

    /// Moves this TCP stream into or out of nonblocking mode.
    ///
    /// This will result in `read`, `write`, `recv` and `send` operations
    /// becoming nonblocking, i.e., immediately returning from their calls.
    /// If the IO operation is successful, `Ok` is returned and no further
    /// action is required. If the IO operation could not be completed and needs
    /// to be retried, an error with kind [`std::io::ErrorKind::WouldBlock`] is
    /// returned.
    ///
    /// On Unix platforms, calling this method corresponds to calling `fcntl`
    /// `FIONBIO`. On Windows calling this method corresponds to calling
    /// `ioctlsocket` `FIONBIO`.
    ///
    /// # Examples
    ///
    /// Reading bytes from a TCP stream in non-blocking mode:
    ///
    /// ```no_run
    /// use qsocket;
    /// use std::io::Read;
    /// use std::io::ErrorKind::WouldBlock;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// qsock.dial()?;
    /// qsock.set_nonblocking(true).expect("set_nonblocking call failed");
    ///
    /// # fn wait_for_fd() { unimplemented!() }
    /// let mut buf = vec![];
    /// loop {
    ///     match qsock.read(&mut buf) {
    ///         Ok(_) => break,
    ///         Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
    ///             // wait until network socket is ready, typically implemented
    ///             // via platform-specific APIs such as epoll or IOCP
    ///             wait_for_fd();
    ///         }
    ///         Err(e) => panic!("encountered IO error: {e}"),
    ///     };
    /// };
    /// println!("bytes: {buf:?}");
    /// ```
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), QSocketError> {
        if !self.stream.connected {
            return Err(QSocketError::NotConnected);
        }
        self.stream
            .tcp_stream
            .as_mut()
            .unwrap()
            .set_nonblocking(nonblocking)?;
        Ok(())
    }

    /// Shuts down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O on the specified
    /// portions to return immediately with an appropriate value (see the
    /// documentation of [`std::net::Shutdown`]).
    ///
    /// # Platform-specific behavior
    ///
    /// Calling this function multiple times may result in different behavior,
    /// depending on the operating system. On Linux, the second call will
    /// return `Ok(())`, but on macOS, it will return `ErrorKind::NotConnected`.
    /// This may change in the future.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use qsocket;
    /// use std::net::Shutdown;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// qsock.dial(qsocket::SocketType::E2E)?;
    /// qsock.shutdown(Shutdown::Both).expect("shutdown call failed");
    /// ```    
    pub fn shutdown(&mut self, how: std::net::Shutdown) -> Result<(), QSocketError> {
        if !self.stream.connected {
            return Err(QSocketError::NotConnected);
        }
        self.stream.tcp_stream.as_mut().unwrap().shutdown(how)?;
        Ok(())
    }

    /// This function creates a new Websocket protocol switch request,
    /// based on the qsocket knock sequence and forward address.
    /// The request host header will point to QSRN_GATE by default. (can be changed for domain
    /// fronting.
    fn new_proto_switch_req(&self) -> std::result::Result<String, QSocketError> {
        let knock = self.new_knock_sequence()?;
        let ws_key = general_purpose::STANDARD.encode(knock);
        let mut req = String::from("GET / HTTP/1.1\n");
        if self.forward_addr.is_some() {
            let addr = self.forward_addr.unwrap();
            req = format!("GET /{}:{} HTTP/1.1\n", addr.ip(), addr.port());
        }
        req.push_str(format!("Host: {}\n", QSRN_GATE).as_str());
        req.push_str("Sec-Websocket-Version: 13\n");
        req.push_str(format!("Sec-Websocket-Key: {}\n", ws_key).as_str());
        req.push_str("Connection: Upgrade\n");
        req.push_str("Upgrade: websocket\n");
        req.push_str("\r\n");
        Ok(req)
    }
}

struct NoCertificateVerification {}
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
        std::result::Result::Ok(ServerCertVerified::assertion())
    }
}

fn new_tls_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
    config
}

/// Calculates a 8bit checksum value for the given byte array.
///
/// `data` is the input value for calculating checksum.
/// `base` is the modulus base used for calculating the checksum.
///
/// # Examples
///
/// ```no_run
/// use qsocket;
///
/// let test_case: [u8; 16] = [
///     0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07,
///     0x15, 0x2d, 0x23, 0x4b, 0x70,
/// ];
///
/// let checksum = qsocket::calc_checksum(&test_case, qsocket::KNOCK_CHECKSUM_BASE);
/// assert_eq!(checksum, 0x30)
/// ```
pub fn calc_checksum(data: &[u8], base: u8) -> u8 {
    let mut checksum: u32 = 0;
    for i in data {
        checksum += ((i << 2) % base) as u32;
    }
    (checksum % base as u32) as u8
}

fn parse_knock_response(buf: &[u8]) -> Result<KnockResponse, QSocketError> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(buf)?;
    match resp.code.unwrap() {
        101 => {
            for header in headers.iter() {
                if header.name.to_lowercase() == "sec-websocket-accept" {
                    let data = general_purpose::STANDARD.decode(header.value)?;
                    return Ok(KnockResponse {
                        status: KnockStatus::Forward,
                        data: String::from_utf8(data)?,
                    });
                }
            }
            Ok(KnockResponse {
                status: KnockStatus::Success,
                data: String::new(),
            })
        }
        401 => Ok(KnockResponse {
            status: KnockStatus::Fail,
            data: String::new(),
        }),
        409 => Ok(KnockResponse {
            status: KnockStatus::Busy,
            data: String::new(),
        }),
        _ => Err(QSocketError::InvalidKnockResponse),
    }
}

//
// #[cfg(test)]
// mod tests {
//     use crate::PeerType;
//
//
//     #[test]
//     fn test_new_knock_sequence() {
//         let qsock = qsocket::QSocket::new(PeerType::Client, "my-secret");
//         let knock = qsock.new_knock_sequence()?;
//         let test_case: [u8; 20] = [
//             0xC0, 0xDE, 0xD6, 0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07,
//             0x15, 0x2d, 0x23, 0x4b, 0x70, 0x1,
//         ];
//
//         for i in 0..knock.len() {
//             assert_eq!(test_case[i], knock[i]);
//         }
//     }
// }
