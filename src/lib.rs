use anyhow::{anyhow, Ok};
//use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b256, Blake2bVar};
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::*;
use rustls::*;
use sha2::{Digest, Sha256};

use srp::client::SrpClient;
use srp::groups::G_4096;
use srp::server::SrpServer;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::result::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// QSocket constants
/// Hardcoded QSocket relay network gate address.
pub const QSRN_GATE: &str = "gate.qsocket.io";
/// Raw connection port for the QSRN.
pub const QSRN_PORT: u32 = 80;
/// TLS connection port for the QSRN.
pub const QSRN_TLS_PORT: u32 = 443;

// Errors
pub const ERR_KNOCK_FAILED: &str = "Connection refused. (no server listening with given secret)";
pub const ERR_KNOCK_BUSY: &str = "Socket busy.";
pub const ERR_INVALID_KNOCK_RESPONSE: &str = "Invalid response.";
pub const ERR_NO_PEER_CERT: &str = "Failed retrieving peer certificate.";
pub const ERR_CERT_FINGERPRINT_MISMATCH: &str = "Certificate fingerprint mismatch!";
pub const ERR_SOCKET_NOT_INITIALIZED: &str = "Socket not initialized!";
pub const ERR_SOCKET_NOT_CONNECTED: &str = "Socket not connected.";
pub const ERR_INVALID_PEER_ID_TAG: &str = "Invalid peer ID tag.";
pub const ERR_INVALID_SRP_CREDS: &str = "Invalid SRP creds.";
pub const ERR_SRP_PROOF_FAILED: &str = "SRP proof check failed.";
pub const ERR_SOCKET_IN_USE: &str = "socket already dialed.";

// Tags
// 000 000 0 0
// |   |   | |
// [OS]|   | |
//     |   | |
//     [ARCH]|
//         | |
//         [PROXY]
//           [SRV|CLI]
// 3 Arch bits...

mod device_id_tag {
    /// Tag ID for representing connections from devices with AMD64 architecture.
    pub const ARCH_AMD64: u8 = 0xE0;
    /// Tag ID for representing connections from devices with 386 architecture.
    pub const ARCH_386: u8 = 0x20;
    /// Tag ID for representing connections from devices with ARM64 architecture.
    pub const ARCH_ARM64: u8 = 0x40;
    /// Tag ID for representing connections from devices with ARM architecture.
    pub const ARCH_ARM: u8 = 0x60;
    /// Tag ID for representing connections from devices with MIPS64 architecture.
    pub const ARCH_MIPS64: u8 = 0x80;
    /// Tag ID for representing connections from devices with MIPS architecture.
    pub const ARCH_MIPS: u8 = 0xA0;
    /// Tag ID for representing connections from devices with MIPS64LE architecture.
    pub const ARCH_MIPS64LE: u8 = 0xC0;
    /// Tag ID for representing connections from Linux devices.
    pub const OS_LINUX: u8 = 0x1C;
    /// Tag ID for representing connections from Darwin devices.
    pub const OS_DARWIN: u8 = 0x04;
    /// Tag ID for representing connections from Windows devices.
    pub const OS_WINDOWS: u8 = 0x08;
    /// Tag ID for representing connections from Android devices.
    pub const OS_ANDROID: u8 = 0x0C;
    /// Tag ID for representing connections from IOS devices.
    pub const OS_IOS: u8 = 0x10;
    /// Tag ID for representing connections from FreeBSD devices.
    pub const OS_FREEBSD: u8 = 0x14;
    /// Tag ID for representing connections from OpenBSD devices.
    pub const OS_OPENBSD: u8 = 0x18;
    // Unknown = 0x00,
}

pub mod peer_id_tag {
    /// Tag ID for representing proxy mode connections.
    pub const PROXY: u8 = 0x02;
    /// Tag ID for representing client mode connections.
    pub const CLIENT: u8 = 0x01;
    /// Tag ID for representing server mode connections.
    pub const SERVER: u8 = 0x00;
}

/// Hardcoded gate.qsocket.io TLS certificate fingerprint
const QSRN_CERT_FINGERPRINT: &str =
    "32ADEB12BA582C97E157D10699080C1598ECC3793C09D19020EDF51CDC67C145";

// Knock constants
pub const KNOCK_HEADER_B1: u8 = 0xC0;
pub const KNOCK_HEADER_B2: u8 = 0xDE;
/// Base value for calculating knock packet checksum.
pub const KNOCK_CHECKSUM_BASE: u8 = 0xEE;
/// Knock response value representing successful connection.
pub const KNOCK_SUCCESS: u8 = 0xE0;
/// Knock response value representing failed connection.
pub const KNOCK_FAIL: u8 = 0xE1;
/// Knock response value representing busy connection.
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
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().write(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().flush(),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().flush(),
        }
    }
}
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        match &self.socket_type {
            SocketType::TLS => self.tls_stream.as_mut().unwrap().read(buf),
            SocketType::TCP => self.tcp_stream.as_mut().unwrap().read(buf),
        }
    }
}

pub struct QSocket {
    /// `tag` value is used internally for QoS purposes.
    /// It specifies the operating system, architecture and the type of connection initiated by the peers,
    /// the relay server uses these values for optimizing the connection performance.
    tag: u8,
    /// `secret` value can be considered as the password for the QSocket connection,
    /// It will be used for generating a 128bit unique identifier (UID) for the connection.
    secret: String,
    /// `verify_cert` value is used for enabling TLS certificate verification. (a.k.a. SSL pinning)
    verify_cert: bool,
    /// `stream` contains the underlying TCP/TLS connection streams.
    stream: Stream,
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
    /// let mut qsock = qsocket::QSocket::new("my-secret", true);
    /// ```
    pub fn new(secret: &str, verify_cert: bool) -> Self {
        let tag = get_default_tag();
        Self {
            tag,
            verify_cert,
            secret: String::from(secret),
            stream: Stream::new(),
        }
    }

    /// Returns true if the QSocket is set to client mode.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret", true);
    /// qsock.add_id_tag(qsocket::peer_id_tag::CLIENT);
    /// assert_eq!(qsock.is_client(), true);
    /// ```
    pub fn is_client(&mut self) -> bool {
        self.tag % 2 == 1
    }

    /// Adds a new ID tag to the quantum socket.
    ///
    /// `secret` value can be considered as the password for the QSocket connection,
    /// It will be used for generating a 128bit unique identifier (UID) for the connection.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// if let Err(e) = qsock.add_id_tag(qsocket::peer_id_tag::CLIENT) {
    ///     panic!("{}", e);
    /// }
    /// ```
    pub fn add_id_tag(&mut self, id_tag: u8) -> Result<(), anyhow::Error> {
        if self.stream.connected {
            return Err(anyhow!(ERR_SOCKET_IN_USE));
        }
        match id_tag {
            peer_id_tag::CLIENT => self.tag |= id_tag,
            peer_id_tag::SERVER => self.tag |= id_tag,
            peer_id_tag::PROXY => self.tag |= id_tag,
            _ => return Err(anyhow!(ERR_INVALID_PEER_ID_TAG)),
        }
        Ok(())
    }

    /// Enables/Disabled the TLS certificate pinning behavior of the quantum socket.
    ///
    /// # Examples
    /// ```no_run
    /// use qsocket;
    ///
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// if let Err(e) = qsock.add_id_tag(qsocket::peer_id_tag::CLIENT) {
    ///     panic!("{}", e);
    /// }
    /// ```
    pub fn set_cert_pinning(&mut self, v: bool) -> Result<(), anyhow::Error> {
        if self.stream.connected {
            return Err(anyhow!(ERR_SOCKET_IN_USE));
        }
        self.verify_cert = v;
        Ok(())
    }

    /// Opens a TCP connection to the QSRN.
    ///
    /// If the connection fails due to network related errors,
    /// function will return the corresponding error, in the case of
    /// QSRN related errors the function will return one the ERR_KNOCK_* errors.
    ///
    /// Examples
    /// ```no_run
    /// use qsocket;
    /// let mut qsock = qsocket::QSocket::new("my-secret");
    /// if let Err(e) = qsock.dial_tcp() {           
    ///     panic!("{}", e);
    /// }
    /// ```
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

    /// Opens a TLS connection to the QSRN.
    ///
    /// If the `verify_cert` parameter is true,
    /// after establishing a TLS connection with the QSRN gate server,
    /// the TLS certificate fingerprint will be validated with the hardcoded certificate fingerprint value `QSRN_CERT_FINGERPRINT`.
    ///
    /// If the connection fails due to network related errors,
    /// function will return the corresponding error, in the case of
    /// QSRN related errors the function will return one the ERR_KNOCK_* errors.
    ///
    /// Examples
    /// ```no_run
    /// use qsocket;
    /// let mut qsock = qsocket::QSocket::new("my-secret", true);
    /// if let Err(e) = qsock.dial() {           
    ///     panic!("{}", e);
    /// }
    /// ```
    pub fn dial(&mut self) -> Result<(), anyhow::Error> {
        self.stream
            .connect(format!("{QSRN_GATE}:{QSRN_TLS_PORT}").as_str())?;
        self.stream.upgrade_to_tls()?;
        if self.verify_cert {
            let conn = &self.stream.tls_stream.as_ref().unwrap().conn;
            let certs = conn.peer_certificates();
            let mut hasher = Sha256::new();
            hasher.update(certs.unwrap()[0].0.as_slice());
            let cert_hash = format!("{:X}", hasher.finalize());
            if cert_hash != QSRN_CERT_FINGERPRINT {
                return Err(anyhow!(ERR_CERT_FINGERPRINT_MISMATCH));
            }
        }
        let knock = new_knock_sequence(&self.secret, self.tag)?;
        self.stream.write_all(knock.as_ref())?;

        let mut resp = vec![1];
        self.stream.read_exact(resp.as_mut())?;
        match resp[0] {
            KNOCK_SUCCESS => (),
            KNOCK_BUSY => return Err(anyhow!(ERR_KNOCK_BUSY)),
            KNOCK_FAIL => return Err(anyhow!(ERR_KNOCK_FAILED)),
            _ => return Err(anyhow!(ERR_INVALID_KNOCK_RESPONSE)),
        };

        let mut session_key: Vec<u8>;
        if self.is_client() {
            session_key = self.init_client_srp()?;
        } else {
            session_key = self.init_server_srp()?;
        }

        // Begin E2E encryption

        Ok(())
    }

    fn init_client_srp(&mut self) -> Result<Vec<u8>, anyhow::Error> {
        let myself = Arc::new(Mutex::new(self));

        if myself.lock().unwrap().stream.connected {
            return Err(anyhow!(ErrorKind::NotConnected));
        }

        let (user, pass) = myself.lock().unwrap().get_srp_creds();
        let client = SrpClient::<Blake2b256>::new(&G_4096);

        // send handshake data (username and a_pub) to the server:
        let mut a = [0u8; 64];
        OsRng.fill_bytes(&mut a);
        let a_pub = client.compute_public_ephemeral(&a);

        myself
            .lock()
            .unwrap()
            .stream
            .write_all(format!("{:x?}:{:x?}", user, a_pub.as_slice()).as_bytes())?;

        // receive salt and b_pub
        let mut buf = [0u8; 4096];
        let n = myself.lock().unwrap().stream.read(&mut buf)?;
        let salt_n_b_pub = format!("{:?}", &buf[0..n]);

        if salt_n_b_pub.split_once(':').is_none() {
            return Err(anyhow!(ERR_INVALID_SRP_CREDS));
        }

        let (salt_srt, b_pub_str) = salt_n_b_pub.split_once(':').unwrap();
        let salt = hex::decode(salt_srt)?;
        let b_pub = hex::decode(b_pub_str)?;

        let verifier = match client.process_reply(
            &a,
            user.as_slice(),
            pass.as_slice(),
            salt.as_slice(),
            b_pub.as_slice(),
        ) {
            std::result::Result::Ok(v) => v,
            Err(e) => return Err(anyhow!(e)),
        };

        myself
            .lock()
            .unwrap()
            .stream
            .write_all(format!("{:x?}", verifier.proof()).as_bytes())?;

        let mut buf = [0u8; 4096];
        let n = myself.lock().unwrap().stream.read(&mut buf)?;

        if verifier.verify_server(&buf[0..n]).is_err() {
            return Err(anyhow!(ERR_SRP_PROOF_FAILED));
        }

        Ok(verifier.key().to_vec())
    }

    fn init_server_srp(&mut self) -> Result<Vec<u8>, anyhow::Error> {
        let myself = Arc::new(Mutex::new(self));
        if !myself.lock().unwrap().stream.connected {
            return Err(anyhow!(ErrorKind::NotConnected));
        }

        let (user, pass) = myself.lock().unwrap().get_srp_creds();
        dbg!(hex::encode(user.clone()), hex::encode(pass.clone()));
        let server = SrpServer::<Blake2b256>::new(&G_4096);

        let mut salt = [0u8; 512];
        OsRng.fill_bytes(&mut salt);
        let cli = SrpClient::<Blake2b256>::new(&G_4096);
        let vi = cli.compute_verifier(user.as_slice(), pass.as_slice(), &salt);

        let mut buf = [0u8; 4096];
        let n = myself.lock().unwrap().stream.read(&mut buf)?;
        dbg!(n);
        let creds = std::str::from_utf8(&buf[0..n])?;
        dbg!(" == CLIENT ==> ", creds);

        // if !creds.contains(':') {
        //     return Err(anyhow!(ERR_INVALID_SRP_CREDS));
        // }

        let (username, a_pub_str) = creds.split_once(':').unwrap();
        let a_pub = hex::decode(a_pub_str)?;
        let user_str = hex::encode(user);
        dbg!(user_str.clone());

        // if username != user_str.as_str() {
        //     return Err(anyhow!(ERR_INVALID_SRP_CREDS));
        // }

        let mut b = [0u8; 512]; // Should be 512
        OsRng.fill_bytes(&mut b);
        let b_pub = server.compute_public_ephemeral(&b, &vi);

        myself
            .lock()
            .unwrap()
            .stream
            .write_all(format!("{}:{}", hex::encode(b), hex::encode(b_pub.clone())).as_bytes())?;

        dbg!(
            "<=== SERVER == ",
            format!("{}:{}", hex::encode(b), hex::encode(b_pub))
        );

        let verifier = match server.process_reply(&b, &vi, a_pub.as_slice()) {
            std::result::Result::Ok(v) => v,
            Err(e) => return Err(anyhow!(e)),
        };

        let n = myself.lock().unwrap().stream.read(&mut buf)?;
        dbg!(n);
        // let proof = format!("{:x?}", &buf[0..n]);
        dbg!("== CLIENT ===> ", hex::encode(&buf[0..n]));

        if verifier.verify_client(&buf[0..n]).is_err() {
            return Err(anyhow!(ERR_SRP_PROOF_FAILED));
        }

        myself
            .lock()
            .unwrap()
            .stream
            .write_all(hex::encode(verifier.proof()).as_bytes())?;

        dbg!(verifier.key());
        Ok(verifier.key().to_vec())
    }

    fn get_srp_creds(&mut self) -> (Vec<u8>, Vec<u8>) {
        let username_md5 = md5::compute(self.secret.clone());
        // let username = blake2b256(username_md5.as_slice()).unwrap(); // blake3::hash(username_md5.as_slice());
        let mut hasher = Sha256::new();
        hasher.update(self.secret.clone());
        let password_sha256 = hasher.finalize();
        //let password = blake2b256(&password_sha256).unwrap(); // blake3::hash(&password_sha256);
        (username_md5.to_vec(), password_sha256.to_vec())
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
    /// if let Err(e) = qsock.dial(){
    ///     panic!("{}", e);
    /// }
    /// let result = qsock.set_read_timeout(Some(Duration::new(0, 0)));
    /// let err = result.unwrap_err();
    /// assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput)
    /// ```
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        if !self.stream.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        self.stream
            .tcp_stream
            .as_mut()
            .unwrap()
            .set_read_timeout(dur)
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
    /// if let Err(e) = qsock.dial(){
    ///     panic!("{}", e);
    /// }
    /// let result = qsock.set_read_timeout(Some(Duration::new(0, 0)));
    /// qsock.set_write_timeout(None).expect("set_write_timeout call failed");
    /// ```
    pub fn set_write_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        if !self.stream.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        self.stream
            .tcp_stream
            .as_mut()
            .unwrap()
            .set_write_timeout(dur)
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
    /// if let Err(e) = qsock.dial() {
    ///     panic!("{}", e)
    /// }
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
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        if !self.stream.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        self.stream
            .tcp_stream
            .as_mut()
            .unwrap()
            .set_nonblocking(nonblocking)
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
    /// if let Err(e) = qsock.dial() {
    ///     panic!("{}", e);
    /// }
    /// qsock.shutdown(Shutdown::Both).expect("shutdown call failed");
    /// ```    
    pub fn shutdown(&mut self, how: std::net::Shutdown) -> std::io::Result<()> {
        if !self.stream.connected {
            return Err(std::io::Error::from(ErrorKind::NotConnected));
        }
        self.stream.tcp_stream.as_mut().unwrap().shutdown(how)
    }
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
        std::result::Result::Ok(ServerCertVerified::assertion())
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
///     0xC0, 0xDE, 0x30, 0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07,
///     0x15, 0x2d, 0x23, 0x4b, 0x70, 0x1,
/// ];
///
/// let knock = match qsocket::new_knock_sequence("123", 0) {
///     Ok(k) => k,
///     Err(e) => panic!("{}", e),
/// };
/// assert!(knock.iter().eq(test_case.iter()));
/// ```
pub fn new_knock_sequence(secret: &str, tag: u8) -> Result<[u8; 20], std::io::Error> {
    let digest = md5::compute(secret);
    let mut knock: [u8; 20] = Default::default();
    knock[0] = KNOCK_HEADER_B1;
    knock[1] = KNOCK_HEADER_B2;
    knock[2] = calc_checksum(digest.as_slice(), KNOCK_CHECKSUM_BASE);
    digest.as_slice().read_exact(knock[3..19].as_mut())?;
    knock[19] = tag;
    std::result::Result::Ok(knock)
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
        checksum += ((*i << 2) % base) as u32;
    }
    (checksum % base as u32) as u8
}

#[cfg(test)]
mod tests {
    use crate::new_knock_sequence;

    #[test]
    fn test_new_knock_sequence() {
        let test_secret = "123";
        let test_tag = 1;
        let knock = new_knock_sequence(test_secret, test_tag).unwrap();
        let test_case: [u8; 20] = [
            0xC0, 0xDE, 0xD6, 0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07,
            0x15, 0x2d, 0x23, 0x4b, 0x70, 0x1,
        ];

        for i in 0..knock.len() {
            assert_eq!(test_case[i], knock[i]);
        }
    }
}

pub fn get_default_tag() -> u8 {
    let mut tag: u8 = 0;
    // Determine OS...
    if cfg!(target_os = "linux") {
        tag |= device_id_tag::OS_LINUX;
    }
    if cfg!(target_os = "windows") {
        tag |= device_id_tag::OS_WINDOWS;
    }
    if cfg!(target_os = "macos") {
        tag |= device_id_tag::OS_DARWIN;
    }
    if cfg!(target_os = "android") {
        tag |= device_id_tag::OS_ANDROID;
    }
    if cfg!(target_os = "ios") {
        tag |= device_id_tag::OS_IOS;
    }
    if cfg!(target_os = "freebsd") {
        tag |= device_id_tag::OS_FREEBSD;
    }
    if cfg!(target_os = "openbsd") {
        tag |= device_id_tag::OS_OPENBSD;
    }

    // Determine architecture...
    if cfg!(target_arch = "x86_64") {
        tag |= device_id_tag::ARCH_AMD64;
    }
    if cfg!(target_arch = "i686") {
        tag |= device_id_tag::ARCH_386;
    }
    if cfg!(target_arch = "aarch64") {
        tag |= device_id_tag::ARCH_ARM64;
    }
    if cfg!(target_arch = "arm") {
        tag |= device_id_tag::ARCH_ARM;
    }
    if cfg!(target_arch = "mips") {
        tag |= device_id_tag::ARCH_MIPS;
    }
    if cfg!(target_arch = "mips64") {
        tag |= device_id_tag::ARCH_MIPS64;
    }
    if cfg!(target_arch = "mips64le") {
        tag |= device_id_tag::ARCH_MIPS64LE;
    }

    tag
}

// fn blake2b256(input: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
//     use blake2::digest::{Update, VariableOutput};
//     let mut hasher = Blake2bVar::new(32).unwrap();
//     hasher.update(input);
//     let mut buf = [0u8; 32];
//     hasher.finalize_variable(&mut buf).unwrap();
//     Ok(buf.to_vec())
// }
