# QSocket Rust

[![Build Status](https://github.com/qsocket/qsocket-rs/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/qsocket/qsocket-rs/actions/workflows/build.yml?query=branch%3Amaster)
[![Coverage Status (codecov.io)](https://codecov.io/gh/qsocket/qsocket-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/qsocket/qsocket/)
[![Documentation](https://docs.rs/qsocket/badge.svg)](https://docs.rs/qsocket/)

Rust library for qsocket...


## Usage
Usage is really simple, `qsocket_rs::new` function simply creates a new quantum socket with given secret, it includes all the functions of standard `std::net::TcpStream` sockets and also implements `io::Read/Write`. After creating a socket you need to dial the QSRN network by calling `qsocket_rs::Dial*` functions. Simple example below...
```rs
use qsocket;

/// Creates a new quantum socket instance.
///
/// `secret` value can be considered as the password for the QSocket connection,
/// It will be used for generating a 128bit unique identifier (UID) for the connection.
let mut qsock = qsocket::QSocket::new("my-secret", true);

/// Opens a TLS connection to the QSRN.
///
/// If the `verify_cert` parameter is true,
/// after establishing a TLS connection with the QSRN gate server,
/// the TLS certificate fingerprint will be validated with the hardcoded certificate fingerprint value `QSRN_CERT_FINGERPRINT`.
///
/// If the connection fails due to network related errors,
/// function will return the corresponding error, in the case of
/// QSRN related errors the function will return one the ERR_KNOCK_* errors.
if let Err(e) = qsock.dial() {           
    panic!("{}", e);
}
``` 

After dialing the QSRN, socket is ready for read/write operations.