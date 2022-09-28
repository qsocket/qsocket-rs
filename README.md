# QSocket Rust
Rust library for qsocket...

## Usage
Usage is really simple, `qsocket_rs::new` function simply creates a new quantum socket with given secret, it includes all the functions of standard `std::net::TcpStream` sockets and also implements `io::Read/Write`. After creating a socket you need to dial the QSRN network by calling `qsocket_rs::Dial*` functions. Simple example below...
```rs
    // qsocket_rs::Qsocket::new(
    //    First param: Secret (e.g. password) for the socket.
    //    Second param: Just a ID tag for your socket, can be left 0
    // )
    let mut qsock = qsocket_rs::Qsocket::new("my-secret", 0); 
    // Qsocket.dial(
    //    First param: Use TLS connection.
    //    Second param: Enable TLS certificate verification.
    // )
    let mut mysock = match qsock.dial(true, true) {           
        Ok(s) => s,
        Err(e) => panic!(e),
    }
``` 

After dialing the QSRN, socket is ready for read/write operations.