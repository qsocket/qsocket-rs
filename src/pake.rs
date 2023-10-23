use crate::QSocketError;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{Read, Write};

pub enum PakeMode {
    Client,
    Server,
}

pub fn init_pake_handshake<S>(
    mode: PakeMode,
    mut sock: S,
    password: String,
) -> Result<Vec<u8>, QSocketError>
where
    S: Read + Write + std::marker::Send,
{
    let pass_digest = md5::compute(password.clone()).to_vec();
    #[allow(unused_assignments)]
    let mut state: Option<Spake2<Ed25519Group>> = None;
    #[allow(unused_assignments)]
    let mut outbound_msg: Vec<u8> = Vec::new();

    match mode {
        PakeMode::Client => {
            let (s, o) = Spake2::<Ed25519Group>::start_a(
                &Password::new(pass_digest.clone()),
                &Identity::new(&pass_digest[..4]),
                &Identity::new(&pass_digest[..4]),
            );
            state = Some(s);
            outbound_msg = o;
        }
        PakeMode::Server => {
            let (s, o) = Spake2::<Ed25519Group>::start_b(
                &Password::new(pass_digest.clone()),
                &Identity::new(&pass_digest[..4]),
                &Identity::new(&pass_digest[..4]),
            );
            state = Some(s);
            outbound_msg = o;
        }
    }

    sock.write_all(&outbound_msg)?;
    let mut inbound_msg = vec![0; 1024];
    let n = sock.read(&mut inbound_msg)?;
    let key = state.unwrap().finish(&inbound_msg[..n]);
    if key.is_err() {
        return Err(QSocketError::PakeError);
    }
    Ok(key.unwrap())
}
