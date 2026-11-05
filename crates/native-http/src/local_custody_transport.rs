//! Bounded local IPC primitives shared by role-specific custody transports.
//! Frame contents and admission decisions remain with each role.

use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub type Refuse = fn() -> io::Error;

pub async fn read_frame(
    stream: &mut UnixStream,
    maximum: usize,
    refuse: Refuse,
) -> io::Result<Vec<u8>> {
    let size: u32 = stream.read_u32().await?;
    let size: usize = usize::try_from(size).map_err(|_| refuse())?;
    if size == 0 || size > maximum {
        return Err(refuse());
    }
    let mut bytes: Vec<u8> = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    let mut trailing: [u8; 1] = [0];
    if stream.read(&mut trailing).await? != 0 {
        return Err(refuse());
    }
    Ok(bytes)
}

/// Writes exactly the supplied bytes; each caller applies its own role cap.
pub async fn write_frame(stream: &mut UnixStream, bytes: &[u8], refuse: Refuse) -> io::Result<()> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| refuse())?)
        .await?;
    stream.write_all(bytes).await?;
    stream.shutdown().await
}

pub fn authenticate(stream: &UnixStream, expected: u32, refuse: Refuse) -> io::Result<()> {
    if stream.peer_cred()?.uid() != expected {
        return Err(refuse());
    }
    Ok(())
}
