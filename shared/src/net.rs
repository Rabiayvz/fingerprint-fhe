// Length-prefixed JSON framing over any Read/Write (used for the client<->server
// TCP connection). Replaces the old file-based IPC (../exchange/*.json + polling).

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};

pub const SERVER_ADDR: &str = "127.0.0.1:7878";

pub fn write_message<W: Write, T: Serialize>(
    stream: &mut W,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::to_vec(value)?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

pub fn read_message<R: Read, T: DeserializeOwned>(
    stream: &mut R,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;

    Ok(serde_json::from_slice(&payload)?)
}
