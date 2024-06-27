use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const CODE_GRANULARITY_MS: u64 = 1000 * 60;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();

    if args.len() < 2 {
        eprintln!("Usage: {} <shared key>", args.nth(0).unwrap_or_default());
        std::process::exit(1);
    }
    let key = args
        .nth(1)
        .expect("expected argument to be present and decode");
    if key.chars().any(|c| c == ' ' || c == '\n') {
        eprintln!("WARNING: passed key contains whitespace");
    }

    let code_validity_ms: u32 = 1000 * 60 * 60; // 1 hour

    let timestamp_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    println!("Current stamp: {}", timestamp_ms);
    let interval: u64 = timestamp_ms / <u32 as Into<u64>>::into(code_validity_ms);
    let interval_beginning_timestamp_ms: u64 =
        interval * <u32 as Into<u64>>::into(code_validity_ms);
    let adjusted_timestamp: u64 = interval_beginning_timestamp_ms / CODE_GRANULARITY_MS;
    let mut big_endian_timestamp = [0; std::mem::size_of::<u64>()];
    BigEndian::write_u64(&mut big_endian_timestamp, adjusted_timestamp as u64);

    let mut mac = HmacSha1::new_from_slice(key.as_bytes())?;
    mac.update(&big_endian_timestamp[..]);
    let digest = mac.finalize().into_bytes();
    println!("digest ({} bytes): {}", digest.len(), hex::encode(&digest));

    let offset = digest.last().expect("digest is not empty") & 0xf;
    println!("offset = {:02x}", offset);
    // read as i32 and clear sign bit
    let result = BigEndian::read_i32(&digest[offset as usize..][..4]) & 0x7fffffff;
    println!("result = {:08x}", result);

    let valid_from_ms = interval_beginning_timestamp_ms;
    let valid_to_ms = valid_from_ms + <u32 as Into<u64>>::into(code_validity_ms);

    let code: i32 = result % 1000000;
    println!();
    println!("Code: {:06}", code);
    let remaining_sec = (valid_to_ms - timestamp_ms) / 1000;
    println!(
        "Expires in: {:02}:{:02} ({} sec)",
        remaining_sec / 60,
        remaining_sec % 60,
        remaining_sec
    );

    Ok(())
}
