use std::{
    io::{BufRead, BufReader, BufWriter, Error, ErrorKind, Read, Result, Write},
    net::TcpStream,
};

use log::info;
use pobf_crypto::{handle_sev_pubkey, KeyPair};

pub fn attest_and_perform_task(
    reader: &mut BufReader<TcpStream>,
    writer: &mut BufWriter<TcpStream>,
    key_pair: &mut KeyPair,
    data: &[u8],
) -> Result<Vec<u8>> {
    let public_key = &key_pair.pub_k;
    info!("[+] Receiving the attestation report");
    let mut len = String::with_capacity(128);
    reader.read_line(&mut len)?;
    let report_len = len[..len.len() - 1]
        .parse::<usize>()
        .map_err(|_| Error::from(ErrorKind::InvalidData))?;
    let mut report = vec![0u8; report_len];
    reader.read_exact(&mut report)?;

    info!("[+] Sending public key");
    writer.write_all(public_key.as_ref())?;
    writer.flush()?;

    info!("[+] Receiving peer public key");
    let peer_pub_key = handle_sev_pubkey(reader).unwrap();
    key_pair.compute_shared_key(&peer_pub_key, b"").unwrap();

    info!("[+] Sending data...");
    // Read the data and encrypt it.
    writer.write_all(data.len().to_string().as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.write_all(&data)?;
    writer.flush()?;

    info!("[+] Receiving the data...");
    len.clear();
    reader.read_line(&mut len)?;
    let buf_len = len[..len.len() - 1].parse::<usize>().unwrap();
    let mut buf = vec![0u8; buf_len];
    reader.read_exact(&mut buf)?;

    // Decrypt the data.
    Ok(key_pair.decrypt_with_smk(&buf).unwrap())
}
