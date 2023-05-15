use log::{debug, error};
use pobf_crypto::KeyPair;
use std::{
    io::{BufRead, BufReader, BufWriter, Error, ErrorKind, Read, Result, Write},
    net::TcpStream,
};

pub const DEFAULT_BUFFER_LEN: usize = 0x1000;

pub fn receive_vecaes_data(reader: &mut BufReader<TcpStream>, key: &KeyPair) -> Result<Vec<u8>> {
    let mut len = String::with_capacity(DEFAULT_BUFFER_LEN);
    reader.read_line(&mut len)?;
    let data_size = len[..len.len() - 1].parse::<usize>().or_else(|_| {
        error!("[-] Cannot parse the data length!");
        Err(Error::from(ErrorKind::InvalidData))
    })?;

    let mut data = vec![0u8; data_size];
    reader.read_exact(&mut data)?;

    // Decrypt the data.
    let decrypted_data = key.decrypt_with_smk(&data).or_else(|_| {
        error!("[-] Decryption failed");
        Err(Error::from(ErrorKind::InvalidData))
    })?;

    Ok(decrypted_data)
}

pub fn send_vecaes_data(
    writer: &mut BufWriter<TcpStream>,
    data: &[u8],
    key: &KeyPair,
) -> Result<()> {
    // Encrypt the data first.
    let encrypted_input = key.encrypt_with_smk(&data).map_err(|_| {
        error!("[-] Cannot encrypt the input.");
        Error::from(ErrorKind::InvalidData)
    })?;

    let batch_num = (encrypted_input.len() as f64 / DEFAULT_BUFFER_LEN as f64).ceil() as usize;

    writer
        .write(encrypted_input.len().to_string().as_bytes())
        .unwrap();
    writer.write(b"\n").unwrap();
    writer.flush().unwrap();

    for i in 0..batch_num {
        let begin = i * DEFAULT_BUFFER_LEN;
        let end = if (i + 1) * DEFAULT_BUFFER_LEN <= encrypted_input.len() {
            (i + 1) * DEFAULT_BUFFER_LEN
        } else {
            encrypted_input.len()
        };

        let size = writer.write(&encrypted_input[begin..end]).unwrap();
        debug!(
            "Batch #{}: wrote {} bytes, sent content {:?}",
            i,
            size,
            &encrypted_input[begin..end]
        );

        std::thread::sleep(std::time::Duration::from_millis(1));
        writer.flush().unwrap();
    }

    Ok(())
}
