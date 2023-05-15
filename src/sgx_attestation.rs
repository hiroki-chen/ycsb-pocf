use std::{
    io::{BufRead, BufReader, BufWriter, Error, ErrorKind, Read, Result, Write},
    net::TcpStream,
    time::SystemTime,
};

use log::{error, info, warn};
use pobf_crypto::{handle_enclave_pubkey, KeyPair, KDF_MAGIC_STR};

#[allow(unused_imports)]
use rand::{rngs::OsRng, RngCore};
#[allow(unused_imports)]
use sgx_types::{
    error::Quote3Error,
    function::{
        sgx_qv_get_quote_supplemental_data_size, sgx_qv_set_enclave_load_policy,
        sgx_qv_verify_quote,
    },
    types::{
        QlQeReportInfo, QlQvResult, QlQvSupplemental, QlRequestPolicy, TargetInfo, MAC_128BIT_SIZE,
    },
};
use sgx_urts::enclave::SgxEnclave;
use spin::Once;

static VERIFICATION_ENCLAVE: Once<SgxEnclave> = Once::new();

use crate::{
    ffi::sgx_tvl_verify_qve_report_and_identity,
    sgx_networking::{receive_vecaes_data, send_vecaes_data, DEFAULT_BUFFER_LEN},
};

const ENCLAVE_FILE: &'static str = "./lib/enclave.signed.so";

pub fn init_verification_library() {
    VERIFICATION_ENCLAVE.call_once(|| SgxEnclave::create(ENCLAVE_FILE, false).unwrap());
}

pub fn attest_and_perform_task(
    reader: &mut BufReader<TcpStream>,
    writer: &mut BufWriter<TcpStream>,
    key_pair: &mut KeyPair,
    data: &[u8],
) -> Result<Vec<u8>> {
    let public_key = &key_pair.pub_k;
    let pubkey_signature = &key_pair.signature;

    // Send remote attestation type.
    writer.write(b"1").unwrap();
    writer.write(b"\n").unwrap();
    writer.flush().unwrap();

    // Send public key and the signature.
    writer.write(&public_key.as_ref()[1..]).unwrap();
    writer.write(b"\n").unwrap();
    writer
        .write(pubkey_signature.len().to_string().as_bytes())
        .unwrap();
    writer.write(b"\n").unwrap();
    writer.flush().unwrap();

    writer.write(&pubkey_signature).unwrap();
    writer.write(b"\n").unwrap();
    writer.flush().unwrap();

    info!("[+] Waiting for public key of the enclave.");
    let enclave_pubkey = handle_enclave_pubkey(reader)
        .map_err(|_| {
            error!("[-] Failed to parse enclave public key.");
            return Error::from(ErrorKind::InvalidData);
        })
        .unwrap();
    info!("[+] Succeeded.");

    info!("[+] Computing ephemeral session key.");
    key_pair
        .compute_shared_key(&enclave_pubkey, KDF_MAGIC_STR.as_bytes())
        .unwrap();
    info!("[+] Succeeded.");

    // Verify the quote sent from the enclave.
    info!("[+] Verifying the quote...");
    verify_dcap_quote(reader, &key_pair)?;
    info!("[+] Quote valid!");

    // Send initial encrypted data. Trivial data 1,2,3 are just for test.
    info!("[+] Sending encrypted vector data.");
    send_vecaes_data(writer, data, &key_pair)?;
    info!("[+] Succeeded.");

    // Receive the computed result.
    info!("[+] Receiving the data.");
    let data = receive_vecaes_data(reader, &key_pair)?;
    info!("[+] Succeeded.");

    std::fs::write("/tmp/output.txt", &data).unwrap();

    Ok(data)
}

/// The relying party verifies the quote. It fetches the attestation collateral associated with the quote from the data center
/// caching service and uses it to verify the signature.
pub fn verify_dcap_quote(reader: &mut BufReader<TcpStream>, key_pair: &KeyPair) -> Result<()> {
    let mut len = String::with_capacity(DEFAULT_BUFFER_LEN);
    reader.read_line(&mut len).unwrap();

    let quote_size = len[..len.len() - 1].parse::<usize>().or_else(|e| {
        error!("[-] Cannot parse quote length due to {:?}.", e);
        Err(Error::from(ErrorKind::InvalidData))
    })?;

    let mut quote = vec![0u8; quote_size + 1];
    reader.read_exact(&mut quote).unwrap();
    quote.truncate(quote_size);

    // Receive target info.
    len.clear();
    reader.read_line(&mut len).unwrap();
    let ti_len_network = len[..len.len() - 1].parse::<usize>().or_else(|e| {
        error!("[-] Cannot parse quote length due to {:?}.", e);
        Err(Error::from(ErrorKind::InvalidData))
    })?;

    if std::mem::size_of::<TargetInfo>() + MAC_128BIT_SIZE != ti_len_network {
        error!("[-] Corrupted target info.");
        return Err(Error::from(ErrorKind::InvalidData));
    }

    let mut ti = vec![0u8; ti_len_network + 1];
    reader.read_exact(&mut ti).unwrap();
    ti.truncate(ti_len_network);

    #[cfg(feature = "sgx_no_verify")]
    return Ok(());

    #[cfg(not(feature = "sgx_no_verify"))]
    {
        // Decrypt them.
        let decrypted_ti = key_pair.decrypt_with_smk(&ti).or_else(|e| {
            error!("[-] Decryption failed due to {:?}.", e);
            Err(Error::from(ErrorKind::InvalidData))
        })?;
        let decrypted_quote = key_pair.decrypt_with_smk(&quote).or_else(|e| {
            error!("[-] Decryption failed due to {:?}.", e);
            Err(Error::from(ErrorKind::InvalidData))
        })?;

        let expiration_check_data: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();
        let mut p_collateral_expiration_status = 1u32;
        let mut p_quote_verification_result = QlQvResult::default();
        let mut p_qve_report_info = QlQeReportInfo::default();
        let mut supplemental_data_size = 0u32;
        let mut supplemental_data = QlQvSupplemental::default();

        // Generate a nonce and fill the report.
        let mut rand_nonce = vec![0u8; 16];
        OsRng.fill_bytes(&mut rand_nonce);
        p_qve_report_info.nonce.rand.copy_from_slice(&rand_nonce);

        // Fill target info.
        unsafe {
            p_qve_report_info.app_enclave_target_info =
                std::ptr::read(decrypted_ti.as_ptr() as *const _);
        }

        // Load policy.
        info!("[+] Performing sgx_qv_set_enclave_load_policy... ");
        let res = unsafe { sgx_qv_set_enclave_load_policy(QlRequestPolicy::Ephemeral) };
        if res != Quote3Error::Success {
            info!(
                "[-] sgx_qv_set_enclave_load_policy failed due to {:?}.",
                res
            );

            return Err(Error::from(ErrorKind::Unsupported));
        }

        info!("[+] sgx_qv_set_enclave_load_policy successfully executed!");

        // Call the DCAP quote verify library to get the supplemental data size.
        info!("[+] Performing sgx_qv_get_quote_supplemental_data_size... ");
        let res = unsafe { sgx_qv_get_quote_supplemental_data_size(&mut supplemental_data_size) };
        if res != Quote3Error::Success {
            info!(
                "[-] sgx_qv_get_quote_supplemental_data_size failed due to {:?}.",
                res
            );

            return Err(Error::from(ErrorKind::Unsupported));
        }
        info!(
            "[+] sgx_qv_get_quote_supplemental_data_size successfully executed! Size = {}.",
            supplemental_data_size
        );

        // Check length.
        if supplemental_data_size as usize != std::mem::size_of::<QlQvSupplemental>() {
            warn!("[!] Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");
            supplemental_data_size = 0u32;
        }

        let p_supplemental_data = match supplemental_data_size {
            0 => std::ptr::null_mut(),
            _ => &mut supplemental_data,
        };

        info!("[+] Performing sgx_qv_verify_quote... ");

        let res = unsafe {
            sgx_qv_verify_quote(
                decrypted_quote.as_ptr(),
                decrypted_quote.len() as u32,
                std::ptr::null(),
                expiration_check_data,
                &mut p_collateral_expiration_status,
                &mut p_quote_verification_result,
                &mut p_qve_report_info,
                supplemental_data_size,
                p_supplemental_data as *mut u8,
            )
        };

        if res != Quote3Error::Success {
            info!("[-] sgx_qv_verify_quote failed due to {:?}.", res);

            return Err(Error::from(ErrorKind::Unsupported));
        }

        info!("[+] Successfully verified the quote!");

        // Call sgx_dcap_tvl API in Intel built enclave to verify QvE's report and identity.
        // This function allows a user’s enclave to more easily verify the QvE REPORT returned in the
        // p_qve_report_info parameter in the Verify Quote API was generated by the Intel QvE at an expected TCB
        // level.
        verify_qve_report_and_identity(
            &quote,
            &p_qve_report_info,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_supplemental_data,
            supplemental_data_size,
        )
    }
}

pub fn verify_qve_report_and_identity(
    p_quote: &Vec<u8>,
    p_qve_report_info: &QlQeReportInfo,
    collateral_expiration_status: u32,
    quote_verification_result: QlQvResult,
    p_supplemental_data: *const QlQvSupplemental,
    supplemental_data_size: u32,
) -> Result<()> {
    // Verify the identity of QvE.
    let mut ret_val = Quote3Error::Success;
    let expiration_check_date = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
    // e.g. You can get latest QvE ISVSVN in QvE Identity JSON file from
    // https://api.trustedservices.intel.com/sgx/certification/v2/qve/identity
    // Make sure you are using trusted & latest QvE ISV SVN as threshold
    //
    let qve_isvsvn_threshold = 5u16;

    let res = unsafe {
        sgx_tvl_verify_qve_report_and_identity(
            VERIFICATION_ENCLAVE.get().unwrap().eid(),
            &mut ret_val,
            p_quote.as_ptr(),
            p_quote.len() as u32,
            p_qve_report_info,
            expiration_check_date,
            collateral_expiration_status,
            quote_verification_result,
            p_supplemental_data as *const u8,
            supplemental_data_size,
            qve_isvsvn_threshold,
        )
    };

    match res {
        Quote3Error::Success => {
            info!("[+] QvE's identity checked and passed.");
            Ok(())
        }

        e => {
            error!("[-] Invalid QvE! Please check the platform. Error: {:?}", e);
            Err(Error::from(ErrorKind::InvalidData))
        }
    }
}
