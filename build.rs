use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=TEE_TYPE");
    println!("cargo:rerun-if-changed=build.rs");

    let tee_type = env::var("TEE_TYPE").unwrap_or_else(|_| "SGX".to_string());

    if tee_type.to_uppercase().as_str() == "SGX" {
        Command::new("make")
            .arg("-j")
            .output()
            .expect("Failed to build TVL library");
        println!("cargo:rerun-if-env-changed=SGX_MODE");

        let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
        let mode = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

        println!("cargo:rustc-link-search=native=./lib");
        println!("cargo:rustc-link-lib=static=enclave_u");

        println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
        println!("cargo:rustc-link-lib=dylib=sgx_dcap_quoteverify");
        println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");

        match mode.as_str() {
            "SW" | "SIM" => {
                println!("cargo:rustc-link-lib=dylib=sgx_urts_sim")
            }
            "HW" | "HYPER" => {
                println!("cargo:rustc-link-lib=dylib=sgx_urts");
            }
            _ => {
                println!("cargo:rustc-link-lib=dylib=sgx_urts")
            }
        }
    }
}
