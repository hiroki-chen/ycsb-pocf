use sgx_types::{error::Quote3Error, types::*};

extern "C" {
    pub fn sgx_tvl_verify_qve_report_and_identity(
        eid: EnclaveId,
        retval: *mut Quote3Error,
        p_quote: *const u8,
        quote_size: u32,
        p_qve_report_info: *const QlQeReportInfo,
        expiration_check_date: i64,
        collateral_expiration_status: u32,
        quote_verification_result: QlQvResult,
        p_supplemental_data: *const u8,
        supplemental_data_size: u32,
        qve_isvsvn_threshold: u16,
    ) -> Quote3Error;
}
