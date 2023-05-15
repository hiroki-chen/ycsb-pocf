#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_sgx_tvl_verify_qve_report_and_identity_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	const sgx_ql_qe_report_info_t* ms_p_qve_report_info;
	time_t ms_expiration_check_date;
	uint32_t ms_collateral_expiration_status;
	sgx_ql_qv_result_t ms_quote_verification_result;
	const uint8_t* ms_p_supplemental_data;
	uint32_t ms_supplemental_data_size;
	sgx_isv_svn_t ms_qve_isvsvn_threshold;
} ms_sgx_tvl_verify_qve_report_and_identity_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t sgx_tvl_verify_qve_report_and_identity(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const sgx_ql_qe_report_info_t* p_qve_report_info, time_t expiration_check_date, uint32_t collateral_expiration_status, sgx_ql_qv_result_t quote_verification_result, const uint8_t* p_supplemental_data, uint32_t supplemental_data_size, sgx_isv_svn_t qve_isvsvn_threshold)
{
	sgx_status_t status;
	ms_sgx_tvl_verify_qve_report_and_identity_t ms;
	ms.ms_p_quote = p_quote;
	ms.ms_quote_size = quote_size;
	ms.ms_p_qve_report_info = p_qve_report_info;
	ms.ms_expiration_check_date = expiration_check_date;
	ms.ms_collateral_expiration_status = collateral_expiration_status;
	ms.ms_quote_verification_result = quote_verification_result;
	ms.ms_p_supplemental_data = p_supplemental_data;
	ms.ms_supplemental_data_size = supplemental_data_size;
	ms.ms_qve_isvsvn_threshold = qve_isvsvn_threshold;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

