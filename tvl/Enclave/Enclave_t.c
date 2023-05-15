#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_sgx_tvl_verify_qve_report_and_identity(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_tvl_verify_qve_report_and_identity_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_tvl_verify_qve_report_and_identity_t* ms = SGX_CAST(ms_sgx_tvl_verify_qve_report_and_identity_t*, pms);
	ms_sgx_tvl_verify_qve_report_and_identity_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_tvl_verify_qve_report_and_identity_t), ms, sizeof(ms_sgx_tvl_verify_qve_report_and_identity_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_p_quote = __in_ms.ms_p_quote;
	uint32_t _tmp_quote_size = __in_ms.ms_quote_size;
	size_t _len_p_quote = _tmp_quote_size;
	uint8_t* _in_p_quote = NULL;
	const sgx_ql_qe_report_info_t* _tmp_p_qve_report_info = __in_ms.ms_p_qve_report_info;
	size_t _len_p_qve_report_info = 1 * sizeof(sgx_ql_qe_report_info_t);
	sgx_ql_qe_report_info_t* _in_p_qve_report_info = NULL;
	const uint8_t* _tmp_p_supplemental_data = __in_ms.ms_p_supplemental_data;
	uint32_t _tmp_supplemental_data_size = __in_ms.ms_supplemental_data_size;
	size_t _len_p_supplemental_data = _tmp_supplemental_data_size;
	uint8_t* _in_p_supplemental_data = NULL;
	quote3_error_t _in_retval;

	if (sizeof(*_tmp_p_qve_report_info) != 0 &&
		1 > (SIZE_MAX / sizeof(*_tmp_p_qve_report_info))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_quote, _len_p_quote);
	CHECK_UNIQUE_POINTER(_tmp_p_qve_report_info, _len_p_qve_report_info);
	CHECK_UNIQUE_POINTER(_tmp_p_supplemental_data, _len_p_supplemental_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_quote != NULL && _len_p_quote != 0) {
		if ( _len_p_quote % sizeof(*_tmp_p_quote) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_quote = (uint8_t*)malloc(_len_p_quote);
		if (_in_p_quote == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_quote, _len_p_quote, _tmp_p_quote, _len_p_quote)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qve_report_info != NULL && _len_p_qve_report_info != 0) {
		_in_p_qve_report_info = (sgx_ql_qe_report_info_t*)malloc(_len_p_qve_report_info);
		if (_in_p_qve_report_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qve_report_info, _len_p_qve_report_info, _tmp_p_qve_report_info, _len_p_qve_report_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_supplemental_data != NULL && _len_p_supplemental_data != 0) {
		if ( _len_p_supplemental_data % sizeof(*_tmp_p_supplemental_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_supplemental_data = (uint8_t*)malloc(_len_p_supplemental_data);
		if (_in_p_supplemental_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_supplemental_data, _len_p_supplemental_data, _tmp_p_supplemental_data, _len_p_supplemental_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = sgx_tvl_verify_qve_report_and_identity((const uint8_t*)_in_p_quote, _tmp_quote_size, (const sgx_ql_qe_report_info_t*)_in_p_qve_report_info, __in_ms.ms_expiration_check_date, __in_ms.ms_collateral_expiration_status, __in_ms.ms_quote_verification_result, (const uint8_t*)_in_p_supplemental_data, _tmp_supplemental_data_size, __in_ms.ms_qve_isvsvn_threshold);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_p_quote) free(_in_p_quote);
	if (_in_p_qve_report_info) free(_in_p_qve_report_info);
	if (_in_p_supplemental_data) free(_in_p_supplemental_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_sgx_tvl_verify_qve_report_and_identity, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


