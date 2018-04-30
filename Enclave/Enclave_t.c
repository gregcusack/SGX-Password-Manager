#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_create_user_t {
	uint8_t* ms_create_pw;
	size_t ms_pw_len;
	uint8_t* ms_cipher_pword;
	size_t ms_cipher_pword_len;
	uint8_t* ms_iv;
	size_t ms_iv_len;
	uint8_t* ms_mac;
	size_t ms_mac_len;
} ms_create_user_t;

typedef struct ms_check_user_t {
	uint8_t* ms_login_attempt;
	size_t ms_pw_len;
	uint8_t* ms_v_pword;
	size_t ms_v_pword_len;
	uint8_t* ms_iv;
	size_t ms_iv_len;
	uint8_t* ms_mac;
	size_t ms_mac_len;
	uint8_t* ms_found;
	size_t ms_found_len;
} ms_check_user_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
} ms_unseal_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL sgx_create_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_create_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_create_user_t* ms = SGX_CAST(ms_create_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_create_pw = ms->ms_create_pw;
	size_t _tmp_pw_len = ms->ms_pw_len;
	size_t _len_create_pw = _tmp_pw_len;
	uint8_t* _in_create_pw = NULL;
	uint8_t* _tmp_cipher_pword = ms->ms_cipher_pword;
	size_t _tmp_cipher_pword_len = ms->ms_cipher_pword_len;
	size_t _len_cipher_pword = _tmp_cipher_pword_len;
	uint8_t* _in_cipher_pword = NULL;
	uint8_t* _tmp_iv = ms->ms_iv;
	size_t _tmp_iv_len = ms->ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_len = ms->ms_mac_len;
	size_t _len_mac = _tmp_mac_len;
	uint8_t* _in_mac = NULL;

	CHECK_UNIQUE_POINTER(_tmp_create_pw, _len_create_pw);
	CHECK_UNIQUE_POINTER(_tmp_cipher_pword, _len_cipher_pword);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_create_pw != NULL && _len_create_pw != 0) {
		_in_create_pw = (uint8_t*)malloc(_len_create_pw);
		if (_in_create_pw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_create_pw, _tmp_create_pw, _len_create_pw);
	}
	if (_tmp_cipher_pword != NULL && _len_cipher_pword != 0) {
		if ((_in_cipher_pword = (uint8_t*)malloc(_len_cipher_pword)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cipher_pword, 0, _len_cipher_pword);
	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ((_in_iv = (uint8_t*)malloc(_len_iv)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_iv, 0, _len_iv);
	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ((_in_mac = (uint8_t*)malloc(_len_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mac, 0, _len_mac);
	}

	create_user(_in_create_pw, _tmp_pw_len, _in_cipher_pword, _tmp_cipher_pword_len, _in_iv, _tmp_iv_len, _in_mac, _tmp_mac_len);
err:
	if (_in_create_pw) free(_in_create_pw);
	if (_in_cipher_pword) {
		memcpy(_tmp_cipher_pword, _in_cipher_pword, _len_cipher_pword);
		free(_in_cipher_pword);
	}
	if (_in_iv) {
		memcpy(_tmp_iv, _in_iv, _len_iv);
		free(_in_iv);
	}
	if (_in_mac) {
		memcpy(_tmp_mac, _in_mac, _len_mac);
		free(_in_mac);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_check_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_check_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_check_user_t* ms = SGX_CAST(ms_check_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_login_attempt = ms->ms_login_attempt;
	size_t _tmp_pw_len = ms->ms_pw_len;
	size_t _len_login_attempt = _tmp_pw_len;
	uint8_t* _in_login_attempt = NULL;
	uint8_t* _tmp_v_pword = ms->ms_v_pword;
	size_t _tmp_v_pword_len = ms->ms_v_pword_len;
	size_t _len_v_pword = _tmp_v_pword_len;
	uint8_t* _in_v_pword = NULL;
	uint8_t* _tmp_iv = ms->ms_iv;
	size_t _tmp_iv_len = ms->ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_len = ms->ms_mac_len;
	size_t _len_mac = _tmp_mac_len;
	uint8_t* _in_mac = NULL;
	uint8_t* _tmp_found = ms->ms_found;
	size_t _tmp_found_len = ms->ms_found_len;
	size_t _len_found = _tmp_found_len;
	uint8_t* _in_found = NULL;

	CHECK_UNIQUE_POINTER(_tmp_login_attempt, _len_login_attempt);
	CHECK_UNIQUE_POINTER(_tmp_v_pword, _len_v_pword);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);
	CHECK_UNIQUE_POINTER(_tmp_found, _len_found);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_login_attempt != NULL && _len_login_attempt != 0) {
		_in_login_attempt = (uint8_t*)malloc(_len_login_attempt);
		if (_in_login_attempt == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_login_attempt, _tmp_login_attempt, _len_login_attempt);
	}
	if (_tmp_v_pword != NULL && _len_v_pword != 0) {
		_in_v_pword = (uint8_t*)malloc(_len_v_pword);
		if (_in_v_pword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_v_pword, _tmp_v_pword, _len_v_pword);
	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_iv, _tmp_iv, _len_iv);
	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mac, _tmp_mac, _len_mac);
	}
	if (_tmp_found != NULL && _len_found != 0) {
		if ((_in_found = (uint8_t*)malloc(_len_found)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_found, 0, _len_found);
	}

	check_user(_in_login_attempt, _tmp_pw_len, _in_v_pword, _tmp_v_pword_len, _in_iv, _tmp_iv_len, _in_mac, _tmp_mac_len, _in_found, _tmp_found_len);
err:
	if (_in_login_attempt) free(_in_login_attempt);
	if (_in_v_pword) free(_in_v_pword);
	if (_in_iv) free(_in_iv);
	if (_in_mac) free(_in_mac);
	if (_in_found) {
		memcpy(_tmp_found, _in_found, _len_found);
		free(_in_found);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_plaintext, _tmp_plaintext, _len_plaintext);
	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}

	ms->ms_retval = seal(_in_plaintext, _tmp_plaintext_len, _in_sealed_data, _tmp_sealed_size);
err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_t* ms = SGX_CAST(ms_unseal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	uint32_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}

	ms->ms_retval = unseal(_in_sealed_data, _tmp_sealed_size, _in_plaintext, _tmp_plaintext_len);
err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_plaintext) {
		memcpy(_tmp_plaintext, _in_plaintext, _len_plaintext);
		free(_in_plaintext);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_create_user, 0},
		{(void*)(uintptr_t)sgx_check_user, 0},
		{(void*)(uintptr_t)sgx_seal, 0},
		{(void*)(uintptr_t)sgx_unseal, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][4];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

