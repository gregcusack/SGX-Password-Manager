#include "Enclave_u.h"
#include <errno.h>

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

typedef struct ms_encrypt_credentials_t {
	uint8_t* ms_create_pw;
	size_t ms_buf_len;
	uint8_t* ms_cur_web;
	uint8_t* ms_cur_usr;
	uint8_t* ms_cur_pw;
	uint8_t* ms_enc_web;
	uint8_t* ms_enc_uname;
	uint8_t* ms_enc_pw;
	uint8_t* ms_iv_out;
	size_t ms_iv_len;
	uint8_t* ms_web_mac;
	size_t ms_web_mac_len;
	uint8_t* ms_uname_mac;
	uint8_t* ms_pw_mac;
	size_t ms_mac_len;
} ms_encrypt_credentials_t;

typedef struct ms_check_return_creds_t {
	uint8_t* ms_create_pw;
	size_t ms_buf_len;
	uint8_t* ms_v_web;
	uint8_t* ms_v_uname;
	uint8_t* ms_v_pw;
	uint8_t* ms_iv;
	size_t ms_iv_len;
	uint8_t* ms_tmp_name;
	uint8_t* ms_web_mac;
	size_t ms_web_mac_len;
	uint8_t* ms_uname_mac;
	uint8_t* ms_pw_mac;
	size_t ms_mac_len;
	uint8_t* ms_dec_web;
	uint8_t* ms_dec_uname;
	uint8_t* ms_dec_pw;
	uint8_t* ms_found;
	size_t ms_found_len;
} ms_check_return_creds_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t create_user(sgx_enclave_id_t eid, uint8_t* create_pw, size_t pw_len, uint8_t* cipher_pword, size_t cipher_pword_len, uint8_t* iv, size_t iv_len, uint8_t* mac, size_t mac_len)
{
	sgx_status_t status;
	ms_create_user_t ms;
	ms.ms_create_pw = create_pw;
	ms.ms_pw_len = pw_len;
	ms.ms_cipher_pword = cipher_pword;
	ms.ms_cipher_pword_len = cipher_pword_len;
	ms.ms_iv = iv;
	ms.ms_iv_len = iv_len;
	ms.ms_mac = mac;
	ms.ms_mac_len = mac_len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t check_user(sgx_enclave_id_t eid, uint8_t* login_attempt, size_t pw_len, uint8_t* v_pword, size_t v_pword_len, uint8_t* iv, size_t iv_len, uint8_t* mac, size_t mac_len, uint8_t* found, size_t found_len)
{
	sgx_status_t status;
	ms_check_user_t ms;
	ms.ms_login_attempt = login_attempt;
	ms.ms_pw_len = pw_len;
	ms.ms_v_pword = v_pword;
	ms.ms_v_pword_len = v_pword_len;
	ms.ms_iv = iv;
	ms.ms_iv_len = iv_len;
	ms.ms_mac = mac;
	ms.ms_mac_len = mac_len;
	ms.ms_found = found;
	ms.ms_found_len = found_len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t encrypt_credentials(sgx_enclave_id_t eid, uint8_t* create_pw, size_t buf_len, uint8_t* cur_web, uint8_t* cur_usr, uint8_t* cur_pw, uint8_t* enc_web, uint8_t* enc_uname, uint8_t* enc_pw, uint8_t* iv_out, size_t iv_len, uint8_t* web_mac, size_t web_mac_len, uint8_t* uname_mac, uint8_t* pw_mac, size_t mac_len)
{
	sgx_status_t status;
	ms_encrypt_credentials_t ms;
	ms.ms_create_pw = create_pw;
	ms.ms_buf_len = buf_len;
	ms.ms_cur_web = cur_web;
	ms.ms_cur_usr = cur_usr;
	ms.ms_cur_pw = cur_pw;
	ms.ms_enc_web = enc_web;
	ms.ms_enc_uname = enc_uname;
	ms.ms_enc_pw = enc_pw;
	ms.ms_iv_out = iv_out;
	ms.ms_iv_len = iv_len;
	ms.ms_web_mac = web_mac;
	ms.ms_web_mac_len = web_mac_len;
	ms.ms_uname_mac = uname_mac;
	ms.ms_pw_mac = pw_mac;
	ms.ms_mac_len = mac_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t check_return_creds(sgx_enclave_id_t eid, uint8_t* create_pw, size_t buf_len, uint8_t* v_web, uint8_t* v_uname, uint8_t* v_pw, uint8_t* iv, size_t iv_len, uint8_t* tmp_name, uint8_t* web_mac, size_t web_mac_len, uint8_t* uname_mac, uint8_t* pw_mac, size_t mac_len, uint8_t* dec_web, uint8_t* dec_uname, uint8_t* dec_pw, uint8_t* found, size_t found_len)
{
	sgx_status_t status;
	ms_check_return_creds_t ms;
	ms.ms_create_pw = create_pw;
	ms.ms_buf_len = buf_len;
	ms.ms_v_web = v_web;
	ms.ms_v_uname = v_uname;
	ms.ms_v_pw = v_pw;
	ms.ms_iv = iv;
	ms.ms_iv_len = iv_len;
	ms.ms_tmp_name = tmp_name;
	ms.ms_web_mac = web_mac;
	ms.ms_web_mac_len = web_mac_len;
	ms.ms_uname_mac = uname_mac;
	ms.ms_pw_mac = pw_mac;
	ms.ms_mac_len = mac_len;
	ms.ms_dec_web = dec_web;
	ms.ms_dec_uname = dec_uname;
	ms.ms_dec_pw = dec_pw;
	ms.ms_found = found;
	ms.ms_found_len = found_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len)
{
	sgx_status_t status;
	ms_unseal_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

