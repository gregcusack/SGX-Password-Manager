#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));

sgx_status_t create_user(sgx_enclave_id_t eid, uint8_t* create_pw, size_t pw_len, uint8_t* cipher_pword, size_t cipher_pword_len, uint8_t* iv, size_t iv_len, uint8_t* mac, size_t mac_len);
sgx_status_t check_user(sgx_enclave_id_t eid, uint8_t* login_attempt, size_t pw_len, uint8_t* v_pword, size_t v_pword_len, uint8_t* iv, size_t iv_len, uint8_t* mac, size_t mac_len, uint8_t* found, size_t found_len);
sgx_status_t encrypt_credentials(sgx_enclave_id_t eid, uint8_t* create_pw, size_t buf_len, uint8_t* cur_web, uint8_t* cur_usr, uint8_t* cur_pw, uint8_t* enc_web, uint8_t* enc_uname, uint8_t* enc_pw, uint8_t* iv_out, size_t iv_len, uint8_t* web_mac, size_t web_mac_len, uint8_t* uname_mac, uint8_t* pw_mac, size_t mac_len);
sgx_status_t check_return_creds(sgx_enclave_id_t eid, uint8_t* create_pw, size_t buf_len, uint8_t* v_web, uint8_t* v_uname, uint8_t* v_pw, uint8_t* iv, size_t iv_len, uint8_t* tmp_name, uint8_t* web_mac, size_t web_mac_len, uint8_t* uname_mac, uint8_t* pw_mac, size_t mac_len, uint8_t* dec_web, uint8_t* dec_uname, uint8_t* dec_pw, uint8_t* found, size_t found_len);
sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
