#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void create_user(uint8_t* create_pw, size_t pw_len, uint8_t* cipher_pword, size_t cipher_pword_len, uint8_t* iv, size_t iv_len, uint8_t* mac, size_t mac_len);
void check_user(uint8_t* login_attempt, size_t pw_len, uint8_t* v_pword, size_t v_pword_len, uint8_t* iv, size_t iv_len, uint8_t* mac, size_t mac_len, uint8_t* found, size_t found_len);
void encrypt_credentials(uint8_t* create_pw, size_t buf_len, uint8_t* cur_web, uint8_t* cur_usr, uint8_t* cur_pw, uint8_t* enc_web, uint8_t* enc_uname, uint8_t* enc_pw, uint8_t* iv_out, size_t iv_len, uint8_t* web_mac, uint8_t* uname_mac, uint8_t* pw_mac, size_t mac_len);
void check_return_creds(uint8_t* create_pw, size_t buf_len, uint8_t* v_web, uint8_t* v_uname, uint8_t* v_pw, uint8_t* iv, size_t iv_len, uint8_t* tmp_name, uint8_t* web_mac, uint8_t* uname_mac, uint8_t* pw_mac, size_t mac_len, uint8_t* dec_web, uint8_t* dec_uname, uint8_t* dec_pw, uint8_t* found, size_t found_len);
sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

sgx_status_t SGX_CDECL ocall_print(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
