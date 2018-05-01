#include "Enclave_t.h"
#include <string.h>
#include <stdlib.h>
#include <sgx_tcrypto.h>
#include "sgx_trts.h"
#include "../../../../../../linux-sgx/external/ippcp_internal/inc/ippcp.h"
#define IV_SIZE 12

uint8_t enclave_key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

int hmac_sha256(const uint8_t *in_key, size_t key_size, const uint8_t *message, size_t msg_len, uint8_t *mac_val, size_t mac_len) {
	IppsHMACState *ctx;
	int psize = 0;
	IppStatus status = ippsHMAC_GetSize(&psize);
	if(status == ippStsNullPtrErr) {
		ocall_print("Error GetSize()");
		return 0;
	}
	ctx = (IppsHMACState*) malloc(psize);
	status = ippsHMAC_Init((const uint8_t*)in_key, key_size, ctx, ippHashAlg_SHA256);
	if(status != ippStsNoErr) {
		ocall_print("error bad hmac init");
		free(ctx);
		return 0;
	}
	status = ippsHMAC_Update(message, msg_len, ctx);
	if(status != ippStsNoErr) {
		ocall_print("error bad hmac update");
		free(ctx);
		return 0;
	}
	status = ippsHMAC_Final(mac_val, mac_len, ctx);
	if(status != ippStsNoErr) {
		ocall_print("error bad hmac final");
		free(ctx);
		return 0;
	}
	free(ctx);
	return 1;
}

void gen_iv(unsigned char *_iv) {
	sgx_status_t status = sgx_read_rand(_iv, IV_SIZE);
	if (status != SGX_SUCCESS) {
		ocall_print("rand # gen fail!");
		return;
	}
}

void create_user(uint8_t *create_pw, size_t pw_len, 
	uint8_t *cipher_pword, size_t cipher_pword_len,
	uint8_t *iv, size_t iv_len, uint8_t *mac, size_t mac_len) {

	uint8_t m_iv[iv_len];
	sgx_aes_gcm_128bit_tag_t master_mac[mac_len];

	uint8_t tmp_key[sizeof(enclave_key)];
	sgx_aes_ctr_128bit_key_t master_key[16];
	if(!hmac_sha256((const uint8_t*)enclave_key, sizeof(enclave_key), create_pw, pw_len, tmp_key, sizeof(tmp_key))) {
		return;
	}
	gen_iv(m_iv);
	memcpy(master_key, tmp_key, 16);
	sgx_status_t status = sgx_rijndael128GCM_encrypt(master_key, create_pw, pw_len, cipher_pword, m_iv, iv_len, NULL, 0, master_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, bad encrypt in create_user()");
		return;
	}
	memcpy(iv, m_iv, iv_len);
	memcpy(mac, master_mac, mac_len);
}

void check_user(uint8_t *login_attempt, size_t pw_len, 
	uint8_t *v_pword, size_t v_pword_len, 
	uint8_t *iv, size_t iv_len, 
	uint8_t *mac, size_t mac_len,
	uint8_t *found, size_t found_len) {
	
	uint8_t tmp[pw_len];
	sgx_aes_gcm_128bit_tag_t tmp_mac[mac_len];
	
	uint8_t tmp_key[sizeof(enclave_key)];
	sgx_aes_ctr_128bit_key_t master_key[16];
	if(!hmac_sha256((const uint8_t*)enclave_key, sizeof(enclave_key), login_attempt, pw_len, tmp_key, sizeof(tmp_key))) {
		return;
	}
	memcpy(master_key, tmp_key, 16);
	sgx_status_t status = sgx_rijndael128GCM_encrypt(master_key, login_attempt, pw_len, tmp, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, decrypt");
		ocall_print((const char*)status);
		return;
	}
	
	uint8_t mac_holder[mac_len];
	memcpy(mac_holder, tmp_mac, mac_len);

	if(strncmp((const char*)mac, (const char*)mac_holder, mac_len)) {
		*found = 0x00;
		return;
	}
	*found = 0x01;
}

void encrypt_credentials(uint8_t *create_pw, size_t buf_len,
	uint8_t *cur_web, uint8_t *cur_usr, uint8_t *cur_pw, 
	uint8_t *enc_web, uint8_t *enc_uname, uint8_t *enc_pw,
	uint8_t *iv_out, size_t iv_len, uint8_t *web_mac,
	uint8_t *uname_mac, uint8_t *pw_mac, size_t mac_len) {

	uint8_t iv_tmp[iv_len];
	sgx_aes_gcm_128bit_tag_t mac_hold[mac_len];

	uint8_t iv[iv_len];
	gen_iv(iv);

	uint8_t tmp_key[sizeof(enclave_key)];
	sgx_aes_ctr_128bit_key_t master_key[16];
	if(!hmac_sha256((const uint8_t*)enclave_key, sizeof(enclave_key), create_pw, buf_len, tmp_key, sizeof(tmp_key))) {
		return;
	}
	memcpy(master_key, tmp_key, 16);
	sgx_status_t status = sgx_rijndael128GCM_encrypt(master_key, cur_web, buf_len, enc_web, iv, iv_len, NULL, 0, mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, encrypt web");
		ocall_print((const char*)status);
		return;
	}
	memcpy(web_mac, mac_hold, mac_len);
	status = sgx_rijndael128GCM_encrypt(master_key, cur_usr, buf_len, enc_uname, iv, iv_len, NULL, 0, mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, encrypt uname");
		ocall_print((const char*)status);
		return;
	}
	memcpy(uname_mac, mac_hold, mac_len);
	status = sgx_rijndael128GCM_encrypt(master_key, cur_pw, buf_len, enc_pw, iv, iv_len, NULL, 0, mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, encrypt pw");
		ocall_print((const char*)status);
		return;
	}
	memcpy(pw_mac, mac_hold, mac_len);
	memcpy(iv_out, iv, iv_len);
}


void check_return_creds(uint8_t *create_pw, size_t buf_len, 
	uint8_t *v_web, uint8_t *v_uname, uint8_t *v_pw,
	uint8_t *iv, size_t iv_len, uint8_t *tmp_name,
	uint8_t *web_mac, uint8_t *uname_mac, uint8_t *pw_mac, 
	size_t mac_len, uint8_t *dec_web, uint8_t *dec_uname, 
	uint8_t *dec_pw, uint8_t *found, size_t found_len) {

	sgx_aes_gcm_128bit_tag_t tmp_mac[mac_len];
	memcpy(tmp_mac, web_mac, mac_len);

	uint8_t tmp_key[sizeof(enclave_key)];
	sgx_aes_ctr_128bit_key_t master_key[16];
	if(!hmac_sha256((const uint8_t*)enclave_key, sizeof(enclave_key), create_pw, buf_len, tmp_key, sizeof(tmp_key))) {
		return;
	}
	memcpy(master_key, tmp_key, 16);
	sgx_status_t status = sgx_rijndael128GCM_decrypt(master_key, v_web, buf_len, dec_web, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error: encrypt check_return_creds()");
		*found = 0x00;
		return;
	}

	if(strncmp((const char*)tmp_name, (const char*)dec_web, buf_len)) {
		*found = 0x00;
		return;
	}
	*found = 0x01;

	memcpy(tmp_mac, uname_mac, mac_len);
	status = sgx_rijndael128GCM_decrypt(master_key, v_uname, buf_len, dec_uname, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error: decrypt uname");
		return;
	}

	memcpy(tmp_mac, pw_mac, mac_len);
	status = sgx_rijndael128GCM_decrypt(master_key, v_pw, buf_len, dec_pw, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error: decrypt pw");
		return;
	}
}