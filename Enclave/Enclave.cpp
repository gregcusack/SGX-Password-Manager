#include "Enclave_t.h"
#include <string.h>
#include <stdlib.h>
#include <sgx_tcrypto.h>
#include "sgx_trts.h"
//#include "ippcp.h"
#define MAX_BUFF_LEN 32
#define IV_SIZE 12
#define MAC_SIZE 16
#define CONCAT_LEN (MAX_BUFF_LEN + IV_SIZE + MAC_SIZE)
uint8_t encStr[CONCAT_LEN];

sgx_aes_ctr_128bit_key_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
/*
void hmac_sha256(const uint8_t *in_key, size_t key_size, const uint16_t *message, size_t msg_len, const uint8_t *mac_val, size_t mac_len) {
	ippsHMACState ctx;
	IppStatus status = ippsHMAC_Init((const Ippu8*) in_key, (int) key_size, &ctx, kSha256);
}
*/
void gen_iv(unsigned char *_iv) {
	sgx_status_t status = sgx_read_rand(_iv, IV_SIZE);
	if (status != SGX_SUCCESS) {
		ocall_print("rand # gen fail!");
		return;
	}
}

//TODO: HMAC key
void create_user(uint8_t *create_pw, size_t pw_len, 
	uint8_t *cipher_pword, size_t cipher_pword_len,
	uint8_t *iv, size_t iv_len, uint8_t *mac, size_t mac_len) {
	//ocall_print("Creating user...");

	uint8_t m_iv[iv_len];
	sgx_aes_gcm_128bit_tag_t master_mac[MAC_SIZE];
	create_pw[pw_len-1] = '\0';
	m_iv[iv_len-1] = '\0';

	//TODO: HMAC key
	gen_iv(m_iv);
	m_iv[iv_len-1] = '\0';
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, create_pw, pw_len, cipher_pword, m_iv, IV_SIZE, NULL, 0, master_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, bad encrypt in create_user()");
		//ocall_print((const char*)status);
		return;
	}
	memcpy(iv, m_iv, iv_len);
	memcpy(mac, master_mac, mac_len);
	mac[mac_len-1] = '\0';
	//iv[iv_len-1] = '\0';
}

void check_user(uint8_t *login_attempt, size_t pw_len, 
	uint8_t *v_pword, size_t v_pword_len, 
	uint8_t *iv, size_t iv_len, 
	uint8_t *mac, size_t mac_len,
	uint8_t *found, size_t found_len) {
	//ocall_print("Checking user...");
	
	uint8_t tmp[pw_len];
	sgx_aes_gcm_128bit_tag_t tmp_mac[mac_len];
	
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, login_attempt, pw_len, tmp, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, decrypt");
		ocall_print((const char*)status);
		return;
	}
	
	uint8_t mac_holder[mac_len];
	memcpy(mac_holder, tmp_mac, mac_len);
	size_t i;
	for(i=0; i < mac_len-1; i++) {
		if(mac[i] != mac_holder[i]) {
			*found = 0x00;
			return;
		}
	}
	*found = 0x01;
}

void encrypt_credentials(uint8_t *create_pw, size_t buf_len,
	uint8_t *cur_web, uint8_t *cur_usr, uint8_t *cur_pw, 
	uint8_t *enc_web, uint8_t *enc_uname, uint8_t *enc_pw,
	uint8_t *iv_out, size_t iv_len, uint8_t *web_mac,
	uint8_t *uname_mac, uint8_t *pw_mac, size_t mac_len) {

	//ocall_print("encrypting credentials...");

	uint8_t iv_tmp[iv_len];
	//uint8_t tmp_buf[buf_len];
	sgx_aes_gcm_128bit_tag_t mac_hold[mac_len];

	uint8_t iv[iv_len];
	gen_iv(iv);
	/*
	cur_web[buf_len-1] = '\0';
	cur_usr[buf_len-1] = '\0';
	cur_pw[buf_len-1] = '\0';
	iv[iv_len-1] = '\0';
	*/
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, cur_web, buf_len, enc_web, iv, iv_len, NULL, 0, mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, encrypt web");
		ocall_print((const char*)status);
		return;
	}
	memcpy(web_mac, mac_hold, mac_len);
	status = sgx_rijndael128GCM_encrypt(key, cur_usr, buf_len, enc_uname, iv, iv_len, NULL, 0, mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, encrypt uname");
		ocall_print((const char*)status);
		return;
	}
	memcpy(uname_mac, mac_hold, mac_len);
	status = sgx_rijndael128GCM_encrypt(key, cur_pw, buf_len, enc_pw, iv, iv_len, NULL, 0, mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, encrypt pw");
		ocall_print((const char*)status);
		return;
	}
	memcpy(pw_mac, mac_hold, mac_len);
	memcpy(iv_out, iv, iv_len);
	/*
	web_mac[web_mac_len-1] = '\0';
	uname_mac[mac_len-1] = '\0';
	pw_mac[mac_len-1] = '\0';
	enc_web[buf_len-1] = '\0';
	enc_uname[buf_len-1] = '\0';
	enc_pw[buf_len-1] = '\0';
	iv_out[iv_len-1] = '\0';
	*/
}


void check_return_creds(uint8_t *create_pw, size_t buf_len, 
	uint8_t *v_web, uint8_t *v_uname, uint8_t *v_pw,
	uint8_t *iv, size_t iv_len, uint8_t *tmp_name,
	uint8_t *web_mac, uint8_t *uname_mac, uint8_t *pw_mac, 
	size_t mac_len, uint8_t *dec_web, uint8_t *dec_uname, 
	uint8_t *dec_pw, uint8_t *found, size_t found_len) {

	//ocall_print("checking creds...");

	sgx_aes_gcm_128bit_tag_t tmp_mac[mac_len];
	//uint8_t decrypted_web[buf_len];
	memcpy(tmp_mac, web_mac, mac_len);
	//tmp_mac[mac_len-1] = '\0';

	sgx_status_t status = sgx_rijndael128GCM_decrypt(key, v_web, buf_len, dec_web, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("2: Error, encrypt check_return_creds()");
		//ocall_print((const char*)status);
		*found = 0x00;
		return;
	}
	unsigned int i;
	for(i=0; i < buf_len; i++) {
		if(tmp_name[i] != dec_web[i]) {
			*found = 0x00;
			return;
		}
	}
	*found = 0x01;
	//ocall_print((const char*)dec_web);

	memcpy(tmp_mac, uname_mac, mac_len);
	status = sgx_rijndael128GCM_decrypt(key, v_uname, buf_len, dec_uname, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error: decrypt uname");
		//ocall_print((const char*)status);
		return;
	}

	memcpy(tmp_mac, pw_mac, mac_len);
	status = sgx_rijndael128GCM_decrypt(key, v_pw, buf_len, dec_pw, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error: decrypt pw");
		//ocall_print((const char*)status);
		return;
	}

/*
	sgx_status_t status = sgx_rijndael128GCM_decrypt(key, v_web, buf_len, decrypted_web, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("2: Error, encrypt check_return_creds()");
		//ocall_print((const char*)status);
		return;
	}
*/
/*
	uint8_t enc_tmp[buf_len];
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, tmp_name, buf_len, enc_tmp, iv, iv_len, NULL, 0, tmp_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("1: Error, encrypt check_return_creds()");
		//ocall_print((const char*)status);
		return;
	}

	uint8_t mac_hold[web_mac_len];
	memcpy(mac_hold, tmp_mac, mac_len);
	//mac_hold[web_mac_len-1] = '\0';

	sgx_aes_gcm_128bit_tag_t new_mac_hold[mac_len];
	memcpy(new_mac_hold, mac_hold, mac_len);

	status = sgx_rijndael128GCM_decrypt(key, enc_tmp, buf_len, enc_tmp, iv, iv_len, NULL, 0, new_mac_hold);
	if (status != SGX_SUCCESS) {
		ocall_print("2: Error, encrypt check_return_creds()");
		//ocall_print((const char*)status);
		return;
	}
*/


}





/*
void encrypt_str(uint8_t *in_buf, size_t in_len, uint8_t *out_buf, size_t out_len) {
	ocall_print("encrypting string...");
	unsigned char iv[IV_SIZE];
	gen_iv(iv);
	uint8_t cipher_buf[MAX_BUFF_LEN];
	sgx_aes_gcm_128bit_tag_t mac[MAC_SIZE];

	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, in_buf, MAX_BUFF_LEN, cipher_buf, iv, IV_SIZE, NULL, 0, mac);
	//ocall_print("here1");
	if (status != SGX_SUCCESS) {
		ocall_print("Error, bad hash");
		ocall_print((const char*)status);
		return;
	}
	
	memcpy(&out_buf[0], cipher_buf, MAX_BUFF_LEN);
	memcpy(&out_buf[MAX_BUFF_LEN], &iv[0], IV_SIZE);
	memcpy(&out_buf[MAX_BUFF_LEN+IV_SIZE], &mac[0], MAC_SIZE);

	//memzero_explicit(in_buf, in_len);
	//memset(in_buf, 0, in_len);

}

void decrypt_str(uint8_t *in_buf, size_t in_len, uint8_t *out_buf, size_t out_len) {
	ocall_print("decrypting string...");
	uint8_t decrypt[MAX_BUFF_LEN];
	uint8_t iv[IV_SIZE];
	uint8_t mac[MAC_SIZE];
	memcpy(decrypt, &in_buf[0], MAX_BUFF_LEN);
	memcpy(iv, &in_buf[MAX_BUFF_LEN], IV_SIZE);
	memcpy(mac, &in_buf[MAX_BUFF_LEN+IV_SIZE], MAC_SIZE);

	sgx_status_t status = sgx_rijndael128GCM_decrypt(key, decrypt, MAX_BUFF_LEN, out_buf, iv, IV_SIZE, NULL, 0, &mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, decrypt");
		ocall_print((const char*)status);
		return;
	}
}
*/