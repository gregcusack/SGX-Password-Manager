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
//#define CONCAT_LEN 96
uint8_t encStr[CONCAT_LEN];


//char enclave_str[MAX_BUFF_LEN];

//was unsigned char
/*
sgx_aes_ctr_128bit_key_t key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 
						0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 
						0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 
						0xa3, 0x09, 0x14, 0xdf, 0xf4 };
*/
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
	ocall_print("Creating user...");

	
	//uint8_t cipher_buf[MAX_BUFF_LEN];
	uint8_t m_iv[iv_len];
	sgx_aes_gcm_128bit_tag_t master_mac[MAC_SIZE];
	create_pw[pw_len-1] = '\0';
	m_iv[iv_len-1] = '\0';
	//ocall_print((const char*)create_pw);
	//TODO: HMAC key
	gen_iv(m_iv);
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, create_pw, pw_len, cipher_pword, m_iv, IV_SIZE, NULL, 0, master_mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, bad encrypt in create_user()");
		ocall_print((const char*)status);
		return;
	}
	//mac[mac_len-1] = '\0';
	//iv[iv_len-1] = '\0';
	memcpy(iv, m_iv, iv_len);
	memcpy(mac, master_mac, mac_len);
	mac[mac_len-1] = '\0';
	ocall_print((const char*)mac);

	/*
	ocall_print("master mac");
	ocall_print((const char*) master_mac);
	memcpy(&cipher_str[0], cipher_buf, pw_len);
	ocall_print((const char*) cipher_str);
	ocall_print("IV: ");
	ocall_print((const char*) master_iv);
	ocall_print("MAC: ");
	ocall_print((const char*) master_mac);
	memcpy(&cipher_str[pw_len], master_iv, IV_SIZE);
	memcpy(&cipher_str[pw_len+IV_SIZE], &master_mac[0], MAC_SIZE);
	ocall_print((const char*) cipher_buf);
	ocall_print("IV start:");
	ocall_print((const char*) &cipher_str[pw_len]);
	*/

}

void check_user(uint8_t *login_attempt, size_t pw_len, 
	uint8_t *v_pword, size_t v_pword_len, 
	uint8_t *iv, size_t iv_len, 
	uint8_t *mac, size_t mac_len,
	uint8_t *found, size_t found_len) {

	uint8_t tmp[pw_len];
	sgx_aes_gcm_128bit_tag_t tmp_mac[mac_len];
	
	//v_pword[pw_len] = '\0';

	ocall_print("login_attempt");
	ocall_print((const char*) login_attempt);
	ocall_print("iv");
	ocall_print((const char*) iv);
	ocall_print("mac");
	ocall_print((const char*) mac);

	
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, login_attempt, pw_len, tmp, iv, iv_len, NULL, 0, tmp_mac);
	//sgx_status_t status = sgx_rijndael128GCM_decrypt(key, v_pword, pw_len, tmp, iv, iv_len, NULL, 0, (const uint8_t (*)[16])mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, decrypt");
		ocall_print((const char*)status);
		return;
	}
	

	unsigned int i;
	ocall_print("here1");
	ocall_print((const char*) v_pword);
	ocall_print((const char*) tmp);
	ocall_print("here3");
	
/*
	for(i=0; i < v_pword_len; i++) {
		//ocall_print((const char*)&v_pword[i]);
		if(v_pword[i] != tmp[i]) {
			found = 0;
			return;
		}
	}
	ocall_print("here");
	for(i=0; i < mac_len; i++) {
		if(&mac[i] != tmp_mac[i]) {
			found = 0;
			return;
		}
	}
	found = (uint8_t*)1;
	ocall_print("here2");
*/
}



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