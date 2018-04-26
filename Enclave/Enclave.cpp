#include "Enclave_t.h"
#include <string.h>
#include <stdlib.h>
#include <sgx_tcrypto.h>
#include "sgx_trts.h"
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

void gen_iv(unsigned char *_iv) {
	sgx_status_t status = sgx_read_rand(_iv, IV_SIZE);
	if (status != SGX_SUCCESS) {
		ocall_print("rand # gen fail!");
		return;
	}
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