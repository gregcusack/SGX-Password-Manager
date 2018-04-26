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


/*
int encrypt(int val) {
	ocall_print("incrementing val...");
	val++;
	return val;
}
*/

void encrypt_str(char *buf, size_t len) {
	ocall_print("encrypting string...");
	//sgx_sha256_hash_t *p_hash;
	//sgx_sha256_hash_t p_hash;
	unsigned char iv[IV_SIZE];
	gen_iv(iv);
	
	uint8_t o_buf[32];
	sgx_aes_gcm_128bit_tag_t mac[16];
	//sgx_status_t status = sgx_aes_ctr_encrypt(key, (const uint8_t*)buf, MAX_BUFF_LEN, iv, 128, o_buf);
	//ocall_print("here");
	
	sgx_status_t status = sgx_rijndael128GCM_encrypt(key, (const uint8_t*)buf, MAX_BUFF_LEN, o_buf, iv, IV_SIZE, NULL, 0, mac);
	//ocall_print("here1");
	if (status != SGX_SUCCESS) {
		ocall_print("Error, bad hash");
		ocall_print((const char*)status);
		return;
	}
	
	memcpy(&encStr[0], &o_buf[0], MAX_BUFF_LEN);
	memcpy(&encStr[MAX_BUFF_LEN], &iv[0], IV_SIZE);
	memcpy(&encStr[MAX_BUFF_LEN+IV_SIZE], &mac[0], MAC_SIZE);
	
	//strcpy(encStr, buf);
	//strcpy(encStr, iv);
	//strcpy(encStr, mac);
	//memcpy(buf, o_buf, 32);

	/*
	uint8_t p_hash[32];
	sgx_status_t status = sgx_sha256_msg((const uint8_t*)buf, len, &p_hash);
	memcpy(buf, p_hash, 32);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, bad hash");
		ocall_print((const char*)status);
		return;
	}
	*/
	//hmac_sha256(key, 32, buf, *size, master_key, 32);
	//gen_iv(master_iv_out);

	//hmac_xcrypt(cipher_pw, master_iv_out, master_key, *size);
}

void get_str(uint8_t *o_buf, size_t len) {
	ocall_print("Getting str...");
	memcpy(o_buf, encStr, CONCAT_LEN);


}

void decrypt_str(uint8_t* buf, size_t len) {
	ocall_print("decrypting string...");
	uint8_t decrypt[MAX_BUFF_LEN];
	uint8_t iv[IV_SIZE];
	uint8_t mac[MAC_SIZE];
	memcpy(decrypt, &buf[0], MAX_BUFF_LEN);
	memcpy(iv, &buf[MAX_BUFF_LEN], IV_SIZE);
	memcpy(mac, &buf[MAX_BUFF_LEN+IV_SIZE], MAC_SIZE);

	sgx_status_t status = sgx_rijndael128GCM_decrypt(key, decrypt, MAX_BUFF_LEN, &encStr[0], iv, IV_SIZE, NULL, 0, &mac);
	if (status != SGX_SUCCESS) {
		ocall_print("Error, decrypt");
		ocall_print((const char*)status);
		return;
	}
}

void get_dec_str(uint8_t* buf, size_t len) {
	ocall_print("returning decrypted string...");
	memcpy(buf, encStr, len);
}

/*
void encrypt_str(char *buf, size_t len) {
	ocall_print("lower casing string...");
	char c;
	int i=0;
	while(buf[i]) {
		if(buf[i] >= 65 && buf[i] <= 90) {
			buf[i] = buf[i] + 32;
		}
		//enclave_str[i] = buf[i];
		i++;
	}
	//ocall_print(enclave_str);
}
*/
