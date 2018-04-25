#include "Enclave_t.h"
#include "aes.h"
#include "sha2.h"
#include "hmac_sha2.h"
#include <string.h>
#include <stdlib.h>
#include "sgx_trts.h"
#define MAX_BUFF_LEN 32
#define IV_SIZE 16
//char enclave_str[MAX_BUFF_LEN];

unsigned char key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 
						0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 
						0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 
						0xa3, 0x09, 0x14, 0xdf, 0xf4 };

void gen_iv(unsigned char *_iv) {\
	sgx_status_t status = sgx_read_rand(_iv, IV_SIZE);
	if (status != SGX_SUCCESS) {
		ocall_print("rand # gen fail!");
		return;
	}
}

void hmac_xcrypt(unsigned char *in_str, unsigned char *_iv,
	unsigned char *master_key, unsigned int size) {
	struct AES_ctx ctx;
	//AES_init_ctx_iv(&ctx, master_key, _iv);
	//AES_ctx_set_iv(&ctx, _iv);
	//AES_CTR_xcrypt_buffer(&ctx, in_str, size);
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
	unsigned char master_key[32];

	//hmac_sha256(key, 32, buf, *size, master_key, 32);
	//gen_iv(master_iv_out);

	//hmac_xcrypt(cipher_pw, master_iv_out, master_key, *size);
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
