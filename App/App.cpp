#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <iostream>
#include <Enclave_u.h>
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include <unistd.h>
#include <sys/syscall.h>

#define max_buff_len 64

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str) {
	printf("1234: %s\n", str);
}
/*
void gen_random_password(unsigned char *s, const unsigned int len) {
  	int i;
	static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
	for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len] = 0;
}
*/
int main(int argc, char** argv) {
	if(initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
		fprintf(stderr, "Fail to initialize enclave.");
		return 1;
	}
		
	char buffer_1[max_buff_len] = "abcdefghijklmnopqrstuvwxyz12345";	
	int ptr;
	int num = 4;
	//char str_out[max_buff_len];
	char str[max_buff_len] = "Hello World!";
	
	char buffer_2[max_buff_len] = "abcdefghijklmn1opqrstuvwxyz1234";	
	//std::cout << buffer_2 << std::endl;
	//sgx_status_t status = encrypt(global_eid, &ptr, num);
	sgx_status_t status = encrypt_str(global_eid, str, max_buff_len);
	//sgx_status_t = create_user(global_eid, &ptr, create_pw, size, iv_in, cipher_pw, master_iv_out);
	std::cout << status << std::endl;
	if (status != SGX_SUCCESS) {
		std::cout << "fail" << std::endl;
	}
	std::cout << "incr. val: " << str << std::endl;
	//std::cout << "ptr val: " << ptr << std::endl;
	/*
	std::cout << "to lower: " << str << std::endl;
	std::cout << "size of str: " << sizeof(str) << std::endl;
	
	//seal password
	//size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
	size_t sealed_size = sizeof(sgx_sealed_data_t) + max_buff_len*sizeof(str);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	
	std::cout << "sealed size: " << sealed_size << std::endl;
	sgx_status_t ecall_status;
	*/
	/*
	status = seal(global_eid, &ecall_status,
			(uint8_t*)&ptr, sizeof(ptr),
			(sgx_sealed_data_t*)sealed_data, sealed_size);
	*/
	/*
	status = seal(global_eid, &ecall_status,
			(uint8_t*)&str, max_buff_len*sizeof(str),
			(sgx_sealed_data_t*)sealed_data, sealed_size);


	if(!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
		return 1;
	}
	std::cout << "sealed data: " << sealed_data << std::endl;
	
	
	//int unsealed;
	char unsealed[max_buff_len];
	std::cout << "size of unsealed: " << sizeof(unsealed) << std::endl;	
	status = unseal(global_eid, &ecall_status,
			(sgx_sealed_data_t*)sealed_data, sealed_size,
		   (uint8_t*)&unsealed, sizeof(unsealed));

	if(!is_ecall_successful(status, "unsealing failed :(", ecall_status)) {
		return 1;
	}
	std::cout << "Seal roud trip success! Receive back: " << unsealed << std::endl;
	std::cout << "here" << std::endl;	
	*/
	return 0;	
	//std::cout << buffer_1 << std::endl;
	//std::cout << buffer_2 << std::endl;
	
}
















