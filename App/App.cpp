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
#include <sys/time.h>
#include <string.h>

#ifndef USERCLASS_H
#define USERCLASS_H
#include "userclass.h"
#endif

#ifndef VAULT_H
#define VAULT_H
#include "vault.h"
#endif

#define MAX_BUFF_LEN 32
#define CONCAT_LEN 60
#define MAC_LEN 16

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str) {
	printf("Ocall says: %s\n", str);
}

void create_vault() {
	FILE *f;
	f = fopen("test.dat", "a+");
	if(f == NULL) {
		std::cerr << "Error in file open (create_vault())" << std::endl;
		exit(1);
	}
	fclose(f);
}

bool read_vault(vault *vault) {
	FILE *infile;
	infile = fopen("test.dat", "r");
	if(infile == NULL) {
		std::cerr << "Error in file open (read_vault())" << std::endl;
		exit(1);
	}
	if(!fread(vault, sizeof(struct vault), 1, infile)) {
		fclose(infile);
		return false;
	}
	fclose(infile);
	return true;
}

bool vault_store_user(vault *vault, uint8_t *pw, uint8_t *iv, uint8_t *mac) {
	unsigned int i;
	if(vault->full) {
		std::cout << "vault full!" << std::endl;
		return false;
	}
	std::cout << "pw: " << pw << std::endl;
	memcpy(vault->m_pword, pw, MAX_BUFF_LEN);
	std::cout << "v_pw: " << vault->m_pword << std::endl;
	std::cout << "iv: " << iv << std::endl;
	memcpy(vault->m_iv, iv, IV_SIZE);
	std::cout << "v_iv: " << vault->m_iv << std::endl;
	std::cout << "mac: " << mac << std::endl;
	memcpy(vault->m_mac, mac, MAC_LEN);
	std::cout << "v_mac: " << vault->m_mac << std::endl;
	/*
	for(i=0; i < pw_len; i++) {
		vault->m_pword[i] = store[i];
	}
	memcpy(vault->m_pword, &store[0], pw_len);
	memcpy(vault->m_iv, &store[pw_len], IV_SIZE);
	memcpy(vault->m_mac, &store[pw_len+IV_SIZE], MAC_LEN);
	std::cout << "master iv: " << vault->m_iv << std::endl;
	std::cout << "master mac: " << vault->m_mac << std::endl;
	*/
	vault->full = true;
	return true;
}

void gen_random_password(uint8_t *s, const unsigned int len) {
  	int i;
	static const uint8_t alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
	std::cout << "len: " << len << std::endl;
	for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len-1] = '\0';
    std::cout << "rand pw: " << s << std::endl;
}

int main(int argc, char** argv) {
	remove("test.dat");
	//srand(time(NULL));
	vault vault;
	create_vault();
	if(!read_vault(&vault)) {
		vault.num_accounts = 0;
		vault.full = false;
	}

	if(initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
		fprintf(stderr, "Fail to initialize enclave.");
		return 1;
	}


	uint8_t str[MAX_BUFF_LEN] = "Hello World!";
	uint8_t create_pw[MAX_BUFF_LEN];
	uint8_t cipher_pw[MAX_BUFF_LEN];
	uint8_t iv[IV_SIZE];
	uint8_t mac[MAC_LEN];
	//sgx_aes_gcm_128bit_tag_t mac[MAC_LEN];
	uint8_t login_password_test[MAX_BUFF_LEN];


	uint8_t cipher_str[CONCAT_LEN];
	//char mac[MAC_LEN];
	uint8_t decrypted_str[MAX_BUFF_LEN];
		
	if(vault.full) {
		std::cerr << "Vault full!" << std::endl;
		exit(1);
	}
	//std::cout << "create_pw1: " << create_pw << std::endl;

	gen_random_password(create_pw, MAX_BUFF_LEN);
	memcpy(login_password_test, create_pw, MAX_BUFF_LEN);
	create_user(global_eid, create_pw, MAX_BUFF_LEN, cipher_pw, MAX_BUFF_LEN, iv, IV_SIZE, mac, MAC_LEN);

	//mac = (char*)mac;
	mac[MAC_LEN-1] = '\0';
	iv[IV_SIZE-1] = '\0';
	cipher_pw[MAX_BUFF_LEN-1] = '\0';
	std::cout << "ret mac: " << mac << std::endl;
	std::cout << "ret iv: " << iv << std::endl;
	std::cout << "ret pw: " << cipher_pw << std::endl;

	if(!vault_store_user(&vault, cipher_pw, iv, mac)) {
		std::cerr << "Bad store!" << std::endl;
		exit(1);
	}
	std::cout << "vault m_pword: " << vault.m_pword << std::endl;
	std::cout << "vault m_iv: " << vault.m_iv << std::endl;
	std::cout << "master mac from vault: " << vault.m_mac << std::endl;

	std::cout << "login_password_test: " << login_password_test << std::endl;

	uint8_t found[1];
	check_user(global_eid, login_password_test, MAX_BUFF_LEN, vault.m_pword, MAX_BUFF_LEN, vault.m_iv, IV_SIZE, vault.m_mac, MAC_LEN, found, sizeof(found));


	//strncpy((char*)login_password_test, (char*)create_pw, MAX_BUFF_LEN);
	//std::cout << "create_pw3: " << create_pw << std::endl;
	//std::cout << "login_password_test: " << login_password_test << std::endl;
	//std::cout << "create_pw len: " << sizeof(create_pw) << std::endl;
	//std::cout << "login pword len: " << sizeof(login_password_test) << std::endl;
	//std::cout << "MAX_BUFF_LEN: " << MAX_BUFF_LEN << std::endl;
	//memcpy(login_password_test, str, MAX_BUFF_LEN);
	/*
	create_user(global_eid, create_pw, MAX_BUFF_LEN, cipher_pword, MAX_BUFF_LEN, iv, IV_SIZE, mac, MAC_LEN);

	if(!vault_store_user(&vault, cipher_str, CONCAT_LEN)) {
		std::cerr << "Bad store!" << std::endl;
		exit(1);
	}
	std::cout << "vault m_pword: " << vault.m_pword << std::endl;
	
	std::cout << "master mac from vault: " << vault.m_mac << std::endl;
*/
/*
	uint8_t found[1];
	check_user(global_eid, login_password_test, MAX_BUFF_LEN, vault.m_pword, MAX_BUFF_LEN, vault.m_iv, IV_SIZE, vault.m_mac, MAC_LEN, found, sizeof(found));
	if(found[0] == 0) {
		std::cerr << "user not found!" << std::endl;
		exit(1);
	}
	std::cout << "found!" << std::endl;

	sgx_status_t status = encrypt_str(global_eid, str, MAX_BUFF_LEN, cipher_str, CONCAT_LEN);
	if (status != SGX_SUCCESS) {
		std::cout << "fail" << std::endl;
	}

	memset(str, 0, MAX_BUFF_LEN);
	std::cout << "zeroed input str: " << str << std::endl;
	std::cout << "encypted string: " << cipher_str << std::endl;

	
	status = decrypt_str(global_eid, cipher_str, CONCAT_LEN, decrypted_str, MAX_BUFF_LEN);
	if (status != SGX_SUCCESS) {
		std::cout << "fail decrypting" << std::endl;
	}

	std::cout << "decrypted string: " << decrypted_str << std::endl;
*/
	return 0;	
}
















