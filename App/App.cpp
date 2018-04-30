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
	memcpy(vault->m_pword, pw, MAX_BUFF_LEN);
	memcpy(vault->m_iv, iv, IV_SIZE);
	memcpy(vault->m_mac, mac, MAC_LEN);
	vault->full = true;
	return true;
}

void gen_random_password(uint8_t *s, const unsigned int len) {
  	int i;
	static const uint8_t alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
	for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len-1] = '\0';
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

	uint8_t create_pw[MAX_BUFF_LEN];
	uint8_t cipher_pw[MAX_BUFF_LEN];
	uint8_t iv[IV_SIZE];
	uint8_t mac[MAC_LEN];
	uint8_t login_password_test[MAX_BUFF_LEN];
	uint8_t cipher_str[CONCAT_LEN];
	uint8_t decrypted_str[MAX_BUFF_LEN];
		
	if(vault.full) {
		std::cerr << "Vault full!" << std::endl;
		exit(1);
	}

	gen_random_password(create_pw, MAX_BUFF_LEN);
	memcpy(login_password_test, create_pw, MAX_BUFF_LEN-1);
	create_user(global_eid, create_pw, MAX_BUFF_LEN, cipher_pw, MAX_BUFF_LEN, iv, IV_SIZE, mac, MAC_LEN);

	//mac = (char*)mac;
	mac[MAC_LEN-1] = '\0';
	iv[IV_SIZE-1] = '\0';

	if(!vault_store_user(&vault, cipher_pw, iv, mac)) {
		std::cerr << "Bad store!" << std::endl;
		exit(1);
	}
	
	uint8_t found[1];
	check_user(global_eid, login_password_test, MAX_BUFF_LEN, vault.m_pword, MAX_BUFF_LEN, vault.m_iv, IV_SIZE, vault.m_mac, MAC_LEN, found, sizeof(found));
	if(found[0] != 0x01) {
		std::cerr << "user not found!" << std::endl;
		exit(1);
	}
	else {
		std::cout << "User Found!" << std::endl;
	}


	return 0;	
}
















