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
#define WEB_MAC_LEN 16

#define ITERATIONS 25

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

bool write_vault(vault *vault) {
	//std::cout << "accounts in vault: " << vault->num_accounts << std::endl;
	FILE *f = fopen("test.dat", "w+");
	if(f == NULL) {
		std::cerr << "Error in file open (write_vault())" << std::endl;
		exit(1);
	}
	fwrite(vault, sizeof(struct vault), 1, f);
	fclose(f);
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

	//iv[IV_SIZE-1] = '\0';

	if(!vault_store_user(&vault, cipher_pw, iv, mac)) {
		std::cerr << "Bad store!" << std::endl;
		exit(1);
	}
	
	uint8_t found[1];
	check_user(global_eid, login_password_test, MAX_BUFF_LEN, vault.m_pword, MAX_BUFF_LEN, vault.m_iv, IV_SIZE, vault.m_mac, MAC_LEN, found, sizeof(found));
	if(!found) {
		std::cerr << "user not found!" << std::endl;
		exit(1);
	}
	else {
		std::cout << "User Found!" << std::endl;
	}

	/***** AFTER LOGIN *****/
	uint8_t current_web[MAX_BUFF_LEN];
	uint8_t current_user[MAX_BUFF_LEN];
	uint8_t current_pw[MAX_BUFF_LEN];
	uint8_t tmp_name[MAX_BUFF_LEN];
	website enc_usr_cred;
	website usr_ret;
	unsigned int loop_count = 0;
	double create_time, reat_time;
	std::cout << "PASSWORD_SIZE,ADD_TIME,GET_TIME" << std::endl;
	int i,k,itr;
	for(k = 4; k < MAX_BUFF_LEN; k+=4) {
		for(itr = 0; itr < ITERATIONS; itr++) {
			memset(current_web, 0, MAX_BUFF_LEN);
			memset(tmp_name, 0, MAX_BUFF_LEN);
			memset(current_user, 0, MAX_BUFF_LEN);
			memset(current_pw, 0, MAX_BUFF_LEN);
			sprintf((char*)current_web, "test%d_%d", itr, k);
			sprintf((char*)tmp_name, "test%d_%d", itr, k);
			sprintf((char*)current_user, "test%d_%d", itr, k);
			gen_random_password(current_pw, k);

			current_web[MAX_BUFF_LEN-1] = '\0';
			tmp_name[MAX_BUFF_LEN-1] = '\0';
			current_user[MAX_BUFF_LEN-1] = '\0';

			bool success;
			uint8_t cred_found[1];
			cred_found[0] = 0x00;
			if(vault.num_accounts > MAX_ACCOUNTS) {
				std::cerr << "MAX_ACCOUNTS LIMIT REACHED!" << std::endl;
				exit(1);
			}
			//std::cout << "here" << std::endl;
			//TODO: BEGIN CLOCK HERE
			encrypt_credentials(global_eid, create_pw, MAX_BUFF_LEN,
				current_web, current_user, current_pw,
				enc_usr_cred.web_name, enc_usr_cred.credentials.a_uname, 
				enc_usr_cred.credentials.a_pword, enc_usr_cred.web_iv, IV_SIZE,
				enc_usr_cred.web_mac, enc_usr_cred.credentials.uname_mac, 
				enc_usr_cred.credentials.pw_mac, MAC_LEN);
			vault.accounts[vault.num_accounts] = enc_usr_cred;
			vault.num_accounts++;
			write_vault(&vault);

			/***** CHECK AND RETURN CREDENTIALS *****/
			unsigned int i;
			for(i = 0; i < vault.num_accounts; i++) {
				check_return_creds(global_eid, create_pw, MAX_BUFF_LEN,
					vault.accounts[i].web_name,
					vault.accounts[i].credentials.a_uname, 
					vault.accounts[i].credentials.a_pword,
					vault.accounts[i].web_iv, IV_SIZE, tmp_name,
					vault.accounts[i].web_mac,
					vault.accounts[i].credentials.uname_mac,
					vault.accounts[i].credentials.pw_mac,
					MAC_LEN, usr_ret.web_name,
					usr_ret.credentials.a_uname,
					usr_ret.credentials.a_pword,
					cred_found, sizeof(cred_found));
				std::cout << "i: " << i << std::endl;
				if(cred_found) {
					break;
				}
			}
			//std::cout << cred_found << std::endl;
			if(!cred_found) {
				std::cerr << "ERROR: Data not found!" << std::endl;
				exit(1);
			}
			std::cout << "k: " << k << std::endl;
			//std::cout << "GOT CREDS!" << std::endl;
			//std::cout << k << "," << crea


		}
	}

	return 0;	
}
















