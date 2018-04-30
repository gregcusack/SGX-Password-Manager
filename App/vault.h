#define MAX_USERS 1
#ifndef USERCLASS_H
#define USERCLASS_H
#include "userclass.h"
#endif

struct vault {  //size 1384 bytes
	uint8_t m_pword[BUFF_SIZE];				 //16 bytes
	uint8_t m_iv[IV_SIZE];
	uint8_t m_mac[16];
	//uint8_t cipher[CONCAT_LEN];
	website accounts[MAX_ACCOUNTS];		//240 bytes				 
	uint32_t num_accounts;// = 0;		//4 bytes
	uint32_t full;
};