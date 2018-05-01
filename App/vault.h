#define MAX_USERS 1
#ifndef USERCLASS_H
#define USERCLASS_H
#include "userclass.h"
#endif

struct vault {  
	uint8_t m_pword[BUFF_SIZE];		
	uint8_t m_iv[IV_SIZE];
	uint8_t m_mac[16];
	website accounts[MAX_ACCOUNTS];					 
	uint32_t num_accounts;
	uint32_t full;
};