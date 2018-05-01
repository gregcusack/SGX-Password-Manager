#define BUFF_SIZE 32
#define MAX_ACCOUNTS 175
#define IV_SIZE 12
#define MAC_LEN 16
#include <stdint.h>

struct web_login { //32 bytes
	uint8_t a_uname[BUFF_SIZE]; //acount uname
	uint8_t uname_mac[MAC_LEN];
	uint8_t a_pword[BUFF_SIZE];
	uint8_t pw_mac[MAC_LEN];
};

struct website { // 48 bytes
	uint8_t web_name[BUFF_SIZE]; //website name  //16 bytes
	uint8_t web_mac[MAC_LEN+1];
	web_login credentials;	//32 bytes  //this will be stored as copy, change in future?
	uint8_t web_iv[IV_SIZE];
};
