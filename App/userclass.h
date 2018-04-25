#define BUFF_SIZE 256
#define MAX_ACCOUNTS 6325
#define IV_SIZE 16
#include <stdint.h>

typedef struct web_login { //32 bytes
	unsigned char a_uname[BUFF_SIZE]; //acount uname
	unsigned char a_pword[BUFF_SIZE];
} web_login;

typedef struct website { // 48 bytes
	unsigned char web_name[BUFF_SIZE]; //website name  //16 bytes
	web_login credentials;	//32 bytes  //this will be stored as copy, change in future?
	uint8_t web_iv[IV_SIZE];
} website;
