#define BUFF_SIZE 256
#define MAX_ACCOUNTS 6325
#define IV_SIZE 12
#define MAC_LEN 16

struct web_login {
	uint8_t a_uname[BUFF_SIZE]; //acount uname
	uint8_t uname_mac[MAC_LEN];
	uint8_t a_pword[BUFF_SIZE];
	uint8_t pw_mac[MAC_LEN];
};

struct website { 
	uint8_t web_name[BUFF_SIZE]; //website name
	uint8_t web_mac[MAC_LEN+1];
	web_login credentials;
	uint8_t web_iv[IV_SIZE];
};
