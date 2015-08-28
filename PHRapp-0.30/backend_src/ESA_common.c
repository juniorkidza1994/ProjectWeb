#include "ESA_common.h"

// Implementation
void gen_random_salt_value(char *salt_value_ret)     // Generate a random 8 character salt value
{
	char cmd[25];
	char ret_code[100];

	sprintf(cmd, "openssl rand -base64 6");
	exec_cmd(cmd, strlen(cmd), ret_code, sizeof(ret_code));

	// Function returns an 8 character salt value with new line character
	if(strlen(ret_code) != 9)
	{
		fprintf(stderr, "err_code: \"%s\"\n", ret_code);
		int_error("Generating a random salt value failed");
	}

	strncpy(salt_value_ret, ret_code, 8);
	salt_value_ret[8] = 0;
}



