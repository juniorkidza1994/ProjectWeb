#include "EmU_client_common.h"

#define PASSWD_RESETTING_CODE_REQUESTING_INFO_CIPHERTEXT_PATH   "EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_code_requesting_info_ciphertext"
#define PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH    "EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_code_requesting_info_plaintext"
#define PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH "EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_code_requesting_result_ciphertext"
#define PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH  "EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_code_requesting_result_plaintext"

#define PASSWD_RESETTING_INFO_CIPHERTEXT_PATH   		"EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_info_ciphertext"
#define PASSWD_RESETTING_INFO_PLAINTEXT_PATH    		"EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_info_plaintext"
#define PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH 		"EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_result_ciphertext"
#define PASSWD_RESETTING_RESULT_PLAINTEXT_PATH  		"EmU_client_cache/EmU_client_passwd_resetting.passwd_resetting_result_plaintext"

// Local Variable
static void (*backend_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototype
static void backend_alert_msg_handler_callback(char *alert_msg);

// Implementation
static void backend_alert_msg_handler_callback(char *alert_msg)
{
	if(backend_alert_msg_callback_handler)
	{
		backend_alert_msg_callback_handler(alert_msg);
	}
	else  // NULL
	{
		int_error("backend_alert_msg_callback_handler is NULL");
	}
}

boolean request_emu_passwd_resetting_code(char *emergency_staff_auth_ip_addr, char *username, boolean is_admin_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handler
	backend_alert_msg_callback_handler = backend_alert_msg_callback_handler_ptr;

	BIO     *bio_conn = NULL;
	char    emergency_staff_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];
	char    info_exchange_passwd[PASSWD_LENGTH + 1];  // Temporary random password for for exchanging information in a BIO channel

	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    err_msg[ERR_MSG_LENGTH + 1];
	char    passwd_resetting_code_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];  // "0" or "1"
	boolean passwd_resetting_code_requesting_result_flag;

	// Connect to Emergency Staff Authority
	sprintf(emergency_staff_auth_addr, "%s:%s", emergency_staff_auth_ip_addr, ESA_USER_PASSWD_RESETTING_PORT);
	bio_conn = BIO_new_connect(emergency_staff_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_handler_callback("Connecting to emergency staff authority failed");
		goto ERROR;
	}

	// Generate a temporary random 8 character password for exchanging information in a BIO channel
	gen_random_password(info_exchange_passwd);

	if(!write_token_into_file("request", PASSWD_RESETTING_CODE_REQUESTING, true, PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the request failed");

	if(!write_token_into_file("username", username, false, PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the username failed");

	if(!write_token_into_file("is_admin_flag", (is_admin_flag) ? "1" : "0", false, PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the is_admin_flag failed");

	if(!write_token_into_file("info_exchange_passwd", info_exchange_passwd, false, PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the info_exchange_passwd failed");

	// Encrypt the password resetting code requesting information with the Emergency Staff Authority's public key
	if(!smime_encrypt_with_cert(PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH, 
		PASSWD_RESETTING_CODE_REQUESTING_INFO_CIPHERTEXT_PATH, ESA_PUB_CERTFILE_PATH, err_msg))
	{
		fprintf(stderr, "Encrypting the password resetting code requesting information failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Encrypting the password resetting code requesting information failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH);

	// Send the password resetting code requesting information
	if(!BIO_send_file(bio_conn, PASSWD_RESETTING_CODE_REQUESTING_INFO_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Sending the password resetting code requesting information failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_CODE_REQUESTING_INFO_CIPHERTEXT_PATH);

	// Receive the password resetting code requesting result
	if(!BIO_recv_file(bio_conn, PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Receiving password resetting code requesting result failed");
		goto ERROR;
	}

	// Decrypt the password resetting code requesting result with the info_exchange_passwd
	if(!des3_decrypt(PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH, PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH, info_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the password resetting code requesting result failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the password resetting code requesting result failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH);

	// Get the password resetting code requesting result flag from file
	if(read_token_from_file(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH, 1, token_name, passwd_resetting_code_requesting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "passwd_resetting_code_requesting_result_flag") != 0)
	{
		int_error("Extracting the passwd_resetting_code_requesting_result_flag failed");
	}

	passwd_resetting_code_requesting_result_flag = (strcmp(passwd_resetting_code_requesting_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!passwd_resetting_code_requesting_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from file
		if(read_token_from_file(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH, 2, 
			token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
		{
			int_error("Extracting the error_msg failed");
		}
		
		backend_alert_msg_handler_callback(error_msg);

		unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH);
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH);

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);
	return true;

ERROR:

	unlink(PASSWD_RESETTING_CODE_REQUESTING_INFO_PLAINTEXT_PATH);
	unlink(PASSWD_RESETTING_CODE_REQUESTING_INFO_CIPHERTEXT_PATH);
	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH);
	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH);

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);
	return false;
}

boolean reset_emu_passwd(char *emergency_staff_auth_ip_addr, char *username, boolean is_admin_flag, char *resetting_code, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handler
	backend_alert_msg_callback_handler = backend_alert_msg_callback_handler_ptr;

	BIO     *bio_conn = NULL;
	char    emergency_staff_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];
	char    info_exchange_passwd[PASSWD_LENGTH + 1];  // Temporary random password for for exchanging information in a BIO channel

	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    err_msg[ERR_MSG_LENGTH + 1];
	char    passwd_resetting_result_flag_str_tmp[FLAG_LENGTH + 1];  // "0" or "1"
	boolean passwd_resetting_result_flag;

	// Connect to Emergency Staff Authority
	sprintf(emergency_staff_auth_addr, "%s:%s", emergency_staff_auth_ip_addr, ESA_USER_PASSWD_RESETTING_PORT);
	bio_conn = BIO_new_connect(emergency_staff_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_handler_callback("Connecting to emergency staff authority failed");
		goto ERROR;
	}

	// Generate a temporary random 8 character password for exchanging information in a BIO channel
	gen_random_password(info_exchange_passwd);

	if(!write_token_into_file("request", PASSWD_RESETTING, true, PASSWD_RESETTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the request failed");

	if(!write_token_into_file("username", username, false, PASSWD_RESETTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the username failed");

	if(!write_token_into_file("is_admin_flag", (is_admin_flag) ? "1" : "0", false, PASSWD_RESETTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the is_admin_flag failed");

	if(!write_token_into_file("resetting_code", resetting_code, false, PASSWD_RESETTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the resetting_code failed");

	if(!write_token_into_file("info_exchange_passwd", info_exchange_passwd, false, PASSWD_RESETTING_INFO_PLAINTEXT_PATH))
		int_error("Writing the info_exchange_passwd failed");

	// Encrypt the password resetting information with the Emergency Staff Authority's public key
	if(!smime_encrypt_with_cert(PASSWD_RESETTING_INFO_PLAINTEXT_PATH, PASSWD_RESETTING_INFO_CIPHERTEXT_PATH, ESA_PUB_CERTFILE_PATH, err_msg))
	{
		fprintf(stderr, "Encrypting the password resetting information failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Encrypting the password resetting information failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_INFO_PLAINTEXT_PATH);

	// Send the password resetting information
	if(!BIO_send_file(bio_conn, PASSWD_RESETTING_INFO_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Sending the password resetting information failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_INFO_CIPHERTEXT_PATH);

	// Receive the password resetting result
	if(!BIO_recv_file(bio_conn, PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Receiving password resetting result failed");
		goto ERROR;
	}

	// Decrypt the password resetting result with the info_exchange_passwd
	if(!des3_decrypt(PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH, info_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the password resetting result failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the password resetting result failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH);

	// Get the password resetting result flag from file
	if(read_token_from_file(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH, 1, token_name, passwd_resetting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "passwd_resetting_result_flag") != 0)
	{
		int_error("Extracting the passwd_resetting_result_flag failed");
	}

	passwd_resetting_result_flag = (strcmp(passwd_resetting_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!passwd_resetting_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from file
		if(read_token_from_file(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH, 2, token_name, error_msg) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
		{
			int_error("Extracting the error_msg failed");
		}
		
		backend_alert_msg_handler_callback(error_msg);

		unlink(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH);
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH);

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);
	return true;

ERROR:

	unlink(PASSWD_RESETTING_INFO_PLAINTEXT_PATH);
	unlink(PASSWD_RESETTING_INFO_CIPHERTEXT_PATH);
	unlink(PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH);
	unlink(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH);

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);
	return false;
}



