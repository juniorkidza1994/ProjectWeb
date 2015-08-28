#include "ESA_common.h"

#define PASSWD_RESETTING_REQUESTING_INFO_CIPHERTEXT_PATH   	"ESA_cache/ESA_user_passwd_resetting.passwd_resetting_requesting_info_ciphertext"
#define PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH    	"ESA_cache/ESA_user_passwd_resetting.passwd_resetting_requesting_info_plaintext"

#define PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH "ESA_cache/ESA_user_passwd_resetting.passwd_resetting_code_requesting_result_ciphertext"
#define PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH  "ESA_cache/ESA_user_passwd_resetting.passwd_resetting_code_requesting_result_plaintext"

#define PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH 		"ESA_cache/ESA_user_passwd_resetting.passwd_resetting_result_ciphertext"
#define PASSWD_RESETTING_RESULT_PLAINTEXT_PATH  		"ESA_cache/ESA_user_passwd_resetting.passwd_resetting_result_plaintext"

#define SALTED_PASSWD_HASH_PATH      				"ESA_cache/ESA_user_passwd_resetting.salted_passwd_hash"

#define SSL_CERT_PRIV_KEY_PATH       				"ESA_cache/ESA_user_passwd_resetting.ssl_cert_priv_key"
#define SSL_CERT_REQ_PATH            				"ESA_cache/ESA_user_passwd_resetting.ssl_cert_req"
#define ENC_SSL_CERT_PATH            				"ESA_cache/ESA_user_passwd_resetting.enc_ssl_cert"
#define FULL_ENC_SSL_CERT_PATH       				"ESA_cache/ESA_user_passwd_resetting.full_enc_ssl_cert"
#define FULL_ENC_SSL_CERT_HASH_PATH  				"ESA_cache/ESA_user_passwd_resetting.full_enc_ssl_cert_hash"

// Local Function Prototypes
static boolean send_passwd_resetting_code_requesting_result(BIO *bio_client, char *info_exchange_passwd);
static boolean send_resetting_code_to_user_email_address(char *email_to, char *username, boolean is_admin_flag, char *resetting_code);
static boolean respond_passwd_resetting_code(BIO *bio_client, char *username, boolean is_admin_flag, char *info_exchange_passwd);
static boolean send_passwd_resetting_result(BIO *bio_client, char *info_exchange_passwd);
static boolean reset_user_passwd(BIO *bio_client, MYSQL *db_conn, boolean is_admin_flag, unsigned int user_or_admin_id, char *info_exchange_passwd, 
	const char *passwd_resetting_result_plaintext_path, const char *passwd_resetting_result_ciphertext_path, const char *salted_passwd_hash_path, 
	const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, const char *full_enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_hash_path);

static boolean respond_passwd_resetting(BIO *bio_client, char *username, boolean is_admin_flag, char *resetting_code, char *info_exchange_passwd);
static boolean process_request(BIO *bio_client);

// Implementation
static boolean send_passwd_resetting_code_requesting_result(BIO *bio_client, char *info_exchange_passwd)
{
	char err_msg[ERR_MSG_LENGTH + 1];

	// Encrypt the password resetting code requesting result with random session password
	if(!des3_encrypt(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH, PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH, info_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Encrypting the password resetting code requesting result failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH);

	// Send the password resetting code requesting result
	if(!BIO_send_file(bio_client, PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Sending the password resetting code requesting result failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH);
	return true;

ERROR:

	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH);
	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH);
	return false;
}

static boolean send_resetting_code_to_user_email_address(char *email_to, char *username, boolean is_admin_flag, char *resetting_code)
{
printf("***resetting_code: %s\n", resetting_code);

	char payload_msg[EMAIL_MSG_LINE_LENGTH + 1];
	sprintf(payload_msg, "To: %s\n", email_to);
	send_email_config_payload(0, payload_msg);

	sprintf(payload_msg, "From: %s(%s's mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	send_email_config_payload(1, payload_msg);

	sprintf(payload_msg, "Subject: Password resetting code\n");
	send_email_config_payload(2, payload_msg);

	sprintf(payload_msg, "\n");  // Empty line to divide headers from body, see RFC5322
	send_email_config_payload(3, payload_msg);

	sprintf(payload_msg, "Authority name = \"%s(EmU)\"\n", GLOBAL_authority_name);
	send_email_config_payload(4, payload_msg);

	sprintf(payload_msg, "Username = \"%s\"\n", username);
	send_email_config_payload(5, payload_msg);

	sprintf(payload_msg, "Status = \"%s\"\n", (is_admin_flag) ? "EmU's administrator" : "EmU's user");
	send_email_config_payload(6, payload_msg);

	sprintf(payload_msg, "Password resetting code = \"%s\"\n", resetting_code);
	send_email_config_payload(7, payload_msg);

	payload_msg[0] = 0;  // Fill a NULL terminated character to tell a send_main() that end of payload
	send_email_config_payload(8, payload_msg);

	return send_email(email_to);
}

static boolean respond_passwd_resetting_code(BIO *bio_client, char *username, boolean is_admin_flag, char *info_exchange_passwd)
{
	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_or_admin_id;
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];
	char         random_passwd_resetting_code[PASSWD_RESETTING_CODE_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check existence of the user
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else  // Normal user
	{
		sprintf(stat, "SELECT user_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__USERS, username);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the password resetting code requesting result flag
		if(!write_token_into_file("passwd_resetting_code_requesting_result_flag", "0", true, PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH))
			int_error("Writing the passwd_resetting_code_requesting_result_flag failed");

		if(!write_token_into_file("error_msg", "Invalid username", false, PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH))
				int_error("Writing the error_msg failed");

		if(!send_passwd_resetting_code_requesting_result(bio_client, info_exchange_passwd))
			goto ERROR;

		goto ERROR;
	}

	user_or_admin_id = atoi(row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password resetting code
	gen_random_password(random_passwd_resetting_code);

	// Update the password resetting code information
	if(is_admin_flag)
	{
		sprintf(stat, "UPDATE %s SET passwd_resetting_code = '%s' WHERE admin_id = %u", ESA__ADMINS, random_passwd_resetting_code, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "UPDATE %s SET passwd_resetting_code = '%s' WHERE user_id = %u", ESA__USERS, random_passwd_resetting_code, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_resetting_code_to_user_email_address(email_address, username, is_admin_flag, random_passwd_resetting_code))
	{
		// Send the password resetting code requesting result flag
		if(!write_token_into_file("passwd_resetting_code_requesting_result_flag", "0", true, PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH))
			int_error("Writing the passwd_resetting_code_requesting_result_flag failed");

		if(!write_token_into_file("error_msg", get_send_email_error_msg(), false, PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH))
			int_error("Writing the error_msg failed");

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!send_passwd_resetting_code_requesting_result(bio_client, info_exchange_passwd))
			goto ERROR;

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the password resetting code requesting result flag
	if(!write_token_into_file("passwd_resetting_code_requesting_result_flag", "1", true, PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH))
		int_error("Writing the passwd_resetting_code_requesting_result_flag failed");

	if(!send_passwd_resetting_code_requesting_result(bio_client, info_exchange_passwd))
		goto ERROR;

	return true;

ERROR:

	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_PLAINTEXT_PATH);
	unlink(PASSWD_RESETTING_CODE_REQUESTING_RESULT_CIPHERTEXT_PATH);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;	
}

static boolean send_passwd_resetting_result(BIO *bio_client, char *info_exchange_passwd)
{
	char err_msg[ERR_MSG_LENGTH + 1];

	// Encrypt the password resetting result with random session password
	if(!des3_encrypt(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH, PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH, info_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Encrypting the password resetting result failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH);

	// Send the password resetting result
	if(!BIO_send_file(bio_client, PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Sending the password resetting result failed");
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH);
	return true;

ERROR:

	unlink(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH);
	unlink(PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH);
	return false;
}

static boolean reset_user_passwd(BIO *bio_client, MYSQL *db_conn, boolean is_admin_flag, unsigned int user_or_admin_id, char *info_exchange_passwd, 
	const char *passwd_resetting_result_plaintext_path, const char *passwd_resetting_result_ciphertext_path, const char *salted_passwd_hash_path, 
	const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, const char *full_enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_hash_path)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      username[USER_NAME_LENGTH + 1];
	char      email_address[EMAIL_ADDRESS_LENGTH + 1];

	char      random_passwd[PASSWD_LENGTH + 1];
	char      random_salt_value[SALT_VALUE_LENGTH + 1];
	char      new_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char      salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	// Query for the user/admin
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT username, email_address FROM %s WHERE admin_id = %u", ESA__ADMINS, user_or_admin_id);	
	}
	else
	{
		sprintf(stat, "SELECT username, email_address FROM %s WHERE user_id = %u", ESA__USERS, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
	{
		if(!write_token_into_file("passwd_resetting_result_flag", "0", true, passwd_resetting_result_plaintext_path))
			int_error("Writing the passwd_resetting_result_flag failed");

		if(!write_token_into_file("error_msg", "User does not exist", false, passwd_resetting_result_plaintext_path))
			int_error("Writing the error_msg failed");

		// Encrypt the password resetting result with random session password
		if(!des3_encrypt(passwd_resetting_result_plaintext_path, passwd_resetting_result_ciphertext_path, info_exchange_passwd, err_msg))
		{
			fprintf(stderr, "Encrypting the password resetting result failed\n\"%s\"\n", err_msg);
			goto ERROR;
		}

		unlink(passwd_resetting_result_plaintext_path);

		// Send the password resetting result
		if(!BIO_send_file(bio_client, passwd_resetting_result_ciphertext_path))
		{
			fprintf(stderr, "Sending the password resetting result failed");
			goto ERROR;
		}

		unlink(passwd_resetting_result_ciphertext_path);
		goto ERROR;
	}

	strcpy(username, row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(new_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(new_passwd_with_salt_value, strlen(new_passwd_with_salt_value), salted_passwd_hash, salted_passwd_hash_path);

	// Update the password hash information
	if(is_admin_flag)
	{
		sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE admin_id = %u", 
			ESA__ADMINS, salted_passwd_hash, random_salt_value, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE user_id = %u", 
			ESA__USERS, salted_passwd_hash, random_salt_value, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
	{
	      	sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Generate an SSL certificate
	generate_ssl_cert(db_conn, user_or_admin_id, username, is_admin_flag, random_passwd, email_address, ssl_cert_priv_key_path, ssl_cert_req_path, enc_ssl_cert_path, 
		full_enc_ssl_cert_path, full_enc_ssl_cert_hash_path);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, is_admin_flag, random_passwd))
	{
		// Send the password resetting result flag
		if(!write_token_into_file("passwd_resetting_result_flag", "0", true, passwd_resetting_result_plaintext_path))
			int_error("Writing the passwd_resetting_result_flag failed");

		if(!write_token_into_file("error_msg", get_send_email_error_msg(), false, passwd_resetting_result_plaintext_path))
			int_error("Writing the error_msg failed");

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		// Encrypt the password resetting result with random session password
		if(!des3_encrypt(passwd_resetting_result_plaintext_path, passwd_resetting_result_ciphertext_path, info_exchange_passwd, err_msg))
		{
			fprintf(stderr, "Encrypting the password resetting result failed\n\"%s\"\n", err_msg);
			goto ERROR;
		}

		unlink(passwd_resetting_result_plaintext_path);

		// Send the password resetting result
		if(!BIO_send_file(bio_client, passwd_resetting_result_ciphertext_path))
		{
			fprintf(stderr, "Sending the password resetting result failed");
			goto ERROR;
		}

		unlink(passwd_resetting_result_ciphertext_path);
		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	return true;

ERROR:
	unlink(passwd_resetting_result_plaintext_path);
	unlink(passwd_resetting_result_ciphertext_path);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;
}

static boolean respond_passwd_resetting(BIO *bio_client, char *username, boolean is_admin_flag, char *resetting_code, char *info_exchange_passwd)
{
	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_or_admin_id;
	char         resetting_code_cmp[PASSWD_RESETTING_CODE_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check existence of the user/admin
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id, passwd_resetting_code FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else  // Normal user
	{
		sprintf(stat, "SELECT user_id, passwd_resetting_code FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__USERS, username);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// The user/admin does not exist
	if(!row)
	{
		// Send the password resetting result flag
		if(!write_token_into_file("passwd_resetting_result_flag", "0", true, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH))
			int_error("Writing the passwd_resetting_result_flag failed");

		if(!write_token_into_file("error_msg", "Invalid username", false, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH))
				int_error("Writing the error_msg failed");

		if(!send_passwd_resetting_result(bio_client, info_exchange_passwd))
			goto ERROR;

		goto ERROR;
	}	

	user_or_admin_id = atoi(row[0]);
	strcpy(resetting_code_cmp, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(strcmp(resetting_code_cmp, resetting_code) != 0)
	{
		// Send the password resetting result flag
		if(!write_token_into_file("passwd_resetting_result_flag", "0", true, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH))
			int_error("Writing the passwd_resetting_result_flag failed");

		if(!write_token_into_file("error_msg", "Invalid password resetting code", false, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH))
				int_error("Writing the error_msg failed");

		if(!send_passwd_resetting_result(bio_client, info_exchange_passwd))
			goto ERROR;

		goto ERROR;
	}
	
	// Reset the user/admin's password
	if(!reset_user_passwd(bio_client, db_conn, is_admin_flag, user_or_admin_id, info_exchange_passwd, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH, 
		PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH, SALTED_PASSWD_HASH_PATH, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH))
	{
		goto ERROR;
	}

	// Update the password resetting code information
	if(is_admin_flag)
	{
		sprintf(stat, "UPDATE %s SET passwd_resetting_code = '' WHERE admin_id = %u", ESA__ADMINS, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "UPDATE %s SET passwd_resetting_code = '' WHERE user_id = %u", ESA__USERS, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
	disconnect_db(&db_conn);

	// Send the password resetting result flag
	if(!write_token_into_file("passwd_resetting_result_flag", "1", true, PASSWD_RESETTING_RESULT_PLAINTEXT_PATH))
		int_error("Writing the passwd_resetting_result_flag failed");

	if(!send_passwd_resetting_result(bio_client, info_exchange_passwd))
		goto ERROR;

	return true;

ERROR:

	unlink(PASSWD_RESETTING_RESULT_PLAINTEXT_PATH);
	unlink(PASSWD_RESETTING_RESULT_CIPHERTEXT_PATH);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean process_request(BIO *bio_client)
{
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char	err_msg[ERR_MSG_LENGTH + 1];

	char    request[REQUEST_TYPE_LENGTH + 1];
	char    username[USER_NAME_LENGTH + 1];
	char    is_admin_flag_str_tmp[FLAG_LENGTH + 1];   // "0" or "1"
	boolean is_admin_flag;
	char    resetting_code[PASSWD_RESETTING_CODE_LENGTH + 1];
	char    info_exchange_passwd[PASSWD_LENGTH + 1];

	// Receive the password resetting requesting  information
	if(!BIO_recv_file(bio_client, PASSWD_RESETTING_REQUESTING_INFO_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Receiving password resetting requesting information failed\n");
		goto ERROR;
	}

	// Decrypt the password resetting requesting information with the Emergency Staff Authority's private key
	if(!smime_decrypt_with_cert(PASSWD_RESETTING_REQUESTING_INFO_CIPHERTEXT_PATH, 
		PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, err_msg))
	{
		fprintf(stderr, "Decrypting password resetting requesting information failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(PASSWD_RESETTING_REQUESTING_INFO_CIPHERTEXT_PATH);

	// Get the password resetting requesting information from file
	if(read_token_from_file(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, 1, token_name, request) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
	{
		int_error("Extracting the request failed");
	}

	if(read_token_from_file(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, 2, token_name, username) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
	{
		int_error("Extracting the username failed");
	}

	if(read_token_from_file(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, 3, token_name, is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_admin_flag") != 0)
	{
		int_error("Extracting the is_admin_flag failed");
	}

	is_admin_flag = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(strcmp(request, PASSWD_RESETTING_CODE_REQUESTING) == 0)
	{
		if(read_token_from_file(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, 4, token_name, info_exchange_passwd) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "info_exchange_passwd") != 0)
		{
			int_error("Extracting the info_exchange_passwd failed");
		}
	}
	else if(strcmp(request, PASSWD_RESETTING) == 0)
	{
		if(read_token_from_file(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, 4, token_name, resetting_code) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "resetting_code") != 0)
		{
			int_error("Extracting the resetting_code failed");
		}

		if(read_token_from_file(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH, 5, token_name, info_exchange_passwd) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "info_exchange_passwd") != 0)
		{
			int_error("Extracting the info_exchange_passwd failed");
		}
	}

	unlink(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH);

	// Process a request
	if(strcmp(request, PASSWD_RESETTING_CODE_REQUESTING) == 0)
	{
		return respond_passwd_resetting_code(bio_client, username, is_admin_flag, info_exchange_passwd);
	}
	else if(strcmp(request, PASSWD_RESETTING) == 0)
	{
		return respond_passwd_resetting(bio_client, username, is_admin_flag, resetting_code, info_exchange_passwd);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	unlink(PASSWD_RESETTING_REQUESTING_INFO_CIPHERTEXT_PATH);
	unlink(PASSWD_RESETTING_REQUESTING_INFO_PLAINTEXT_PATH);
	return false;	
}

void *user_passwd_resetting_main(void *arg)
{
    	BIO *bio_acc    = NULL;
	BIO *bio_client = NULL;

    	bio_acc = BIO_new_accept(ESA_USER_PASSWD_RESETTING_PORT);
    	if(!bio_acc)
        	int_error("Creating server socket failed");
  
    	if(BIO_do_accept(bio_acc) <= 0)
        	int_error("Binding server socket failed");
  
    	for(;;)
    	{
        	if(BIO_do_accept(bio_acc) <= 0)
            		int_error("Accepting connection failed");
 
        	bio_client = BIO_pop(bio_acc);

		// Process a request
		if(!process_request(bio_client))
			goto ERROR;
ERROR:

		BIO_free(bio_client);
		bio_client = NULL;
		ERR_remove_state(0);
    	}
    
    	BIO_free(bio_acc);
	bio_acc = NULL;

	pthread_exit(NULL);
    	return NULL;
}



