#include "ESA_common.h"

#define SALTED_PASSWD_HASH_PATH      "ESA_cache/UA_user_management.salted_passwd_hash"

#define SSL_CERT_PRIV_KEY_PATH       "ESA_cache/ESA_user_management.ssl_cert_priv_key"
#define SSL_CERT_REQ_PATH            "ESA_cache/ESA_user_management.ssl_cert_req"
#define ENC_SSL_CERT_PATH            "ESA_cache/ESA_user_management.enc_ssl_cert"
#define FULL_ENC_SSL_CERT_PATH       "ESA_cache/ESA_user_management.full_enc_ssl_cert"
#define FULL_ENC_SSL_CERT_HASH_PATH  "ESA_cache/ESA_user_management.full_enc_ssl_cert_hash"

// Local Function Prototypes
static boolean register_user(SSL *ssl_client, boolean is_admin_flag);
static boolean edit_user_email_address(SSL *ssl_client, boolean is_admin_flag);
static boolean reset_user_passwd(SSL *ssl_client, boolean is_admin_flag);
static boolean remove_user(SSL *ssl_client, boolean is_admin_flag);

// Implementation
void generate_ssl_cert(MYSQL *db_conn, unsigned int user_or_admin_id, char *username, boolean is_admin_flag, char *passwd, char *email_address, 
	const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, const char *full_enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_hash_path)
{
	char         cmd[CMD_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];
	char         stat[SQL_STATEMENT_LENGTH + 1];

	unsigned int len, enc_ssl_cert_size;
	char         *enc_ssl_cert_data;
	char         enc_ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];
	char         *enc_ssl_cert_chunk;
	char         *query;

	// Generate an SSL certificate
	if(is_admin_flag)
	{
		sprintf(cmd, "openssl req -newkey rsa:1024 -sha1 -keyout %s -out %s -passout pass:%s -subj '/CN=%s.%s%s"
			"/ST=Songkla/C=TH/emailAddress=%s/O=PSU/OU=PSU'", ssl_cert_priv_key_path, ssl_cert_req_path, passwd, 
			GLOBAL_authority_name, username, ADMIN_IDENTITY_TOKEN, email_address);
	}
	else
	{
		sprintf(cmd, "openssl req -newkey rsa:1024 -sha1 -keyout %s -out %s -passout pass:%s -subj '/CN=%s.%s%s"
			"/ST=Songkla/C=TH/emailAddress=%s/O=PSU/OU=PSU'", ssl_cert_priv_key_path, ssl_cert_req_path, passwd, 
			GLOBAL_authority_name, username, USER_IDENTITY_TOKEN, email_address);
	}

	exec_cmd(cmd, strlen(cmd), err_msg, sizeof(err_msg));
	if(!strstr(err_msg, "writing new private key"))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an SSL certificate failed");
	}

	sprintf(cmd, "openssl x509 -req -days 365 -in %s -sha1 -extfile %s -extensions usr_cert -CA %s -CAkey %s -CAcreateserial "
		"-out %s -passin pass:%s", ssl_cert_req_path, OPENSSL_PHRAPP_CNF_PATH, USER_CA_FULL_CERTFILE_PATH, 
		USER_CA_FULL_CERTFILE_PATH, enc_ssl_cert_path, USER_CA_CERTFILE_PASSWD);

	exec_cmd(cmd, strlen(cmd), err_msg, sizeof(err_msg));
	if(!strstr(err_msg, "Getting CA Private Key"))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an SSL certificate failed");
	}

	sprintf(cmd, "cat %s %s %s %s > %s", enc_ssl_cert_path, ssl_cert_priv_key_path, USER_CA_ONLY_CERT_CERTFILE_PATH, 
		EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH, full_enc_ssl_cert_path);

	exec_cmd(cmd, strlen(cmd), err_msg, sizeof(err_msg));
	if(strcmp(err_msg, "") != 0)
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an SSL certificate failed");
	}

	// Allocate heap variables
	enc_ssl_cert_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!enc_ssl_cert_data)
	{
		int_error("Allocating memory for \"enc_ssl_cert_data\" failed");
	}

	enc_ssl_cert_chunk = (char *)malloc(sizeof(char)*((1000*1024)*2+1));
	if(!enc_ssl_cert_chunk)
	{
		int_error("Allocating memory for \"enc_ssl_cert_chunk\" failed");
	}

	query = (char *)malloc(sizeof(char)*(((1000*1024)*2+1)+sizeof(stat)+1));
	if(!query)
	{
		int_error("Allocating memory for \"query\" failed");
	}

	// Read the SSL certificate into the buffer
	if(!read_bin_file(full_enc_ssl_cert_path, enc_ssl_cert_data, sizeof(char)*1000*1024, &enc_ssl_cert_size))
		int_error("Reading full encrypted SSL certificate failed");

	sum_sha1_from_file(full_enc_ssl_cert_path, enc_ssl_cert_hash, full_enc_ssl_cert_hash_path);

	// Insert encrypted SSL certificate and its hash into database
	if(is_admin_flag)
	{
		sprintf(stat, "UPDATE %s SET enc_ssl_cert='%%s', enc_ssl_cert_hash='%s' WHERE admin_id=%u", ESA__ADMINS, enc_ssl_cert_hash, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "UPDATE %s SET enc_ssl_cert='%%s', enc_ssl_cert_hash='%s' WHERE user_id=%u", ESA__USERS, enc_ssl_cert_hash, user_or_admin_id);
	}

	// Delete files
	unlink(ssl_cert_priv_key_path);
	unlink(ssl_cert_req_path);
	unlink(enc_ssl_cert_path);
	unlink(full_enc_ssl_cert_path);

	// Take the escaped SQL string
	mysql_real_escape_string(db_conn, enc_ssl_cert_chunk, enc_ssl_cert_data, enc_ssl_cert_size);
  	len = snprintf(query, sizeof(stat)+sizeof(char)*((1000*1024)*2+1), stat, enc_ssl_cert_chunk);

	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Free heap variables
	if(enc_ssl_cert_data)
	{
		free(enc_ssl_cert_data);
		enc_ssl_cert_data = NULL;
	}

	if(enc_ssl_cert_chunk)
	{
		free(enc_ssl_cert_chunk);
		enc_ssl_cert_chunk = NULL;
	}

	if(query)
	{
		free(query);
		query = NULL;
	}
}

boolean send_passwd_to_user_email_address(char *email_to, char *username, boolean is_admin_flag, char *passwd)
{
printf("***passwd: %s\n", passwd);

	char payload_msg[EMAIL_MSG_LINE_LENGTH + 1];
	sprintf(payload_msg, "To: %s\n", email_to);
	send_email_config_payload(0, payload_msg);

	sprintf(payload_msg, "From: %s(%s's mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	send_email_config_payload(1, payload_msg);

	sprintf(payload_msg, "Subject: Your account's password\n");
	send_email_config_payload(2, payload_msg);

	sprintf(payload_msg, "\n");  // Empty line to divide headers from body, see RFC5322
	send_email_config_payload(3, payload_msg);

	sprintf(payload_msg, "Authority name = \"%s(EmU)\"\n", GLOBAL_authority_name);
	send_email_config_payload(4, payload_msg);

	sprintf(payload_msg, "Username = \"%s\"\n", username);
	send_email_config_payload(5, payload_msg);

	sprintf(payload_msg, "Status = \"%s\"\n", (is_admin_flag) ? "EmU's administrator" : "EmU's user");
	send_email_config_payload(6, payload_msg);

	sprintf(payload_msg, "Password = \"%s\"\n", passwd);
	send_email_config_payload(7, payload_msg);

	payload_msg[0] = 0;  // Fill a NULL terminated character to tell a send_main() that end of payload
	send_email_config_payload(8, payload_msg);

	return send_email(email_to);
}

static boolean register_user(SSL *ssl_client, boolean is_admin_flag)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	unsigned int user_or_admin_id;

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];
	
	// Receive user/admin information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user/admin information failed\n");
		goto ERROR;
	}

	// Get user/admin information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username. If the username does not exist then add it into database
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__USERS, username);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The username exists
	if(row)
	{
		// Send the user/admin registration result flag
		write_token_into_buffer("user_or_admin_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Username exists already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

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
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Insert a new user if he/she does not exist
	if(is_admin_flag)
	{
		sprintf(stat, "INSERT INTO %s(username, salted_passwd_hash, salt_value, email_address, passwd_resetting_code, enc_ssl_cert, enc_ssl_cert_hash) "
			"VALUES('%s', '%s', '%s', '%s', '', NULL, NULL)", ESA__ADMINS, username, salted_passwd_hash, random_salt_value, email_address);
	}
	else
	{
		sprintf(stat, "INSERT INTO %s(username, salted_passwd_hash, salt_value, email_address, passwd_resetting_code, enc_ssl_cert, enc_ssl_cert_hash) "
			"VALUES('%s', '%s', '%s', '%s', '', NULL, NULL)", ESA__USERS, username, salted_passwd_hash, random_salt_value, email_address);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
	
	// Get a user/admin's id
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__USERS, username);
	}

	if(mysql_query(db_conn, stat))
 	{
	      	sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
		int_error("Getting a user/admin id from database failed");

	user_or_admin_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	
	// Generate an SSL certificate
	generate_ssl_cert(db_conn, user_or_admin_id, username, is_admin_flag, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, is_admin_flag, random_passwd))
	{
		// Send the user/admin registration result flag
		write_token_into_buffer("user_or_admin_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");
	
	// Send the user/admin registration result flag
	write_token_into_buffer("user_or_admin_registration_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user/admin registration result flag failed\n");
		goto ERROR;
	}	

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean edit_user_email_address(SSL *ssl_client, boolean is_admin_flag)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_or_admin_id;

	// Receive user/admin's e-mail address information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user/admin's e-mail address information failed\n");
		goto ERROR;
	}

	// Get user/admin's e-mail address information editing tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__USERS, username);
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
		// Send the user/admin email address editing result flag
		write_token_into_buffer("user_or_admin_email_address_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin email address editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_or_admin_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Update the user/admin's e-mail address
	if(is_admin_flag)
	{
		sprintf(stat, "UPDATE %s SET email_address = '%s' WHERE admin_id = %u", ESA__ADMINS, email_address, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "UPDATE %s SET email_address = '%s' WHERE user_id = %u", ESA__USERS, email_address, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	
	// Send the user/admin email address editing result flag
	write_token_into_buffer("user_or_admin_email_address_editing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user/admin email address editing result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean reset_user_passwd(SSL *ssl_client, boolean is_admin_flag)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_or_admin_id;
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	// Receive user/admin password resetting information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user/admin password resetting information failed\n");
		goto ERROR;
	}

	// Get a user/admin password resetting information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else
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

	// The user/admin does not exist
	if(!row)
	{
		// Send the user/admin password resetting result flag
		write_token_into_buffer("user_or_admin_passwd_resetting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin password resetting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_or_admin_id = atoi(row[0]);
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
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

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
	generate_ssl_cert(db_conn, user_or_admin_id, username, is_admin_flag, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, is_admin_flag, random_passwd))
	{
		// Send the user/admin password resetting result flag
		write_token_into_buffer("user_or_admin_passwd_resetting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin password resetting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the user/admin password resetting result flag
	write_token_into_buffer("user_or_admin_passwd_resetting_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user/admin password resetting result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean remove_user(SSL *ssl_client, boolean is_admin_flag)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_or_admin_id;

	// Receive user/admin removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user/admin removal information failed\n");
		goto ERROR;
	}

	// Get a user/admin removal information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", ESA__USERS, username);	
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
		// Send the user/admin removal result flag
		write_token_into_buffer("user_or_admin_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_or_admin_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete the user/admin
	if(is_admin_flag)
	{
		sprintf(stat, "DELETE FROM %s WHERE admin_id = %u", ESA__ADMINS, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "DELETE FROM %s WHERE user_id = %u", ESA__USERS, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	disconnect_db(&db_conn);

	// Send the user/admin removal result flag
	write_token_into_buffer("user_or_admin_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user/admin removal result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean process_request(SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];
	char request[REQUEST_TYPE_LENGTH + 1];
	
	// Receive request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request information failed\n");
		goto ERROR;
	}

	// Get a request information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(strcmp(request, USER_REGISTRATION) == 0)
	{
		return register_user(ssl_client, false);
	}
	else if(strcmp(request, USER_EMAIL_ADDRESS_EDITING) == 0)
	{
		return edit_user_email_address(ssl_client, false);
	}
	else if(strcmp(request, USER_PASSWD_RESETTING) == 0)
	{
		return reset_user_passwd(ssl_client, false);
	}
	else if(strcmp(request, USER_REMOVAL) == 0)
	{
		return remove_user(ssl_client, false);
	}
	else if(strcmp(request, ADMIN_REGISTRATION) == 0)
	{
		return register_user(ssl_client, true);
	}
	else if(strcmp(request, ADMIN_EMAIL_ADDRESS_EDITING) == 0)
	{
		return edit_user_email_address(ssl_client, true);
	}
	else if(strcmp(request, ADMIN_PASSWD_RESETTING) == 0)
	{
		return reset_user_passwd(ssl_client, true);
	}
	else if(strcmp(request, ADMIN_REMOVAL) == 0)
	{
		return remove_user(ssl_client, true);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *user_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_USER_MANAGEMENT_PORT);
    	if(!bio_acc)
        	int_error("Creating server socket failed");
  
    	if(BIO_do_accept(bio_acc) <= 0)
        	int_error("Binding server socket failed");
  
    	for(;;)
    	{
        	if(BIO_do_accept(bio_acc) <= 0)
            		int_error("Accepting connection failed");
 
        	bio_client = BIO_pop(bio_acc);

        	if(!(ssl_client = SSL_new(ctx)))
            		int_error("Creating SSL context failed");

        	SSL_set_bio(ssl_client, bio_client, bio_client);
		if(SSL_accept(ssl_client) <= 0)
		{
        		fprintf(stderr, "Accepting SSL connection failed\n");
			goto ERROR_AT_SSL_LAYER;
		}

		hosts[0] = ADMIN_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process a request
		if(!process_request(ssl_client))
			goto ERROR_AT_SSL_LAYER;

ERROR_AT_SSL_LAYER:

		SSL_cleanup(ssl_client);
		ssl_client = NULL;
    		ERR_remove_state(0);
    	}
    
    	SSL_CTX_free(ctx);
	ctx = NULL;

    	BIO_free(bio_acc);
	bio_acc = NULL;

	pthread_exit(NULL);
    	return NULL;
}



