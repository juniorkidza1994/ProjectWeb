#include "ESA_common.h"

#define SALTED_PASSWD_HASH_PATH      "ESA_cache/ESA_user_info_management.salted_passwd_hash"

#define SSL_CERT_PRIV_KEY_PATH       "ESA_cache/ESA_user_info_management.ssl_cert_priv_key"
#define SSL_CERT_REQ_PATH            "ESA_cache/ESA_user_info_management.ssl_cert_req"
#define ENC_SSL_CERT_PATH            "ESA_cache/ESA_user_info_management.enc_ssl_cert"
#define FULL_ENC_SSL_CERT_PATH       "ESA_cache/ESA_user_info_management.full_enc_ssl_cert"
#define FULL_ENC_SSL_CERT_HASH_PATH  "ESA_cache/ESA_user_info_management.full_enc_ssl_cert_hash"

// Local Function Prototypes
static boolean change_user_passwd(SSL *ssl_client, MYSQL *db_conn, boolean is_admin_flag, unsigned int user_or_admin_id, char *new_passwd, boolean send_new_passwd_flag, 
	const char *salted_passwd_hash_path, const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_path, const char *full_enc_ssl_cert_hash_path);

static boolean change_user_passwd_main(SSL *ssl_client, boolean is_admin_flag, char *username);
static boolean change_user_email_address(SSL *ssl_client, boolean is_admin_flag, char *username);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean change_user_passwd(SSL *ssl_client, MYSQL *db_conn, boolean is_admin_flag, unsigned int user_or_admin_id, char *new_passwd, boolean send_new_passwd_flag, 
	const char *salted_passwd_hash_path, const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_path, const char *full_enc_ssl_cert_hash_path)
{
	char      buffer[BUFFER_LENGTH + 1];

	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      username[USER_NAME_LENGTH + 1];
	char      email_address[EMAIL_ADDRESS_LENGTH + 1];

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
		// Send the user/admin password changing result flag
		write_token_into_buffer("user_or_admin_passwd_changing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin password changing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	strcpy(username, row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(new_passwd_with_salt_value, "%s%s", new_passwd, random_salt_value);
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
	generate_ssl_cert(db_conn, user_or_admin_id, username, is_admin_flag, new_passwd, email_address, ssl_cert_priv_key_path, ssl_cert_req_path, enc_ssl_cert_path, 
		full_enc_ssl_cert_path, full_enc_ssl_cert_hash_path);

	// Send new password to the user's e-mail address
	if(send_new_passwd_flag)
	{
		// Lock an e-mail sending
		if(sem_wait(&email_sending_lock_mutex) != 0)
			int_error("Locking the mutex failed");

		if(!send_passwd_to_user_email_address(email_address, username, is_admin_flag, new_passwd))
		{
			// Send the user/admin password changing result flag
			write_token_into_buffer("user_or_admin_passwd_changing_result_flag", "0", true, buffer);
			write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

			// Unlock an e-mail sending
			if(sem_post(&email_sending_lock_mutex) != 0)
				int_error("Unlocking the mutex failed");

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the user/admin password changing result flag failed\n");
				goto ERROR;
			}

			goto ERROR;
		}

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");
	}

	return true;

ERROR:
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;
}

static boolean change_user_passwd_main(SSL *ssl_client, boolean is_admin_flag, char *username)
{
	char          buffer[BUFFER_LENGTH + 1];
	char          token_name[TOKEN_NAME_LENGTH + 1];
	char          new_passwd[PASSWD_LENGTH + 1];
	char          send_new_passwd_flag_str_tmp[FLAG_LENGTH + 1];
	boolean       send_new_passwd_flag;

	MYSQL         *db_conn = NULL;
  	MYSQL_RES     *result  = NULL;
  	MYSQL_ROW     row;
	char          stat[SQL_STATEMENT_LENGTH + 1];
	char	      err_msg[ERR_MSG_LENGTH + 1];
	unsigned long *lengths = NULL;

	unsigned int  user_or_admin_id;

	char          *ssl_cert_data = NULL;
	unsigned long ssl_cert_data_length;
	char          ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];

	// Receive user/admin password changing information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user/admin password changing information failed\n");
		goto ERROR;
	}

	// Get user/admin password changing information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, new_passwd) != READ_TOKEN_SUCCESS || strcmp(token_name, "new_passwd") != 0)
		int_error("Extracting the new_passwd failed");

	if(read_token_from_buffer(buffer, 2, token_name, send_new_passwd_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "send_new_passwd_flag") != 0)
		int_error("Extracting the send_new_passwd_flag failed");

	send_new_passwd_flag = (strcmp(send_new_passwd_flag_str_tmp, "1") == 0) ? true : false;

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
		// Send the user/admin password changing result flag
		write_token_into_buffer("user_or_admin_passwd_changing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin password changing result flag failed\n");
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

	// Change user/admin password
	if(!change_user_passwd(ssl_client, db_conn, is_admin_flag, user_or_admin_id, new_passwd, send_new_passwd_flag, SALTED_PASSWD_HASH_PATH, SSL_CERT_PRIV_KEY_PATH, 
		SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH))
	{
		goto ERROR;
	}

	// Send the user/admin passwd changing result flag
	write_token_into_buffer("user_or_admin_passwd_changing_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user/admin passwd changing result flag failed\n");
		goto ERROR;
	}

	// Heap variable allocation
	ssl_cert_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!ssl_cert_data)
	{
		int_error("Allocating memory for \"ssl_cert_data\" failed");
	}

	// Query the user/admin's SSL certificate
	if(is_admin_flag)
	{
		sprintf(stat, "SELECT enc_ssl_cert, enc_ssl_cert_hash FROM %s WHERE admin_id = %u", ESA__ADMINS, user_or_admin_id);
	}
	else
	{
		sprintf(stat, "SELECT enc_ssl_cert, enc_ssl_cert_hash FROM %s WHERE user_id = %u", ESA__USERS, user_or_admin_id);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);
	if(!row)
		int_error("Getting the user/admin's SSL certificate from the database failed");

	lengths = mysql_fetch_lengths(result);

	memcpy(ssl_cert_data, row[0], lengths[0]);
	strcpy(ssl_cert_hash, row[1]);

	ssl_cert_data_length = lengths[0];

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	
	disconnect_db(&db_conn);

	// Send the user/admin's SSL certificate and its hash value
	if(!SSL_send_buffer(ssl_client, ssl_cert_data, ssl_cert_data_length))
	{
		fprintf(stderr, "Sending the SSL certificate failed\n");
		goto ERROR;
	}

	if(!SSL_send_buffer(ssl_client, ssl_cert_hash, strlen(ssl_cert_hash)))
	{
		fprintf(stderr, "Sending the SSL certificate failed\n");
		goto ERROR;
	}

	if(ssl_cert_data)
	{
		free(ssl_cert_data);
		ssl_cert_data = NULL;
	}

	return true;

ERROR:

	if(ssl_cert_data)
	{
		free(ssl_cert_data);
		ssl_cert_data = NULL;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean change_user_email_address(SSL *ssl_client, boolean is_admin_flag, char *username)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_or_admin_id;

	// Receive user/admin email address changing information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user/admin email address changing information failed\n");
		goto ERROR;
	}

	// Get a user/admin email address changing information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
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
		// Send the user/admin email address changing result flag
		write_token_into_buffer("user_or_admin_email_address_changing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin email address changing result flag failed\n");
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
	
	// Send the user/admin email address changing result flag
	write_token_into_buffer("user_or_admin_email_address_changing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user/admin email address changing result flag failed\n");
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
	entity_type user_or_admin_type;
	char        cert_ownername[USER_NAME_LENGTH + 1];
	
	char        buffer[BUFFER_LENGTH + 1];
	char        token_name[TOKEN_NAME_LENGTH + 1];
	char        request[REQUEST_TYPE_LENGTH + 1];

	// Get certificate's ownername and entity type
	get_cert_ownername(ssl_client, GLOBAL_authority_name, cert_ownername, &user_or_admin_type);
	
	// Receive request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request information failed\n");
		goto ERROR;
	}

	// Get a request information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(user_or_admin_type == user)
	{
		if(strcmp(request, PASSWD_CHANGING) == 0)
		{
			return change_user_passwd_main(ssl_client, false, cert_ownername);
		}
		else if(strcmp(request, EMAIL_ADDRESS_CHANGING) == 0)
		{
			return change_user_email_address(ssl_client, false, cert_ownername);		
		}
		else
		{
			fprintf(stderr, "Invalid request type\n");
			goto ERROR;
		}
	}
	else if(user_or_admin_type == admin)
	{
		if(strcmp(request, PASSWD_CHANGING) == 0)
		{
			return change_user_passwd_main(ssl_client, true, cert_ownername);
		}
		else if(strcmp(request, EMAIL_ADDRESS_CHANGING) == 0)
		{
			return change_user_email_address(ssl_client, true, cert_ownername);	
		}
		else
		{
			fprintf(stderr, "Invalid request type\n");
			goto ERROR;
		}
	}
	else
	{
		fprintf(stderr, "Invalid certificate's entity type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *user_info_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[2];

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_USER_INFO_MANAGEMENT_PORT);
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
		hosts[1] = USER_CN;
    		if((err = post_connection_check(ssl_client, hosts, 2, true, GLOBAL_authority_name)) != X509_V_OK)
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



