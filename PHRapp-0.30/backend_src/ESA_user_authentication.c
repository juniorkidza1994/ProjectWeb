#include "ESA_common.h"

#define VERIFICATION_INFO_CIPHERTEXT_PATH   "ESA_cache/ESA_user_authentication.verification_info_ciphertext"
#define VERIFICATION_INFO_PLAINTEXT_PATH    "ESA_cache/ESA_user_authentication.verification_info_plaintext"
#define VERIFICATION_RESULT_CIPHERTEXT_PATH "ESA_cache/ESA_user_authentication.verification_result_ciphertext"
#define VERIFICATION_RESULT_PLAINTEXT_PATH  "ESA_cache/ESA_user_authentication.verification_result_plaintext"

#define SALTED_PASSWD_HASH_PATH      	    "ESA_cache/ESA_user_authentication.salted_passwd_hash"

#define SSL_CERT_PLAINTEXT_PATH             "ESA_cache/ESA_user_authentication.ssl_cert_plaintext"
#define SSL_CERT_CIPHERTEXT_PATH            "ESA_cache/ESA_user_authentication.ssl_cert_ciphertext"

#define SSL_CERT_HASH_PLAINTEXT_PATH        "ESA_cache/ESA_user_authentication.ssl_cert_hash_plaintext"
#define SSL_CERT_HASH_CIPHERTEXT_PATH       "ESA_cache/ESA_user_authentication.ssl_cert_hash_ciphertext"

// Local Function Prototypes
static boolean verify_authentication_request(BIO *bio_client, char *username_ret, boolean *is_admin_flag_ret, char *key_exchange_passwd_ret);
static boolean ssl_cert_response(BIO *bio_client, char *username, boolean is_admin_flag, char *key_exchange_passwd);
static boolean verify_cert_owner(SSL *ssl_client, char *username, boolean is_admin_flag);
static void load_user_basic_info(char *username, boolean is_admin_flag, char *email_address_ret);
static boolean basic_info_response(SSL *ssl_client, char *username, boolean is_admin_flag);

// Implementation
static boolean verify_authentication_request(BIO *bio_client, char *username_ret, boolean *is_admin_flag_ret, char *key_exchange_passwd_ret)
{
	boolean   verification_flag;

	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      is_admin_flag_str_tmp[FLAG_LENGTH + 1];   // "0" or "1"
	char      passwd[PASSWD_LENGTH + 1];
	char      salted_passwd_hash_cmp[SHA1_DIGEST_LENGTH + 1];
	char      salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];
	char      salt_value[SALT_VALUE_LENGTH + 1];
	char      passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];

	// Receive the verification information
	if(!BIO_recv_file(bio_client, VERIFICATION_INFO_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Receiving verification information failed\n");
		goto ERROR;
	}

	// Decrypt the verification information with the Emergency Staff Authority's private key
	if(!smime_decrypt_with_cert(VERIFICATION_INFO_CIPHERTEXT_PATH, VERIFICATION_INFO_PLAINTEXT_PATH, ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, err_msg))
	{
		fprintf(stderr, "Decrypting verification information failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(VERIFICATION_INFO_CIPHERTEXT_PATH);

	// Get the verification information from file
	if(read_token_from_file(VERIFICATION_INFO_PLAINTEXT_PATH, 1, token_name, is_admin_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "is_admin_flag") != 0)
	{
		int_error("Extracting the is_admin_flag failed");
	}

	*is_admin_flag_ret = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false; 

	if(read_token_from_file(VERIFICATION_INFO_PLAINTEXT_PATH, 2, token_name, username_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
	{
		int_error("Extracting the username failed");
	}

	if(read_token_from_file(VERIFICATION_INFO_PLAINTEXT_PATH, 3, token_name, passwd) != READ_TOKEN_SUCCESS || strcmp(token_name, "passwd") != 0)
	{
		int_error("Extracting the passwd failed");
	}

	if(read_token_from_file(VERIFICATION_INFO_PLAINTEXT_PATH, 4, token_name, key_exchange_passwd_ret) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "key_exchange_passwd") != 0)
	{
		int_error("Extracting the key_exchange_passwd failed");
	}

	unlink(VERIFICATION_INFO_PLAINTEXT_PATH);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Verify the user
	sprintf(stat, "SELECT salted_passwd_hash, salt_value FROM %s WHERE username LIKE '%s' "
		"COLLATE latin1_general_cs", (*is_admin_flag_ret) ? ESA__ADMINS : ESA__USERS, username_ret);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	if(row)
	{
		strcpy(salted_passwd_hash_cmp, row[0]);
		strcpy(salt_value, row[1]);

		// Get the salted password hash
		sprintf(passwd_with_salt_value, "%s%s", passwd, salt_value);
		sum_sha1_from_string(passwd_with_salt_value, strlen(passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

		if(strcmp(salted_passwd_hash, salted_passwd_hash_cmp) == 0)   // Authentication succeed
		{
			verification_flag = true;
			if(!write_token_into_file("verification_result_flag", "1", true, VERIFICATION_RESULT_PLAINTEXT_PATH))
				int_error("Writing the verification_result_flag failed");
		}
		else   // Authentication failed
		{
			verification_flag = false;
			if(!write_token_into_file("verification_result_flag", "0", true, VERIFICATION_RESULT_PLAINTEXT_PATH))
				int_error("Writing the verification_result_flag failed");

			if(!write_token_into_file("error_msg", "Invalid username or password", false, VERIFICATION_RESULT_PLAINTEXT_PATH))
				int_error("Writing the error_msg failed");
		}
	}
	else      // Authentication failed
	{
		verification_flag = false;
		if(!write_token_into_file("verification_result_flag", "0", true, VERIFICATION_RESULT_PLAINTEXT_PATH))
			int_error("Writing the verification_result_flag failed");

		if(!write_token_into_file("error_msg", "Invalid username or password", false, VERIFICATION_RESULT_PLAINTEXT_PATH))
				int_error("Writing the error_msg failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Encrypt the verification result with random session password
	if(!des3_encrypt(VERIFICATION_RESULT_PLAINTEXT_PATH, VERIFICATION_RESULT_CIPHERTEXT_PATH, key_exchange_passwd_ret, err_msg))
	{
		fprintf(stderr, "Encrypting the verification result failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(VERIFICATION_RESULT_PLAINTEXT_PATH);

	// Send the verification result
	if(!BIO_send_file(bio_client, VERIFICATION_RESULT_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Sending the verification result failed");
		goto ERROR;
	}

	unlink(VERIFICATION_RESULT_CIPHERTEXT_PATH);
	return verification_flag;

ERROR:
	unlink(VERIFICATION_INFO_CIPHERTEXT_PATH);
	unlink(VERIFICATION_INFO_PLAINTEXT_PATH);
	unlink(VERIFICATION_RESULT_PLAINTEXT_PATH);
	unlink(VERIFICATION_RESULT_CIPHERTEXT_PATH);
	return false;
}

static boolean ssl_cert_response(BIO *bio_client, char *username, boolean is_admin_flag, char *key_exchange_passwd)
{
	char          *ssl_cert_data = NULL;
	unsigned long ssl_cert_data_length;
	char          ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];

	MYSQL         *db_conn = NULL;
  	MYSQL_RES     *result  = NULL;
  	MYSQL_ROW     row;
	char          stat[SQL_STATEMENT_LENGTH + 1];
	char	      err_msg[ERR_MSG_LENGTH + 1];
	unsigned long *lengths = NULL;

	ssl_cert_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!ssl_cert_data)
	{
		int_error("Allocating memory for \"ssl_cert_data\" failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the user's SSL certificate and write it to buffer
	sprintf(stat, "SELECT enc_ssl_cert, enc_ssl_cert_hash FROM %s WHERE username LIKE '%s' "
		"COLLATE latin1_general_cs", (is_admin_flag) ? ESA__ADMINS : ESA__USERS, username);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);
	if(!row)
		int_error("Getting an SSL certificate from the database failed");

	lengths = mysql_fetch_lengths(result);
	ssl_cert_data_length = lengths[0];

	memcpy(ssl_cert_data, row[0], ssl_cert_data_length);
	strcpy(ssl_cert_hash, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Write the SSL ceertificate to file and encrypt it with random session password before sending it to the user
	if(!write_bin_file(SSL_CERT_PLAINTEXT_PATH, "wb", ssl_cert_data, ssl_cert_data_length))
	{
		fprintf(stderr, "Writing the SSL certificate hash failed");
		goto ERROR;
	}

	if(!des3_encrypt(SSL_CERT_PLAINTEXT_PATH, SSL_CERT_CIPHERTEXT_PATH, key_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the SSL certificate failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(SSL_CERT_PLAINTEXT_PATH);

	// Send the user's SSL certificate
	if(!BIO_send_file(bio_client, SSL_CERT_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Sending the SSL certificate failed\n");
		goto ERROR;
	}

	unlink(SSL_CERT_CIPHERTEXT_PATH);

	// Write hash value to file and encrypt it with random session password before sending it to the user
	if(!write_bin_file(SSL_CERT_HASH_PLAINTEXT_PATH, "wb", ssl_cert_hash, SHA1_DIGEST_LENGTH))
	{
		fprintf(stderr, "Writing the SSL certificate hash failed");
		goto ERROR;
	}

	if(!des3_encrypt(SSL_CERT_HASH_PLAINTEXT_PATH, SSL_CERT_HASH_CIPHERTEXT_PATH, key_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the SSL certificate hash failed\n\"%s\"\n", err_msg);
		goto ERROR;
	}

	unlink(SSL_CERT_HASH_PLAINTEXT_PATH);

	// Send the user's SSL certificate hash
	if(!BIO_send_file(bio_client, SSL_CERT_HASH_CIPHERTEXT_PATH))
	{
		fprintf(stderr, "Sending the SSL certificate hash failed\n");
		goto ERROR;
	}

	unlink(SSL_CERT_HASH_CIPHERTEXT_PATH);

	if(ssl_cert_data)
	{
		free(ssl_cert_data);
		ssl_cert_data = NULL;
	}

	return true;

ERROR:
	unlink(SSL_CERT_PLAINTEXT_PATH);
	unlink(SSL_CERT_CIPHERTEXT_PATH);
	unlink(SSL_CERT_HASH_PLAINTEXT_PATH);
	unlink(SSL_CERT_HASH_CIPHERTEXT_PATH);

	if(ssl_cert_data)
	{
		free(ssl_cert_data);
		ssl_cert_data = NULL;
	}

	return false;
}

static boolean verify_cert_owner(SSL *ssl_client, char *username, boolean is_admin_flag)
{
	entity_type cert_owner_type;
	char        cert_ownername[USER_NAME_LENGTH + 1];

	// Get a certificate owner's name and user type
	get_cert_ownername(ssl_client, GLOBAL_authority_name, cert_ownername, &cert_owner_type);

	// Verify the cert owner type (either normal user or admin)
	if((is_admin_flag && cert_owner_type != admin) || (!is_admin_flag && cert_owner_type != user))
	{
		fprintf(stderr, "Verifying the certificate owner type failed\n");
		return false;
	}

	// Verify the certificate ownername
	if(strcmp(cert_ownername, username) != 0)
	{
		fprintf(stderr, "Verifying the certificate ownername failed\n");
		return false;
	}

	return true;
}

static void load_user_basic_info(char *username, boolean is_admin_flag, char *email_address_ret)
{
	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the user's e-mail address
	sprintf(stat, "SELECT email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", (is_admin_flag) ? ESA__ADMINS : ESA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);
	if(!row)
		int_error("Getting user basic information from the database failed");

	strcpy(email_address_ret, row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
}

static boolean basic_info_response(SSL *ssl_client, char *username, boolean is_admin_flag)
{
	char email_address[EMAIL_ADDRESS_LENGTH + 1];
	char buffer[BUFFER_LENGTH + 1];

	// Load user's e-mail address from database
	load_user_basic_info(username, is_admin_flag, email_address);

	// Send basic information
	write_token_into_buffer("email_address", email_address, true, buffer);
	write_token_into_buffer("authority_name", GLOBAL_authority_name, false, buffer);

	if(is_admin_flag)
	{
		write_token_into_buffer("mail_server_url", GLOBAL_mail_server_url, false, buffer);
		write_token_into_buffer("authority_email_address", GLOBAL_authority_email_address, false, buffer);
		write_token_into_buffer("authority_email_passwd", GLOBAL_authority_email_passwd, false, buffer);
	}

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the basic information failed\n");
		return false;
	}

	return true;
}

void *user_authentication_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	char    username[USER_NAME_LENGTH + 1];
	char    key_exchange_passwd[PASSWD_LENGTH + 1];
	boolean is_admin_flag;

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_USER_AUTHENTICATION_PORT);
    	if(!bio_acc)
        	int_error("Creating server socket failed");
  
    	if(BIO_do_accept(bio_acc) <= 0)
        	int_error("Binding server socket failed");
  
    	for(;;)
    	{
        	if(BIO_do_accept(bio_acc) <= 0)
            		int_error("Accepting connection failed");
 
        	bio_client = BIO_pop(bio_acc);

		// Verify the user
		if(verify_authentication_request(bio_client, username, &is_admin_flag, key_exchange_passwd))
		{
			int  err;
			char *hosts[1];

			// SSL certificate response
			if(!ssl_cert_response(bio_client, username, is_admin_flag, key_exchange_passwd))
				goto ERROR_AT_BIO_LAYER;

        		if(!(ssl_client = SSL_new(ctx)))
            			int_error("Creating SSL context failed");

        		SSL_set_bio(ssl_client, bio_client, bio_client);
			if(SSL_accept(ssl_client) <= 0)
			{
        			fprintf(stderr, "Accepting SSL connection failed\n");
				goto ERROR_AT_SSL_LAYER;
			}

			hosts[0] = is_admin_flag ? ADMIN_CN : USER_CN; 
    			if((err = post_connection_check(ssl_client, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    			{
        			fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        			goto ERROR_AT_SSL_LAYER;
    			}

			// Verify the certificate owner
			if(!verify_cert_owner(ssl_client, username, is_admin_flag))
				goto ERROR_AT_SSL_LAYER;

			// Basic information response
			if(!basic_info_response(ssl_client, username, is_admin_flag))
				goto ERROR_AT_SSL_LAYER;

ERROR_AT_SSL_LAYER:

			SSL_cleanup(ssl_client);
			ssl_client = NULL;
    			ERR_remove_state(0);
			continue;

ERROR_AT_BIO_LAYER:

			BIO_free(bio_client);
			bio_client = NULL;
			ERR_remove_state(0);
		}
		else
		{
			fprintf(stderr, "Incorrect the verification information\n");

			BIO_free(bio_client);
			bio_client = NULL;
		}
    	}
    
    	SSL_CTX_free(ctx);
	ctx = NULL;

    	BIO_free(bio_acc);
	bio_acc = NULL;

	pthread_exit(NULL);
    	return NULL;
}



