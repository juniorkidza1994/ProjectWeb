#include "UA_common.h"

#define EMERGENCY_CPABE_PRIV_KEY_PATH "UA_cache/UA_emergency_key_management.emergency_cpabe_priv_key"

// Local Function Prototypes
static boolean respond_emergency_key(SSL *ssl_client);
static boolean respond_emergency_trusted_user_pub_key(SSL *ssl_client, char *username, char *authority_name);
static boolean respond_emergency_trusted_user_pub_key_list(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean respond_emergency_key(SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];
	char emergency_key_attribute[ATTRIBUTE_NAME_LENGTH + 1];

	char keygen_cmd[BUFFER_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Receive emergency key attribute information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving emergency key attribute information failed\n");
		goto ERROR;
	}

	// Get an emergency key attribute information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, emergency_key_attribute) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_key_attribute") != 0)
		int_error("Extracting the emergency_key_attribute failed");

	// Make a CP-ABE private key generation command
	sprintf(keygen_cmd, "%s -o %s %s %s 'SpecialNode__SUB__%s__SUB__unique_emergency_key_%s'", CPABE_KEYGEN_PATH, EMERGENCY_CPABE_PRIV_KEY_PATH, 
		CPABE_PUB_KEY_PATH, CPABE_MASTER_KEY_PATH, GLOBAL_authority_name, emergency_key_attribute);

	// Generate an emergency CP-ABE private key
	exec_cmd(keygen_cmd, strlen(keygen_cmd), err_msg, sizeof(err_msg));
	if(strcmp(err_msg, "") != 0)
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an emergency CP-ABE private key failed");
	}

	// Send the emergency CP-ABE private key from file
	if(!SSL_send_file(ssl_client, EMERGENCY_CPABE_PRIV_KEY_PATH))
	{
		fprintf(stderr, "Sending the emergency CP-ABE private key failed\n");
		goto ERROR;
	}

	unlink(EMERGENCY_CPABE_PRIV_KEY_PATH);
	return true;

ERROR:

	unlink(EMERGENCY_CPABE_PRIV_KEY_PATH);
	return false;
}

static boolean respond_emergency_trusted_user_pub_key(SSL *ssl_client, char *username, char *authority_name)
{
	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];
	char      ssl_pub_key_data[SSL_PUB_KEY_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the emergency trusted user's public key
	if(strcmp(authority_name, GLOBAL_authority_name) == 0)  // Current authority
	{
		sprintf(stat, "SELECT ssl_pub_key FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	}
	else  // Another authority
	{
		sprintf(stat, "SELECT UOA.ssl_pub_key FROM %s UOA, %s AUT WHERE UOA.username LIKE '%s' COLLATE latin1_general_cs "
			"AND UOA.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", 
			UA__USERS_IN_OTHER_AUTHORITIES, UA__AUTHORITIES, username, authority_name);
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
		// Send the user's public key requesting result
		write_token_into_buffer("user_pub_key_requesting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the emergency trusted user", false, buffer);
		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user_pub_key_requesting_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the user's public key requesting result
	write_token_into_buffer("user_pub_key_requesting_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user_pub_key_requesting_result_flag failed\n");
		goto ERROR;
	}

	strcpy(ssl_pub_key_data, row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the user's public key
	if(!SSL_send_buffer(ssl_client, ssl_pub_key_data, strlen(ssl_pub_key_data)))
	{
		fprintf(stderr, "Sending the emergency trusted user's public key failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

static boolean respond_emergency_trusted_user_pub_key_list(SSL *ssl_client)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    is_end_of_user_pub_key_requesting_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_user_pub_key_requesting_flag;
	char    username[USER_NAME_LENGTH + 1];
	char    authority_name[AUTHORITY_NAME_LENGTH + 1];

	while(1)
	{
		// Receive the user's public key requesting information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving attribute list loading information failed\n");
			goto ERROR;
		}

		// Get the user's public key requesting information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_user_pub_key_requesting_flag_str_tmp) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "is_end_of_user_pub_key_requesting_flag") != 0)
		{
			int_error("Extracting the is_end_of_user_pub_key_requesting_flag failed");
		}

		is_end_of_user_pub_key_requesting_flag = (strcmp(is_end_of_user_pub_key_requesting_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_user_pub_key_requesting_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		{
			int_error("Extracting the username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		{
			int_error("Extracting the authority_name failed");
		}

		if(!respond_emergency_trusted_user_pub_key(ssl_client, username, authority_name))
			goto ERROR;
	}

	return true;

ERROR:

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

	if(strcmp(request, EMERGENCY_KEY_GENERATING) == 0)
	{
		return respond_emergency_key(ssl_client);
	}
	else if(strcmp(request, EMERGENCY_TRUSTED_USER_PUB_KEY_LIST_REQUESTING) == 0)
	{
		return respond_emergency_trusted_user_pub_key_list(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *emergency_key_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_EMERGENCY_KEY_MANAGEMENT_PORT);
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

		hosts[0] = USER_CN;
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



