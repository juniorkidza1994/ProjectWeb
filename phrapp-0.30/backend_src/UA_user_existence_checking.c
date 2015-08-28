#include "UA_common.h"

// Local Function Prototype
static boolean check_user_existence(SSL *ssl_client);

// Implementation
static boolean check_user_existence(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];
	
	// Receive user existence checking information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user existence checking information failed\n");
		goto ERROR;
	}

	// Get user existence checking information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		int_error("Extracting the authority_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	if(strcmp(authority_name, GLOBAL_authority_name) == 0)
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	}
	else
	{
		sprintf(stat, "SELECT UOA.user_id FROM %s UOA, %s AUT WHERE UOA.username LIKE '%s' COLLATE latin1_general_cs AND "
			"UOA.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", 
			UA__USERS_IN_OTHER_AUTHORITIES, UA__AUTHORITIES, username, authority_name);
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
		// Send the user existence checking result flag
		write_token_into_buffer("user_existence_checking_result_flag", "1", true, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user existence checking result flag failed\n");
			goto ERROR;
		}
	}
	else
	{
		// Send the user existence checking result flag
		write_token_into_buffer("user_existence_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the user that your're looking for", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user existence checking result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
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

void *user_existence_checking_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[2];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_USER_EXISTENCE_CHECKING_PORT);
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
		hosts[1] = EMERGENCY_SERVER_CN;
    		if((err = post_connection_check(ssl_client, hosts, 2, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Check user existence
		if(!check_user_existence(ssl_client))
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



