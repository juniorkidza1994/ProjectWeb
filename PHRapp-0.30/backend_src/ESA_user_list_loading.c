#include "ESA_common.h"

// Local Function Prototypes
static boolean load_user_list(SSL *ssl_client, boolean is_admin_flag);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean load_user_list(SSL *ssl_client, boolean is_admin_flag)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	if(is_admin_flag)
	{
		char username[USER_NAME_LENGTH + 1];

		// Get certificate owner's name
		get_cert_ownername(ssl_client, GLOBAL_authority_name, username, NULL);

		// Query for all admins except the requestor
		sprintf(stat, "SELECT username, email_address FROM %s WHERE username NOT LIKE '%s' COLLATE latin1_general_cs", ESA__ADMINS, username);
	}
	else
	{
		// Query for all users
		sprintf(stat, "SELECT username, email_address FROM %s", ESA__USERS);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the user/admin information
		write_token_into_buffer("is_end_of_user_or_admin_list_flag", "0", true, buffer);
		write_token_into_buffer("username", row[0], false, buffer);
		write_token_into_buffer("email_address", row[1], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/admin information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of user/admin list
	write_token_into_buffer("is_end_of_user_or_admin_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of user/admin list failed\n");
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
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    load_admin_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean load_admin_list_flag;

	// Receive user loading information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user loading information failed\n");
		goto ERROR;
	}

	// Get a user loading information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, load_admin_list_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "load_admin_list_flag") != 0)
	{
		int_error("Extracting the use load_admin_list_flag failed");
	}

	load_admin_list_flag = (strcmp(load_admin_list_flag_str_tmp, "1") == 0) ? true : false;

	// Load user/admin list
	return load_user_list(ssl_client, load_admin_list_flag);

ERROR:

	return false;
}

void *user_list_loading_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_USER_LIST_LOADING_PORT);
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

		host[0] = ADMIN_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process request
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



