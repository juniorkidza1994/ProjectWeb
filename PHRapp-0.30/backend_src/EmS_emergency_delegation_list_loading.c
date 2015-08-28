#include "EmS_common.h"

// Local Function Prototypes
static void get_user_information(MYSQL *db_conn, unsigned int trusted_user_id, char *trusted_username_ret, char *trusted_user_authority_name_ret);

// A PHR owner is assumed to be in current authority but a trusted user can be in another authority
static boolean load_emergency_trusted_user_list(SSL *ssl_client);

// A trusted user is assumed to be in current authority but a PHR owner can be in another authority
static boolean load_emergency_phr_owner_list(SSL *ssl_client);

static boolean process_request(SSL *ssl_client);

// Implementation
static void get_user_information(MYSQL *db_conn, unsigned int user_id, char *username_ret, char *user_authority_name_ret)
{
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query the user infomation
	sprintf(stat, "SELECT USR.username, AUT.authority_name FROM %s USR, %s AUT WHERE USR.user_id = %u "
		"AND USR.authority_id = AUT.authority_id", EMS__USERS, EMS__AUTHORITIES, user_id);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
		int_error("Getting the user information from database failed");

	strcpy(username_ret, row[0]);
	strcpy(user_authority_name_ret, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

// A PHR owner is assumed to be in current authority but a trusted user can be in another authority
static boolean load_emergency_trusted_user_list(SSL *ssl_client)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int trusted_user_id;
	char         trusted_username[USER_NAME_LENGTH + 1];
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the emergency trusted user list of the requestor
	sprintf(stat, "SELECT DGT.trusted_user_id FROM %s DGT, %s USR WHERE DGT.phr_owner_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs "
		"AND USR.authority_id = %u AND DGT.rejection_by_trusted_user_flag = '0'", EMS__DELEGATIONS, EMS__USERS, phr_owner_name, GLOBAL_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		trusted_user_id = atoi(row[0]);
		get_user_information(db_conn, trusted_user_id, trusted_username, trusted_user_authority_name);

		// Send the emergency trusted user information
		write_token_into_buffer("is_end_of_emergency_trusted_user_list_flag", "0", true, buffer);
		write_token_into_buffer("trusted_username", trusted_username, false, buffer);
		write_token_into_buffer("trusted_user_authority_name", trusted_user_authority_name, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency trusted user information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of emergency trusted user list
	write_token_into_buffer("is_end_of_emergency_trusted_user_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of emergency trusted user list failed\n");
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

// A trusted user is assumed to be in current authority but a PHR owner can be in another authority
static boolean load_emergency_phr_owner_list(SSL *ssl_client)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         trusted_username[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;
	char         phr_owner_name[USER_NAME_LENGTH + 1];
	char         phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Get certificate trusted user's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, trusted_username, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the emergency PHR owner list
	sprintf(stat, "SELECT DGT.phr_owner_id FROM %s DGT, %s USR WHERE DGT.trusted_user_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs "
		"AND USR.authority_id = %u AND DGT.rejection_by_trusted_user_flag='0'", EMS__DELEGATIONS, EMS__USERS, trusted_username, GLOBAL_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		phr_owner_id = atoi(row[0]);
		get_user_information(db_conn, phr_owner_id, phr_owner_name, phr_owner_authority_name);

		// Send the emergency PHR owner information
		write_token_into_buffer("is_end_of_emergency_phr_owner_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_owner_name", phr_owner_name, false, buffer);
		write_token_into_buffer("phr_owner_authority_name", phr_owner_authority_name, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency PHR owner information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of emergency PHR owner list
	write_token_into_buffer("is_end_of_emergency_phr_owner_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of emergency PHR owner list failed\n");
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
	char request_type[REQUEST_TYPE_LENGTH + 1];

	// Receive request type information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request type information failed\n");
		goto ERROR;
	}

	// Get a request type information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request_type) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_type") != 0)
	{
		int_error("Extracting the request_type failed");
	}

	if(strcmp(request_type, EMERGENCY_TRUSTED_USER_LIST_LOADING) == 0)
	{
		return load_emergency_trusted_user_list(ssl_client);
	}
	else if(strcmp(request_type, EMERGENCY_PHR_OWNER_LIST_LOADING) == 0)
	{
		return load_emergency_phr_owner_list(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *emergency_delegation_list_loading_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_EMERGENCY_DELEGATION_LIST_LOADING_PORT);
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

		host[0] = USER_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process types of request
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



