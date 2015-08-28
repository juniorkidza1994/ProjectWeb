#include "EmS_common.h"

// Local Function Prototypes
static void get_username(MYSQL *db_conn, unsigned int user_id, char *username_ret);
static boolean synchronize_peer_phr_owner_list(MYSQL *db_conn, SSL *ssl_client, char *peer_authority_name);
static boolean synchronize_peer_trusted_user_list(MYSQL *db_conn, SSL *ssl_client, char *peer_authority_name);
static boolean process_synchronization(SSL *ssl_client);

// Implementation
static void get_username(MYSQL *db_conn, unsigned int user_id, char *username_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the username
	sprintf(stat, "SELECT username FROM %s WHERE user_id=%u", EMS__USERS, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		int_error("Getting the username failed");
	}

	strcpy(username_ret, row[0]);
	
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean synchronize_peer_phr_owner_list(MYSQL *db_conn, SSL *ssl_client, char *peer_authority_name)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int trusted_user_id;
	unsigned int phr_owner_id;

	char         trusted_username[USER_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];

	char         buffer[BUFFER_LENGTH + 1];

	// Query for the delegation rows that have the trusted user belonged to the desired authority (ignore if the rejection_by_trusted_user_flag = '0')
	sprintf(stat, "SELECT DGT.trusted_user_id, DGT.phr_owner_id FROM %s DGT, %s USR, %s AUT WHERE DGT.trusted_user_id = USR.user_id AND "
		"USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DGT.rejection_by_trusted_user_flag = '0'", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, peer_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		trusted_user_id = atoi(row[0]);
		phr_owner_id    = atoi(row[1]);

		// Get usernames
		get_username(db_conn, trusted_user_id, trusted_username);
		get_username(db_conn, phr_owner_id, phr_ownername);

		// Send the delegation information
		write_token_into_buffer("is_end_of_peer_phr_owner_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);
		write_token_into_buffer("trusted_username", trusted_username, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the delegation information failed\n");
			goto ERROR;
		}
	}

	// Send the is_end_of_peer_phr_owner_list_flag
	write_token_into_buffer("is_end_of_peer_phr_owner_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_peer_phr_owner_list_flag failed\n");
		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

static boolean synchronize_peer_trusted_user_list(MYSQL *db_conn, SSL *ssl_client, char *peer_authority_name)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int delegation_id;
	unsigned int trusted_user_id;
	unsigned int phr_owner_id;

	boolean      rejection_by_trusted_user_flag;

	char         trusted_username[USER_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];

	char         buffer[BUFFER_LENGTH + 1];

	// Query for the delegation rows that have the PHR owner belonged to the desired authority
	sprintf(stat, "SELECT DGT.delegation_id, DGT.trusted_user_id, DGT.phr_owner_id, DGT.rejection_by_trusted_user_flag FROM %s DGT, %s USR, %s AUT WHERE "
		"DGT.phr_owner_id = USR.user_id AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, peer_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		delegation_id   = atoi(row[0]);
		trusted_user_id = atoi(row[1]);
		phr_owner_id    = atoi(row[2]);
		rejection_by_trusted_user_flag = (strcmp(row[3], "1") == 0) ? true : false;

		// Get usernames
		get_username(db_conn, trusted_user_id, trusted_username);
		get_username(db_conn, phr_owner_id, phr_ownername);

		// Send the delegation information
		write_token_into_buffer("is_end_of_peer_trusted_user_list_flag", "0", true, buffer);
		write_token_into_buffer("trusted_username", trusted_username, false, buffer);
		write_token_into_buffer("rejection_by_trusted_user_flag", (rejection_by_trusted_user_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the delegation information failed\n");
			goto ERROR;
		}

		// If the rejection_by_trusted_user_flag is set then delete the delegation from the database
		if(rejection_by_trusted_user_flag)
		{
			// Delete the delegation from the database
			sprintf(stat, "DELETE FROM %s WHERE delegation_id = %u", EMS__DELEGATIONS, delegation_id);
			if(mysql_query(db_conn, stat))
			{
				sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
				int_error(err_msg);
			}
		}
	}

	// Send the is_end_of_peer_trusted_user_list_flag
	write_token_into_buffer("is_end_of_peer_trusted_user_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_peer_trusted_user_list_flag failed\n");
		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

static boolean process_synchronization(SSL *ssl_client)
{
	MYSQL *db_conn = NULL;
	char  buffer[BUFFER_LENGTH + 1];
	char  token_name[TOKEN_NAME_LENGTH + 1];
	char  peer_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Receive peer authority name
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving peer authority name failed\n");
		goto ERROR;
	}

	// Get a peer authority name token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, peer_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "peer_authority_name") != 0)
	{
		int_error("Extracting the peer_authority_name failed");
	}

	// Peer PHR owner list
	if(!synchronize_peer_phr_owner_list(db_conn, ssl_client, peer_authority_name))
		goto ERROR;

	// Peer trusted user list
	if(!synchronize_peer_trusted_user_list(db_conn, ssl_client, peer_authority_name))
		goto ERROR;

	disconnect_db(&db_conn);
	return true;

ERROR:

	disconnect_db(&db_conn);
	return false;
}

void *synchronization_responding_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_DELEGATION_SYNCHRONIZATION_RESPONDING_PORT);
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

		host[0] = USER_AUTH_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process Synchronization
		if(!process_synchronization(ssl_client))
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



