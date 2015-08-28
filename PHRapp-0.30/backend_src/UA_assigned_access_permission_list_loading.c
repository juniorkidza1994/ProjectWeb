#include "UA_common.h"

// Local Function Prototypes
static void get_assigned_user_information(MYSQL *db_conn, unsigned int assigned_user_id, unsigned int assigned_user_authority_id, 
	char *assigned_username_ret, char *assigned_user_authority_name_ret);

static boolean load_assigned_access_permission_list(SSL *ssl_client);

// Implementation
static void get_assigned_user_information(MYSQL *db_conn, unsigned int assigned_user_id, unsigned int assigned_user_authority_id, 
	char *assigned_username_ret, char *assigned_user_authority_name_ret)
{
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	if(assigned_user_authority_id == GLOBAL_authority_id)
	{
		// Query the assigned username
		sprintf(stat, "SELECT username FROM %s WHERE user_id = %u", UA__USERS, assigned_user_id);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
		row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting the assigned username from database failed");

		strcpy(assigned_username_ret, row[0]);
		strcpy(assigned_user_authority_name_ret, GLOBAL_authority_name);
	}
	else
	{
		// Query the assigned username and assigned user authority name
		sprintf(stat, "SELECT UOA.username, AUT.authority_name FROM %s UOA, %s AUT WHERE UOA.user_id = %u AND "
			"UOA.authority_id = AUT.authority_id AND UOA.authority_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, 
			UA__AUTHORITIES, assigned_user_id, assigned_user_authority_id);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
		row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting the assigned username and assigned user authority name from database failed");

		strcpy(assigned_username_ret, row[0]);
		strcpy(assigned_user_authority_name_ret, row[1]);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean load_assigned_access_permission_list(SSL *ssl_client)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int assigned_user_id;
	unsigned int assigned_user_authority_id;
	char         assigned_username[USER_NAME_LENGTH + 1];
	char         assigned_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the assigned access permission list of the requestor
	sprintf(stat, "SELECT PAO.object_user_id, PAO.object_user_authority_id, PAO.upload_permission_flag, PAO.download_permission_flag, "
		"PAO.delete_permission_flag FROM %s PAO, %s USR WHERE PAO.user_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs", 
		UA__PERMISSIONS_ASSIGNED_TO_OTHERS, UA__USERS, phr_owner_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		assigned_user_id           = atoi(row[0]);
		assigned_user_authority_id = atoi(row[1]);
		get_assigned_user_information(db_conn, assigned_user_id, assigned_user_authority_id, assigned_username, assigned_user_authority_name);

		// Send the assigned access permission information
		write_token_into_buffer("is_end_of_assigned_access_permission_list_flag", "0", true, buffer);
		write_token_into_buffer("assigned_username", assigned_username, false, buffer);
		write_token_into_buffer("assigned_user_authority_name", assigned_user_authority_name, false, buffer);
		write_token_into_buffer("upload_permission_flag", row[2], false, buffer);
		write_token_into_buffer("download_permission_flag", row[3], false, buffer);
		write_token_into_buffer("delete_permission_flag", row[4], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the assigned access permission information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of assigned access permission list
	write_token_into_buffer("is_end_of_assigned_access_permission_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of assigned access permission list failed\n");
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

void *assigned_access_permission_list_loading_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_ASSIGNED_ACCESS_PERMISSION_LIST_LOADING_PORT);
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

		if(!load_assigned_access_permission_list(ssl_client))
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



