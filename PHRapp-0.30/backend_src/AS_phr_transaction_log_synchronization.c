#include "AS_common.h"

// Local Function Prototypes
static void unset_sync_flag(MYSQL *db_conn, unsigned int event_log_id);
static boolean synchronize_phr_transaction_log(SSL *ssl_client);

// Implementation
static void unset_sync_flag(MYSQL *db_conn, unsigned int event_log_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Unset the sync flag
	sprintf(stat, "UPDATE %s SET sync_flag = '0' WHERE event_log_id = %u", AS__EVENT_LOGS, event_log_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static boolean synchronize_phr_transaction_log(SSL *ssl_client)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         syncing_authority_name[AUTHORITY_NAME_LENGTH + 1];

	unsigned int actor_id;
	char         actor_name[USER_NAME_LENGTH + 1];
	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_actor_admin_flag;

	unsigned int object_owner_id;
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_object_owner_admin_flag;

	unsigned int affected_user_id;
	char         affected_username[USER_NAME_LENGTH + 1];
	char         affected_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_affected_user_admin_flag;

	unsigned int event_log_id;
	char         buffer[BUFFER_LENGTH + 1];

	// Receive the syncing authority name
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the syncing authority name failed\n");
		goto ERROR;
	}

	// Get the syncing authority name token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, syncing_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "syncing_authority_name") != 0)
	{
		int_error("Extracting the syncing_authority_name failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for event logs regarding PHR transactions of desired authority's users
	sprintf(stat, "SELECT EVT.event_log_id, EVT.actor_id, EVT.object_owner_id, EVT.affected_user_id, EVT.object_description, EVT.event_description, "
		"EVT.date_time, EVT.actor_ip_address FROM %s EVT, %s USR, %s AUT WHERE (EVT.object_owner_id = USR.user_id OR EVT.affected_user_id = USR.user_id) "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND EVT.sync_flag = '1'", AS__EVENT_LOGS, 
		AS__USERS, AS__AUTHORITIES, syncing_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		event_log_id     = atoi(row[0]);
		actor_id         = atoi(row[1]);
		object_owner_id  = atoi(row[2]);
		affected_user_id = atoi(row[3]);

printf("event_log_id = %u\n", event_log_id);

		// Get users' info
		if(!get_user_info(db_conn, actor_id, actor_name, actor_authority_name, &is_actor_admin_flag))
			goto ERROR;

		if(!get_user_info(db_conn, object_owner_id, object_owner_name, object_owner_authority_name, &is_object_owner_admin_flag))
			goto ERROR;

		if(!get_user_info(db_conn, affected_user_id, affected_username, affected_user_authority_name, &is_affected_user_admin_flag))
			goto ERROR;

		// Send the PHR transaction log information
		write_token_into_buffer("is_end_of_phr_transaction_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", actor_name, false, buffer);
		write_token_into_buffer("actor_authority_name", actor_authority_name, false, buffer);
		write_token_into_buffer("is_actor_admin_flag", (is_actor_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_owner_name", object_owner_name, false, buffer);
		write_token_into_buffer("object_owner_authority_name", object_owner_authority_name, false, buffer);
		write_token_into_buffer("is_object_owner_admin_flag", (is_object_owner_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("affected_username", affected_username, false, buffer);
		write_token_into_buffer("affected_user_authority_name", affected_user_authority_name, false, buffer);
		write_token_into_buffer("is_affected_user_admin_flag", (is_affected_user_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_description", row[4], false, buffer);
		write_token_into_buffer("event_description", row[5], false, buffer);
		write_token_into_buffer("date_time", row[6], false, buffer);
		write_token_into_buffer("actor_ip_address", row[7], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR transaction log information failed\n");
			goto ERROR;
		}
printf("sync log out\n");

		// Unset an sync_flag of the event log that just be synchronized
		unset_sync_flag(db_conn, event_log_id);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of PHR transaction logs
	write_token_into_buffer("is_end_of_phr_transaction_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of PHR transaction logs failed\n");
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

void *phr_transaction_log_synchronization_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(AS_CERTFILE_PATH, AS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(AS_PHR_TRANSACTION_LOG_SYNCHRONIZATION_PORT);
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

		hosts[0] = USER_AUTH_CN;
    		if((err = post_connection_check(ssl_client, hosts, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}
		
		// Synchronize logs
		if(!synchronize_phr_transaction_log(ssl_client))
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



