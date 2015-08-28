#include "UA_common.h"

#define ACCESS_GRANTING_TICKET_PATH         "UA_cache/UA_access_granting_ticket_responding.access_granting_ticket"
#define SGN_ACCESS_GRANTING_TICKET_PATH     "UA_cache/UA_access_granting_ticket_responding.sgn_access_granting_ticket"
#define ENC_SGN_ACCESS_GRANTING_TICKET_PATH "UA_cache/UA_access_granting_ticket_responding.enc_sgn_access_granting_ticket"

// Local Function Prototypes
static void set_expired_date_time(char *expired_date_time_ret);
static boolean respond_access_granting_ticket(SSL *ssl_client);

// Implementation
static void set_expired_date_time(char *expired_date_time_ret)  // Format is "YYYY-MM-DD.HH:mm:ss"
{
	time_t    expired_time;
	struct tm tm_expired_time;

	expired_time = time(NULL) + ACCESS_GRANTING_TICKET_LIFETIME*60;
	tm_expired_time = *localtime(&expired_time);
	strftime(expired_date_time_ret, strlen("YYYY-MM-DD.HH:mm:ss")+1, "%Y-%m-%d.%X", &tm_expired_time);
}

static boolean respond_access_granting_ticket(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         desired_phr_owner_name[USER_NAME_LENGTH + 1];
	char         desired_phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         ticket_passwd[PASSWD_LENGTH + 1];

	char         requestor_name[USER_NAME_LENGTH + 1];

	unsigned int desired_phr_owner_authority_id;
	unsigned int desired_phr_owner_id;
	char         upload_permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"
	char         download_permission_flag_str[FLAG_LENGTH + 1];   // "0" or "1"
	char         delete_permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"

	char         expired_date_time[DATETIME_STR_LENGTH + 1];      // Format is "YYYY-MM-DD.HH:mm:ss"

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, requestor_name, NULL);

	// Receive access granting ticket requesting information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving access granting ticket requesting information failed\n");
		goto ERROR;
	}

	// Get access granting ticket requesting information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_phr_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_name") != 0)
		int_error("Extracting the desired_phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, desired_phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_authority_name") != 0)
	{
		int_error("Extracting the desired_phr_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, ticket_passwd) != READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_passwd") != 0)
		int_error("Extracting the ticket_passwd failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for the PHR owner authority id and PHR owner id
	if(strcmp(desired_phr_owner_authority_name, GLOBAL_authority_name) == 0)
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, desired_phr_owner_name);
	}
	else
	{
		sprintf(stat, "SELECT UOA.user_id, UOA.authority_id FROM %s UOA, %s AUT WHERE UOA.authority_id = AUT.authority_id AND "
			"AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND UOA.username LIKE '%s' COLLATE latin1_general_cs", 
			UA__USERS_IN_OTHER_AUTHORITIES, UA__AUTHORITIES, desired_phr_owner_authority_name, desired_phr_owner_name);
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
		// Send the access granting ticket requesting result flag
		write_token_into_buffer("access_granting_ticket_requesting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the PHR owner that you're looking for", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access granting ticket requesting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	desired_phr_owner_id           = atoi(row[0]);
	desired_phr_owner_authority_id = (strcmp(desired_phr_owner_authority_name, GLOBAL_authority_name) == 0) ? GLOBAL_authority_id : atoi(row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Query for the PHR access permissions of the requestor
	sprintf(stat, "SELECT AP.upload_permission_flag, AP.download_permission_flag, AP.delete_permission_flag FROM %s AP, %s USR WHERE "
		"AP.user_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs AND AP.phr_owner_id = %u AND AP.phr_owner_authority_id = %u", 
		UA__ACCESS_PERMISSIONS, UA__USERS, requestor_name, desired_phr_owner_id, desired_phr_owner_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
	{
		// Send the access granting ticket requesting result flag
		write_token_into_buffer("access_granting_ticket_requesting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You do not have the access permission", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access granting ticket requesting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	strcpy(upload_permission_flag_str, row[0]);
	strcpy(download_permission_flag_str, row[1]);
	strcpy(delete_permission_flag_str, row[2]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Write the access granting ticket
	if(!write_token_into_file("ticket_owner_name", requestor_name, true, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the ticket_owner_name into the access granting ticket file failed");

	if(!write_token_into_file("ticket_owner_authority_name", GLOBAL_authority_name, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the ticket_owner_authority_name into the access granting ticket file failed");

	if(!write_token_into_file("phr_owner_name", desired_phr_owner_name, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the phr_owner_name into the access granting ticket file failed");

	if(!write_token_into_file("phr_owner_authority_name", desired_phr_owner_authority_name, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the phr_owner_authority_name into the access granting ticket file failed");

	if(!write_token_into_file("upload_permission_flag", upload_permission_flag_str, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the upload_permission_flag into the access granting ticket file failed");

	if(!write_token_into_file("download_permission_flag", download_permission_flag_str, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the download_permission_flag into the access granting ticket file failed");

	if(!write_token_into_file("delete_permission_flag", delete_permission_flag_str, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the delete_permission_flag into an access granting ticket file failed");

	// Set the ticket's expired date/time
	set_expired_date_time(expired_date_time);

	if(!write_token_into_file("expired_date_time", expired_date_time, false, ACCESS_GRANTING_TICKET_PATH))
		int_error("Writing the expired_date_time into an access granting ticket file failed");

	// Sign the access granting ticket with the user authority's private key
	if(!smime_sign_with_cert(ACCESS_GRANTING_TICKET_PATH, SGN_ACCESS_GRANTING_TICKET_PATH, UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, err_msg))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Signing the access granting ticket failed");
	}

	unlink(ACCESS_GRANTING_TICKET_PATH);

	// Encrypt the signed access granting ticket with the requestor's password
	if(!des3_encrypt(SGN_ACCESS_GRANTING_TICKET_PATH, ENC_SGN_ACCESS_GRANTING_TICKET_PATH, ticket_passwd, err_msg))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Encrypting the signed access granting ticket failed");
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Send the access granting ticket requesting result flag and the ticket
	write_token_into_buffer("access_granting_ticket_requesting_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the access granting ticket requesting result flag failed\n");
		goto ERROR;
	}

	if(!SSL_send_file(ssl_client, ENC_SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		fprintf(stderr, "Sending the access granting ticket failed\n");
		goto ERROR;
	}

	unlink(ENC_SGN_ACCESS_GRANTING_TICKET_PATH);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	unlink(ACCESS_GRANTING_TICKET_PATH);
	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ENC_SGN_ACCESS_GRANTING_TICKET_PATH);
	return false;
}

void *access_granting_ticket_responding_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_ACCESS_GRANTING_TICKET_RESPONDING_PORT);
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

		// Reqpond an access granting ticket
		if(!respond_access_granting_ticket(ssl_client))
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



