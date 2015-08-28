#include "EmS_common.h"

// Local Function Prototypes
static boolean record_transaction_log(SSL *ssl_client, char *desired_trusted_username, char *desired_trusted_user_authority_name, char *event_description);
static boolean connect_to_user_existence_checking_service(SSL **ssl_conn_ret);

// Check for the existence of the trusted user by asking the user authority
static boolean does_desired_trusted_user_exists(char *desired_trusted_user_authority_name, char *desired_trusted_username);
static boolean add_emergency_trusted_user(SSL *ssl_client, char *desired_trusted_user_authority_name, char *desired_trusted_username);

// Implementation
static boolean record_transaction_log(SSL *ssl_client, char *desired_trusted_username, char *desired_trusted_user_authority_name, char *event_description)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char phr_owner_name[USER_NAME_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn_AS))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send a transaction log
	write_token_into_buffer("actor_name", phr_owner_name, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", desired_trusted_username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", desired_trusted_user_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", NO_SPECIFIC_DATA, false, buffer);
	write_token_into_buffer("event_description", event_description, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn_AS);
	ssl_conn_AS = NULL;
	return true;

ERROR:

	if(ssl_conn_AS)
	{
		SSL_cleanup(ssl_conn_AS);
		ssl_conn_AS = NULL;
	}

	return false;
}

static boolean connect_to_user_existence_checking_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_USER_EXISTENCE_CHECKING_PORT);
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to user authority failed\n");
		goto ERROR_AT_BIO_LAYER;
	}

	ctx = setup_client_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	fprintf(stderr, "Connecting SSL object failed\n");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = USER_AUTH_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        	goto ERROR_AT_SSL_LAYER;
    	}

	// Return value of *ssl_conn_ret
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return true;

ERROR_AT_BIO_LAYER:

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);	
	return false;

ERROR_AT_SSL_LAYER:

	SSL_cleanup(*ssl_conn_ret);
	*ssl_conn_ret = NULL;
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return false;
}

// Check for the existence of the trusted user by asking the user authority
static boolean does_desired_trusted_user_exists(char *desired_trusted_user_authority_name, char *desired_trusted_username)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    user_existence_checking_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean user_existence_checking_result_flag;

	// Connect to User Authority
	if(!connect_to_user_existence_checking_service(&ssl_conn))
		goto ERROR;

	// Send the user existence checking information
	write_token_into_buffer("authority_name", desired_trusted_user_authority_name, true, buffer);
	write_token_into_buffer("username", desired_trusted_username, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
		goto ERROR;

	// Receive user existence checking result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		goto ERROR;

	// Get a user existence checking result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_existence_checking_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_existence_checking_result_flag") != 0)
	{
		int_error("Extracting the user_existence_checking_result_flag failed");
	}

	user_existence_checking_result_flag = (strcmp(user_existence_checking_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_existence_checking_result_flag)
		goto ERROR;

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

static boolean add_emergency_trusted_user(SSL *ssl_client, char *desired_trusted_user_authority_name, char *desired_trusted_username)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;
	unsigned int trusted_user_id;

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// The desired trusted user must not be the same one with the PHR owner
	if(strcmp(desired_trusted_user_authority_name, GLOBAL_authority_name) == 0 && strcmp(desired_trusted_username, phr_owner_name) == 0)
	{
		// Send the emergency trusted user adding result flag
		write_token_into_buffer("emergency_trusted_user_adding_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Trusted user must be another user", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency trusted user adding result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of the trusted user by asking the user authority
	if(!does_desired_trusted_user_exists(desired_trusted_user_authority_name, desired_trusted_username))
	{
		// Send the emergency trusted user adding result flag
		write_token_into_buffer("emergency_trusted_user_adding_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the user that you're looking for", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency trusted user adding result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	phr_owner_id    = get_user_id_if_not_exist_create(db_conn, phr_owner_name, GLOBAL_authority_name);
	trusted_user_id = get_user_id_if_not_exist_create(db_conn, desired_trusted_username, desired_trusted_user_authority_name);

	// Check for the existence of the delegation (ignore the rejection_by_trusted_user_flag variable)
	sprintf(stat, "SELECT delegation_id FROM %s WHERE trusted_user_id = %u AND phr_owner_id = %u", EMS__DELEGATIONS, trusted_user_id, phr_owner_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	if(row)
	{
		// Send the emergency trusted user adding result flag
		write_token_into_buffer("emergency_trusted_user_adding_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You have added this user in your trusted user list already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency trusted user adding result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Insert the emergency trusted user
	sprintf(stat, "INSERT INTO %s(trusted_user_id, rejection_by_trusted_user_flag, phr_owner_id) VALUES(%u, '0', %u)", EMS__DELEGATIONS, trusted_user_id, phr_owner_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);

	// Send the emergency trusted user adding result flag
	write_token_into_buffer("emergency_trusted_user_adding_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the emergency trusted user adding result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log(ssl_client, desired_trusted_username, desired_trusted_user_authority_name, EMERGENCY_TRUSTED_USER_ADDING_MSG);
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
	char    request[REQUEST_TYPE_LENGTH + 1];
	char    desired_trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char    desired_trusted_username[USER_NAME_LENGTH + 1];

	// Receive emergency trusted user operation request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving emergency trusted user operation request information failed\n");
		goto ERROR;
	}

	// Get emergency trusted user information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(read_token_from_buffer(buffer, 2, token_name, desired_trusted_user_authority_name) != READ_TOKEN_SUCCESS 
		|| strcmp(token_name, "desired_trusted_user_authority_name") != 0)
	{
		int_error("Extracting the desired_trusted_user_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, desired_trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_trusted_username") != 0)
		int_error("Extracting the desired_trusted_username failed");

	if(strcmp(request, EMERGENCY_TRUSTED_USER_ADDING) == 0)
	{
		return add_emergency_trusted_user(ssl_client, desired_trusted_user_authority_name, desired_trusted_username);
	}
/*	else if(strcmp(request, EMERGENCY_TRUSTED_USER_REMOVAL) == 0)
	{
		return remove_emergency_trusted_user(ssl_client, desired_trusted_user_authority_name, desired_trusted_username);
	}*/
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *emergency_trusted_user_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_EMERGENCY_TRUSTED_USER_MANAGEMENT_PORT);
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



