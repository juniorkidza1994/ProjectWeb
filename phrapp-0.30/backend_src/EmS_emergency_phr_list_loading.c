#include "EmS_common.h"

// Local Function Prototypes
static void get_no_approvals(MYSQL *db_conn, unsigned int phr_request_id, unsigned int *no_approvals_ret);
static void get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret);
static void get_restricted_phr_request_status(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_unit_name, 
	char *emergency_staff_name, unsigned int *no_approvals_ret,  unsigned int *threshold_value_ret, char *request_status_ret);

static boolean connect_to_emergency_phr_list_loading_service(SSL **ssl_conn_ret);
static boolean respond_emergency_phr_list_loading(SSL *ssl_client);
static boolean respond_requested_restricted_phr_list_loading(SSL *ssl_client);
static boolean respond_only_restricted_phr_list_loading(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static void get_no_approvals(MYSQL *db_conn, unsigned int phr_request_id, unsigned int *no_approvals_ret)
{
	MYSQL_RES *result = NULL;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	// Count the number of approvals of the specific request
	sprintf(stat, "SELECT approval_flag FROM %s WHERE phr_request_id = %u AND approval_flag = '1'", EMS__SECRET_KEY_APPROVALS, phr_request_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result            = mysql_store_result(db_conn);
	*no_approvals_ret = mysql_num_rows(result);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the threshold value of the desired restricted-level PHR
	sprintf(stat, "SELECT threshold_value FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		int_error("Getting the threshold value of the desired restricted-level PHR failed");
	}

	*threshold_value_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void get_restricted_phr_request_status(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_unit_name, 
	char *emergency_staff_name, unsigned int *no_approvals_ret,  unsigned int *threshold_value_ret, char *request_status_ret)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_request_id;

	get_threshold_value(db_conn, remote_site_phr_id, threshold_value_ret);

	// Query for the phr_request_id that was requested by the emergency staff if any
	sprintf(stat, "SELECT phr_request_id FROM %s WHERE remote_site_phr_id = %u AND emergency_unit_name LIKE '%s' COLLATE latin1_general_cs AND emergency_staff_name "
		"LIKE '%s' COLLATE latin1_general_cs", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, remote_site_phr_id, emergency_unit_name, emergency_staff_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	// There is no request for this PHR by the emergency staff
	if(!row)
	{	
		strcpy(request_status_ret, RESTRICTED_PHR_NO_REQUEST);
		*no_approvals_ret = 0;
		goto NO_REQUEST;
	}

	// There is a request for this PHR by the emergency staff
	phr_request_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	get_no_approvals(db_conn, phr_request_id, no_approvals_ret);

	// Note that, if the request was rejected, Emergency server will remove the request and then 
	// inform the emergency staff (requestor) about the rejection through his/her e-mail address
	if(*no_approvals_ret >= *threshold_value_ret)
	{
		// Request approved
		strcpy(request_status_ret, RESTRICTED_PHR_REQUEST_APPROVED);
	}
	else
	{
		// Request pending
		strcpy(request_status_ret, RESTRICTED_PHR_REQUEST_PENDING);
	}

	return;

NO_REQUEST:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean connect_to_emergency_phr_list_loading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    phr_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to PHR Server
	sprintf(phr_server_addr, "%s:%s", GLOBAL_phr_server_ip_addr, PHRSV_EMERGENCY_PHR_LIST_LOADING_PORT);
	bio_conn = BIO_new_connect(phr_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to PHR server failed\n");
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

	hosts[0] = PHR_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, false, NULL)) != X509_V_OK)
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

static boolean respond_emergency_phr_list_loading(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];

	SSL          *ssl_PHRsv_conn = NULL;
	char         is_end_of_secure_phr_list_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean      is_end_of_secure_phr_list_flag;

	char         is_end_of_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean      is_end_of_restricted_phr_list_flag;

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;

	unsigned int no_approvals;
	char         no_approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	unsigned int threshold_value;
	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	// Get the emergency staff info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);
	
	// Receive the emergency PHR list loading information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the emergency PHR list loading information failed\n");
		goto ERROR;
	}

	// Get a emergency PHR list loading information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	// Connect to PHR Server
	if(!connect_to_emergency_phr_list_loading_service(&ssl_PHRsv_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", EMERGENCY_PHR_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending request information failed\n");
		goto ERROR;
	}

	// Send the emergency PHR list loading information
	write_token_into_buffer("phr_ownername", phr_ownername, true, buffer);
	write_token_into_buffer("phr_owner_authority_name", GLOBAL_authority_name, false, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the emergency PHR list loading information failed\n");
		goto ERROR;
	}

	// Secure-level PHRs
	while(1)
	{
		// Receive secure-level PHR information
		if(SSL_recv_buffer(ssl_PHRsv_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the secure-level PHR information failed\n");
			goto ERROR;
		}

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the secure-level PHR information failed\n");
			goto ERROR;
		}		

		// Get the is_end_of_secure_phr_list_flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_secure_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_secure_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_secure_phr_list_flag failed");
		}

		is_end_of_secure_phr_list_flag = (strcmp(is_end_of_secure_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_secure_phr_list_flag)
			break;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Restricted-level PHRs
	while(1)
	{
		char data_description[DATA_DESCRIPTION_LENGTH + 1];
		char file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

		// Receive restricted-level PHR information
		if(SSL_recv_buffer(ssl_PHRsv_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the restricted-level PHR information failed\n");
			goto ERROR;
		}		

		// Get the is_end_of_restricted_phr_list_flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_restricted_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_restricted_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_restricted_phr_list_flag failed");
		}

		is_end_of_restricted_phr_list_flag = (strcmp(is_end_of_restricted_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_restricted_phr_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		{
			int_error("Extracting the phr_id failed");
		}

		phr_id = atoi(phr_id_str_tmp);

		if(read_token_from_buffer(buffer, 3, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
		{
			int_error("Extracting the file_size failed");
		}

		// Get a restricted-level PHR request status
		get_restricted_phr_request_status(db_conn, phr_id, emergency_unit_name, emergency_staff_name, &no_approvals, &threshold_value, request_status);

		sprintf(no_approvals_str_tmp, "%u", no_approvals);
		sprintf(threshold_value_str_tmp, "%u", threshold_value);

		// Re-pack the information
		write_token_into_buffer("is_end_of_restricted_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", phr_id_str_tmp, false, buffer);
		write_token_into_buffer("data_description", data_description, false, buffer);
		write_token_into_buffer("file_size", file_size_str_tmp, false, buffer);
		
		// Append the request info
		write_token_into_buffer("approvals", no_approvals_str_tmp, false, buffer);
		write_token_into_buffer("threshold_value", threshold_value_str_tmp, false, buffer);
		write_token_into_buffer("request_status", request_status, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted-level PHR information failed\n");
			goto ERROR;
		}
	}

	// Send the is_end_of_restricted_phr_list_flag
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_restricted_phr_list_flag failed\n");
		goto ERROR;
	}

	disconnect_db(&db_conn);

	SSL_cleanup(ssl_PHRsv_conn);
	ssl_PHRsv_conn = NULL;
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	if(ssl_PHRsv_conn)
	{
		SSL_cleanup(ssl_PHRsv_conn);
		ssl_PHRsv_conn = NULL;
	}

	return false;
}

static boolean respond_requested_restricted_phr_list_loading(SSL *ssl_client)
{
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_request_id;
	
	SSL          *ssl_PHRsv_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         remote_site_phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         restricted_phr_information_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      restricted_phr_information_requesting_result_flag;

	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	unsigned int no_approvals;
	char         no_approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	unsigned int threshold_value;
	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	// Get the emergency staff info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for the phr_request_id and remote_site_phr_id that was requested by the emergency staff if any
	sprintf(stat, "SELECT phr_request_id, remote_site_phr_id FROM %s WHERE emergency_unit_name LIKE '%s' COLLATE latin1_general_cs AND emergency_staff_name "
		"LIKE '%s' COLLATE latin1_general_cs", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, emergency_unit_name, emergency_staff_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	// There is no request from the emergency staff
	if(!row)
	{	
		// Send the is_end_of_requested_restricted_phr_list_flag
		write_token_into_buffer("is_end_of_requested_restricted_phr_list_flag", "1", true, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the is_end_of_requested_restricted_phr_list_flag failed\n");
			goto ERROR;
		}

		goto NO_REQUEST;
	}

	// There are requests from the emergency staff, then connect to PHR Server
	if(!connect_to_emergency_phr_list_loading_service(&ssl_PHRsv_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", REQUESTED_RESTRICTED_LEVEL_PHR_INFO_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending request information failed\n");
		goto ERROR;
	}

	// Requested restricted-level PHRs
	do{
		phr_request_id     = atoi(row[0]);
		remote_site_phr_id = atoi(row[1]);

		// Send the restricted-level PHR information request
		sprintf(remote_site_phr_id_str_tmp, "%u", remote_site_phr_id);
		write_token_into_buffer("is_end_of_getting_restricted_phr_information_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", remote_site_phr_id_str_tmp, false, buffer);

		if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted-level PHR information request failed\n");
			goto ERROR;
		}

		// Receive the restricted-level PHR information
		if(SSL_recv_buffer(ssl_PHRsv_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the restricted-level PHR information failed\n");
			goto ERROR;
		}	

		if(read_token_from_buffer(buffer, 1, token_name, restricted_phr_information_requesting_result_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "restricted_phr_information_requesting_result_flag") != 0)
		{
			int_error("Extracting the restricted_phr_information_requesting_result_flag failed");
		}

		restricted_phr_information_requesting_result_flag = (strcmp(restricted_phr_information_requesting_result_flag_str_tmp, "1") == 0) ? true : false;
		if(!restricted_phr_information_requesting_result_flag)
			continue;

		if(read_token_from_buffer(buffer, 2, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
		{
			int_error("Extracting the file_size failed");
		}

		get_threshold_value(db_conn, remote_site_phr_id, &threshold_value);
		get_no_approvals(db_conn, phr_request_id, &no_approvals);

		// Note that, if the request was rejected, Emergency server will remove the request and then 
		// inform the emergency staff (requestor) about the rejection through his/her e-mail address
		if(no_approvals >= threshold_value)
		{
			// Request approved
			strcpy(request_status, RESTRICTED_PHR_REQUEST_APPROVED);
		}
		else
		{
			// Request pending
			strcpy(request_status, RESTRICTED_PHR_REQUEST_PENDING);
		}

		sprintf(remote_site_phr_id_str_tmp, "%u", remote_site_phr_id);
		sprintf(no_approvals_str_tmp, "%u", no_approvals);
		sprintf(threshold_value_str_tmp, "%u", threshold_value);

		// Re-pack the information
		write_token_into_buffer("is_end_of_requested_restricted_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", remote_site_phr_id_str_tmp, false, buffer);
		write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);
		write_token_into_buffer("data_description", data_description, false, buffer);
		write_token_into_buffer("file_size", file_size_str_tmp, false, buffer);
		
		// Append the request info
		write_token_into_buffer("approvals", no_approvals_str_tmp, false, buffer);
		write_token_into_buffer("threshold_value", threshold_value_str_tmp, false, buffer);
		write_token_into_buffer("request_status", request_status, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the requested restricted-level PHR information failed\n");
			goto ERROR;
		}
	}
	while((row = mysql_fetch_row(result)));

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the is_end_of_getting_restricted_phr_information_flag
	write_token_into_buffer("is_end_of_getting_restricted_phr_information_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_getting_restricted_phr_information_flag failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_PHRsv_conn);
	ssl_PHRsv_conn = NULL;

	// Send the is_end_of_requested_restricted_phr_list_flag
	write_token_into_buffer("is_end_of_requested_restricted_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_requested_restricted_phr_list_flag failed\n");
		goto ERROR;
	}

	return true;

NO_REQUEST:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	if(ssl_PHRsv_conn)
	{
		SSL_cleanup(ssl_PHRsv_conn);
		ssl_PHRsv_conn = NULL;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	if(ssl_PHRsv_conn)
	{
		SSL_cleanup(ssl_PHRsv_conn);
		ssl_PHRsv_conn = NULL;
	}

	return false;
}

static boolean respond_only_restricted_phr_list_loading(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];

	SSL          *ssl_PHRsv_conn = NULL;

	char         is_end_of_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean      is_end_of_restricted_phr_list_flag;

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;

	unsigned int no_approvals;
	char         no_approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	unsigned int threshold_value;
	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	// Get the emergency staff info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);
	
	// Receive the restricted-level PHR list loading information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR list loading information failed\n");
		goto ERROR;
	}

	// Get the restricted-level PHR list loading information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	// Connect to PHR Server
	if(!connect_to_emergency_phr_list_loading_service(&ssl_PHRsv_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", ONLY_RESTRICTED_LEVEL_PHR_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending request information failed\n");
		goto ERROR;
	}

	// Send the restricted-level PHR list loading information
	write_token_into_buffer("phr_ownername", phr_ownername, true, buffer);
	write_token_into_buffer("phr_owner_authority_name", GLOBAL_authority_name, false, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the restricted-level PHR list loading information failed\n");
		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Restricted-level PHRs
	while(1)
	{
		char data_description[DATA_DESCRIPTION_LENGTH + 1];
		char file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

		// Receive restricted-level PHR information
		if(SSL_recv_buffer(ssl_PHRsv_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the restricted-level PHR information failed\n");
			goto ERROR;
		}		

		// Get the is_end_of_restricted_phr_list_flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_restricted_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_restricted_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_restricted_phr_list_flag failed");
		}

		is_end_of_restricted_phr_list_flag = (strcmp(is_end_of_restricted_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_restricted_phr_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		{
			int_error("Extracting the phr_id failed");
		}

		phr_id = atoi(phr_id_str_tmp);

		if(read_token_from_buffer(buffer, 3, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
		{
			int_error("Extracting the file_size failed");
		}

		// Get a restricted-level PHR request status
		get_restricted_phr_request_status(db_conn, phr_id, emergency_unit_name, emergency_staff_name, &no_approvals, &threshold_value, request_status);

		sprintf(no_approvals_str_tmp, "%u", no_approvals);
		sprintf(threshold_value_str_tmp, "%u", threshold_value);

		// Re-pack the information
		write_token_into_buffer("is_end_of_restricted_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", phr_id_str_tmp, false, buffer);
		write_token_into_buffer("data_description", data_description, false, buffer);
		write_token_into_buffer("file_size", file_size_str_tmp, false, buffer);
		
		// Append the request info
		write_token_into_buffer("approvals", no_approvals_str_tmp, false, buffer);
		write_token_into_buffer("threshold_value", threshold_value_str_tmp, false, buffer);
		write_token_into_buffer("request_status", request_status, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted-level PHR information failed\n");
			goto ERROR;
		}
	}

	// Send the is_end_of_restricted_phr_list_flag
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_restricted_phr_list_flag failed\n");
		goto ERROR;
	}

	disconnect_db(&db_conn);

	SSL_cleanup(ssl_PHRsv_conn);
	ssl_PHRsv_conn = NULL;
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	if(ssl_PHRsv_conn)
	{
		SSL_cleanup(ssl_PHRsv_conn);
		ssl_PHRsv_conn = NULL;
	}

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

	if(strcmp(request, EMERGENCY_PHR_LIST_LOADING) == 0)
	{
		return respond_emergency_phr_list_loading(ssl_client);
	}
	else if(strcmp(request, REQUESTED_RESTRICTED_LEVEL_PHR_LIST_LOADING) == 0)
	{
		return respond_requested_restricted_phr_list_loading(ssl_client);
	}
	else if(strcmp(request, ONLY_RESTRICTED_LEVEL_PHR_LIST_LOADING) == 0)
	{
		return respond_only_restricted_phr_list_loading(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *emergency_phr_list_loading_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_EMERGENCY_ACCESS_CERTFILE_PATH, EMS_EMERGENCY_ACCESS_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_EMERGENCY_PHR_LIST_LOADING_PORT);
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
    		if((err = post_connection_check(ssl_client, hosts, 1, false, NULL)) != X509_V_OK)
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



