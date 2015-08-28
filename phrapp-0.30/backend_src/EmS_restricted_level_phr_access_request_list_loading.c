#include "EmS_common.h"

// Local Function Prototypes
static void get_no_approvals(MYSQL *db_conn, unsigned int phr_request_id, unsigned int *no_approvals_ret);
static void get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret);
static boolean connect_to_emergency_phr_list_loading_service(SSL **ssl_conn_ret);
static boolean respond_list_loader_as_phr_owner(MYSQL *db_conn, SSL *ssl_client, unsigned int phr_owner_id, char *phr_ownername);
static boolean respond_request_list_with_specific_phr_owner_and_trusted_user(MYSQL *db_conn, SSL *ssl_PHRsv_conn, SSL *ssl_client, 
	unsigned int trusted_user_id, unsigned int phr_owner_id, char *phr_ownername);

static boolean respond_if_phr_owners_in_current_authority(MYSQL *db_conn, SSL *ssl_client, unsigned int trusted_user_id);

// The another authority's Emergency Server service
static boolean connect_to_remote_restricted_level_phr_access_request_list_loading_service(char *authority_name, char *emergency_server_ip_addr, SSL **ssl_conn_ret);
static boolean respond_if_phr_owners_in_another_authority(SSL *ssl_client, char *trusted_username, char *phr_owner_authority_name);
static boolean check_trusted_user_has_delegations_on_phr_owners_in_specific_authority(MYSQL *db_conn, unsigned int trusted_user_id, char *phr_owner_authority_name);
static boolean respond_list_loader_as_trusted_user(MYSQL *db_conn, SSL *ssl_client, unsigned int trusted_user_id, char *trusted_username);
static boolean respond_restricted_level_phr_access_request_list_loading(SSL *ssl_client);
static boolean respond_remote_ems_restricted_level_phr_access_request_list_loading(SSL *ssl_client);

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

// Respond the requests that have list loader as PHR owner
static boolean respond_list_loader_as_phr_owner(MYSQL *db_conn, SSL *ssl_client, unsigned int phr_owner_id, char *phr_ownername)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	SSL          *ssl_PHRsv_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	unsigned int phr_request_id;

	char         remote_site_phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	char         restricted_phr_information_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      restricted_phr_information_requesting_result_flag;

	char         data_description[DATA_DESCRIPTION_LENGTH + 1];

	unsigned int no_approvals;
	char         no_approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	unsigned int threshold_value;
	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	// Query for the requests that have the specific PHR owner
	sprintf(stat, "SELECT REQ.phr_request_id, REQ.remote_site_phr_id, REQ.emergency_unit_name, REQ.emergency_staff_name FROM %s REQ, %s RLP WHERE "
		"REQ.remote_site_phr_id = RLP.remote_site_phr_id AND RLP.phr_owner_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, EMS__RESTRICTED_LEVEL_PHRS, phr_owner_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	// There is no request of the specific PHR owner's requested restricted-level PHRs
	if(!row)
	{	
		goto NO_REQUEST;
	}

	// There are requests
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
		strcpy(emergency_unit_name, row[2]);
		strcpy(emergency_staff_name, row[3]);

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

		// Ignore index #2 because we had this information already
		/*if(read_token_from_buffer(buffer, 2, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}*/

		if(read_token_from_buffer(buffer, 3, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		// Ignore index #4 because we do not need this informaion
		/*if(read_token_from_buffer(buffer, 4, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
		{
			int_error("Extracting the file_size failed");
		}*/

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
		write_token_into_buffer("emergency_unit_name", emergency_unit_name, false, buffer);
		write_token_into_buffer("emergency_staff_name", emergency_staff_name, false, buffer);
		write_token_into_buffer("phr_owner_authority_name", GLOBAL_authority_name, false, buffer);
		write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);
		write_token_into_buffer("data_description", data_description, false, buffer);
		
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

	// Send the is_end_of_getting_restricted_phr_information_flag
	write_token_into_buffer("is_end_of_getting_restricted_phr_information_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_getting_restricted_phr_information_flag failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_PHRsv_conn);
	ssl_PHRsv_conn = NULL;
	return true;

NO_REQUEST:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

	if(ssl_PHRsv_conn)
	{
		SSL_cleanup(ssl_PHRsv_conn);
		ssl_PHRsv_conn = NULL;
	}

	return false;
}

static boolean respond_request_list_with_specific_phr_owner_and_trusted_user(MYSQL *db_conn, SSL *ssl_PHRsv_conn, SSL *ssl_client, 
	unsigned int trusted_user_id, unsigned int phr_owner_id, char *phr_ownername)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	unsigned int phr_request_id;

	char         remote_site_phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	char         restricted_phr_information_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      restricted_phr_information_requesting_result_flag;

	char         data_description[DATA_DESCRIPTION_LENGTH + 1];

	unsigned int no_approvals;
	char         no_approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	unsigned int threshold_value;
	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	// Query for the requests of the specific PHR owner
	sprintf(stat, "SELECT REQ.phr_request_id, REQ.remote_site_phr_id, REQ.emergency_unit_name, REQ.emergency_staff_name FROM %s REQ, %s RLP WHERE "
		"REQ.remote_site_phr_id = RLP.remote_site_phr_id AND RLP.phr_owner_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, EMS__RESTRICTED_LEVEL_PHRS, phr_owner_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);

	// Requested restricted-level PHRs
	while((row = mysql_fetch_row(result)))
	{
		phr_request_id     = atoi(row[0]);
		remote_site_phr_id = atoi(row[1]);
		strcpy(emergency_unit_name, row[2]);
		strcpy(emergency_staff_name, row[3]);

		// If the trusted user took the deduction on this request, skip this request to attend him
		if(check_trusted_user_had_deduction_this_request(db_conn, trusted_user_id, phr_request_id))
			continue;

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

		// Ignore index #2 because we had this information already
		/*if(read_token_from_buffer(buffer, 2, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}*/

		if(read_token_from_buffer(buffer, 3, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		// Ignore index #4 because we do not need this informaion
		/*if(read_token_from_buffer(buffer, 4, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
		{
			int_error("Extracting the file_size failed");
		}*/

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
		write_token_into_buffer("emergency_unit_name", emergency_unit_name, false, buffer);
		write_token_into_buffer("emergency_staff_name", emergency_staff_name, false, buffer);
		write_token_into_buffer("phr_owner_authority_name", GLOBAL_authority_name, false, buffer);
		write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);
		write_token_into_buffer("data_description", data_description, false, buffer);
		
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

static boolean respond_if_phr_owners_in_current_authority(MYSQL *db_conn, SSL *ssl_client, unsigned int trusted_user_id)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_owner_id;
	char         phr_ownername[USER_NAME_LENGTH + 1];

	SSL          *ssl_PHRsv_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];

	// There are requests
	if(!connect_to_emergency_phr_list_loading_service(&ssl_PHRsv_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", REQUESTED_RESTRICTED_LEVEL_PHR_INFO_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending request information failed\n");
		goto ERROR;
	}

	// Query for all PHR owners who are in the current authority and delegate the specific user as their trusted user
	sprintf(stat, "SELECT phr_owner_id FROM %s WHERE trusted_user_id = %u AND rejection_by_trusted_user_flag = '0'", EMS__DELEGATIONS, trusted_user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		phr_owner_id = atoi(row[0]);

		// Get the PHR owner's name
		if(!get_user_info(db_conn, phr_owner_id, NULL, phr_ownername))
			int_error("Getting the PHR ownername failed");

		// Respond the requests of the specific PHR owner and which have the specific trusted user who does not have a deduction 
		if(!respond_request_list_with_specific_phr_owner_and_trusted_user(db_conn, ssl_PHRsv_conn, 
			ssl_client, trusted_user_id, phr_owner_id, phr_ownername))
		{
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the is_end_of_getting_restricted_phr_information_flag
	write_token_into_buffer("is_end_of_getting_restricted_phr_information_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_PHRsv_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_getting_restricted_phr_information_flag failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_PHRsv_conn);
	ssl_PHRsv_conn = NULL;
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(ssl_PHRsv_conn)
	{
		SSL_cleanup(ssl_PHRsv_conn);
		ssl_PHRsv_conn = NULL;
	}

	return false;
}

// The another authority's Emergency Server service
static boolean connect_to_remote_restricted_level_phr_access_request_list_loading_service(char *authority_name, char *emergency_server_ip_addr, SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server of another authority
	sprintf(emergency_server_addr, "%s:%s", emergency_server_ip_addr, EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_LIST_LOADING_REMOTE_EMS_PORT/*"7039"*/);  //****
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to %s's emergency server failed\n", authority_name);
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

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, authority_name)) != X509_V_OK)
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

static boolean respond_if_phr_owners_in_another_authority(SSL *ssl_client, char *trusted_username, char *phr_owner_authority_name)
{
	SSL     *ssl_conn = NULL;
	char    remote_emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];

	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_requested_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_requested_restricted_phr_list_flag;

	// Get remote Emergency Server's IP address
	if(!get_remote_emergency_server_ip_addr(phr_owner_authority_name, remote_emergency_server_ip_addr))
	{
		goto ERROR;
	}

	// Connect to the another authority's Emergency Server
	if(!connect_to_remote_restricted_level_phr_access_request_list_loading_service(phr_owner_authority_name, remote_emergency_server_ip_addr, &ssl_conn))
	{
		goto COULD_NOT_CONNECT_TO_REMOTE_EMS;
	}

	// Send the trusted user information
	write_token_into_buffer("trusted_user_authority_name", GLOBAL_authority_name, true, buffer);
	write_token_into_buffer("trusted_username", trusted_username, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the trusted user information failed\n");
		goto ERROR;
	}

	// Restricted-level PHR access request list
	while(1)
	{
		// Receive the restricted-level PHR access request information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the restricted-level PHR access request information failed\n");
			goto ERROR;
		}

		// Get the is_end_of_requested_restricted_phr_list_flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_requested_restricted_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_requested_restricted_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_requested_restricted_phr_list_flag failed");
		}

		is_end_of_requested_restricted_phr_list_flag = (strcmp(is_end_of_requested_restricted_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_requested_restricted_phr_list_flag)
			break;

		// Forward packet to the client
		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted-level PHR access request information failed\n");
			goto ERROR;
		}
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

COULD_NOT_CONNECT_TO_REMOTE_EMS:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

static boolean check_trusted_user_has_delegations_on_phr_owners_in_specific_authority(MYSQL *db_conn, unsigned int trusted_user_id, char *phr_owner_authority_name)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	boolean   has_delegation_flag = false;

	// Query for the delegations on the PHR owners in specific authority and the specific trusted user who is in the current authority
	sprintf(stat, "SELECT DGT.delegation_id FROM %s DGT, %s USR, %s AUT WHERE DGT.trusted_user_id = %u AND DGT.rejection_by_trusted_user_flag = '0' AND "
		"DGT.phr_owner_id = USR.user_id AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", EMS__DELEGATIONS, 
		EMS__USERS, EMS__AUTHORITIES, trusted_user_id, phr_owner_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	has_delegation_flag = (row) ? true : false;

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return has_delegation_flag;
}

// Respond the requests that have list loader as trusted user (only the requests that the trusted user does not have a deduction)
static boolean respond_list_loader_as_trusted_user(MYSQL *db_conn, SSL *ssl_client, unsigned int trusted_user_id, char *trusted_username)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	char      phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Query for all authorities
	sprintf(stat, "SELECT authority_name FROM %s ORDER BY authority_id ASC", EMS__AUTHORITIES);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		strcpy(phr_owner_authority_name, row[0]);

		if(strcmp(phr_owner_authority_name, GLOBAL_authority_name) == 0)  // Current authority
		{
			if(!respond_if_phr_owners_in_current_authority(db_conn, ssl_client, trusted_user_id))
				goto ERROR;
		}
		else  // Another authority
		{
			// If the trusted user does not have any delegation in the specific authority, skip this authority
			if(check_trusted_user_has_delegations_on_phr_owners_in_specific_authority(db_conn, trusted_user_id, phr_owner_authority_name))
			{
				if(!respond_if_phr_owners_in_another_authority(ssl_client, trusted_username, phr_owner_authority_name))
					goto ERROR;
			}
		}
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

static boolean respond_restricted_level_phr_access_request_list_loading(SSL *ssl_client)
{
	char         requestor_name[USER_NAME_LENGTH + 1];
	unsigned int requestor_id;	

	MYSQL        *db_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];

	// Get the requestor name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, requestor_name, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Get the requestor id
	if(get_user_id(db_conn, requestor_name, GLOBAL_authority_name, &requestor_id))
	{
		// Respond the requests that have list loader as PHR owner
		if(!respond_list_loader_as_phr_owner(db_conn, ssl_client, requestor_id, requestor_name))
			goto ERROR;

		// Respond the requests that have list loader as trusted user (only the requests that the trusted user does not have a deduction)
		if(!respond_list_loader_as_trusted_user(db_conn, ssl_client, requestor_id, requestor_name))
			goto ERROR;
	}

	// Send the is_end_of_requested_restricted_phr_list_flag
	write_token_into_buffer("is_end_of_requested_restricted_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_requested_restricted_phr_list_flag failed\n");
		goto ERROR;
	}

	disconnect_db(&db_conn);
	db_conn = NULL;
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

void *restricted_level_phr_access_request_list_loading_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_LIST_LOADING_PORT);
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

		// Respond restricted-level PHR access request list loading
		if(!respond_restricted_level_phr_access_request_list_loading(ssl_client))
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

static boolean respond_remote_ems_restricted_level_phr_access_request_list_loading(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         trusted_username[USER_NAME_LENGTH + 1];
	unsigned int trusted_user_id;

	MYSQL        *db_conn = NULL;

	// Receive the trusted user information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the trusted user information failed\n");
		goto ERROR;
	}

	// Get the trusted user information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, trusted_user_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_user_authority_name") != 0)
		int_error("Extracting the trusted_user_authority_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_username") != 0)
		int_error("Extracting the trusted_username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Get the trusted user id
	if(get_user_id(db_conn, trusted_username, trusted_user_authority_name, &trusted_user_id))
	{
		// Respond the requests that have the specific trusted user (only the requests that the trusted user does not have a deduction)
		if(!respond_if_phr_owners_in_current_authority(db_conn, ssl_client, trusted_user_id))
			goto ERROR;
	}

	// Send the is_end_of_requested_restricted_phr_list_flag
	write_token_into_buffer("is_end_of_requested_restricted_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_requested_restricted_phr_list_flag failed\n");
		goto ERROR;
	}

	disconnect_db(&db_conn);
	db_conn = NULL;
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

void *restricted_level_phr_access_request_list_loading_remote_ems_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_LIST_LOADING_REMOTE_EMS_PORT);
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

		hosts[0] = EMERGENCY_SERVER_CN;
    		if((err = post_connection_check(ssl_client, hosts, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Respond the remote emergency server's restricted-level PHR access request list loading
		if(!respond_remote_ems_restricted_level_phr_access_request_list_loading(ssl_client))
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



