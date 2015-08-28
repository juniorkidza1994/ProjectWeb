#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_restricted_level_phr_access_request_list_update.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       	     = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) 	     = NULL;
static void (*clear_restricted_phr_access_request_table_callback_handler)()          = NULL;
static void (*add_restricted_phr_access_request_to_table_callback_handler)(
	char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, 
	unsigned int phr_id)                                                         = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void clear_restricted_phr_access_request_table_handler_callback();
static void add_restricted_phr_access_request_to_table_handler_callback(char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id);

static boolean connect_to_restricted_level_phr_access_request_list_loading_service(SSL **ssl_conn_ret);

// Implementaion
static void backend_alert_msg_handler_callback(char *alert_msg)
{
	if(backend_alert_msg_callback_handler)
	{
		backend_alert_msg_callback_handler(alert_msg);
	}
	else  // NULL
	{
		int_error("backend_alert_msg_callback_handler is NULL");
	}
}

static void backend_fatal_alert_msg_handler_callback(char *alert_msg)
{
	if(backend_fatal_alert_msg_callback_handler)
	{
		backend_fatal_alert_msg_callback_handler(alert_msg);
	}
	else  // NULL
	{
		int_error("backend_fatal_alert_msg_callback_handler is NULL");
	}
}

static void clear_restricted_phr_access_request_table_handler_callback()
{
	if(clear_restricted_phr_access_request_table_callback_handler)
	{
		clear_restricted_phr_access_request_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_restricted_phr_access_request_table_callback_handler is NULL");
	}
}

static void add_restricted_phr_access_request_to_table_handler_callback(char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id)
{
	if(add_restricted_phr_access_request_to_table_callback_handler)
	{
		add_restricted_phr_access_request_to_table_callback_handler(full_requestor_name, full_phr_ownername, data_description, approvals, 
			threshold_value, request_status, phr_id);
	}
	else  // NULL
	{
		int_error("add_restricted_phr_access_request_to_table_callback_handler is NULL");
	}
}

static boolean connect_to_restricted_level_phr_access_request_list_loading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server
	sprintf(emergency_server_addr, "%s:%s", GLOBAL_emergency_server_ip_addr, EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_LIST_LOADING_PORT);
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to emergency server failed");
		goto ERROR_AT_BIO_LAYER;
	}

	/* Hash value is used for verifying an SSL certificate to make sure that certificate is a latest update version, 
	   preventing a user uses a revoked certificate to feign to be a revoked one */
	if(!verify_file_integrity(SSL_CERT_PATH, GLOBAL_ssl_cert_hash, CALCULATING_SSL_CERT_HASH_PATH))
	{
		// Notify alert message to user and then terminate the application
		backend_fatal_alert_msg_handler_callback("Your SSL certificate is not verified.\nTo solve this, please contact an administrator.");
	}

	ctx = setup_client_ctx(SSL_CERT_PATH, GLOBAL_passwd, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	backend_alert_msg_handler_callback("Connecting SSL object failed");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
		backend_alert_msg_handler_callback("Checking SSL information failed");
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

boolean update_restricted_phr_access_request_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_restricted_phr_access_request_table_callback_handler_ptr)(), 
	void (*add_restricted_phr_access_request_to_table_callback_handler_ptr)(char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                          = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler                    = backend_fatal_alert_msg_callback_handler_ptr;
	clear_restricted_phr_access_request_table_callback_handler  = clear_restricted_phr_access_request_table_callback_handler_ptr;
	add_restricted_phr_access_request_to_table_callback_handler = add_restricted_phr_access_request_to_table_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];

	char         approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int approvals;

	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int threshold_value;

	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	char         is_end_of_requested_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_requested_restricted_phr_list_flag;

	char         phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         full_phr_ownername[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 2];

	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         full_emergency_staff_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 2];

	// Connect to Emergency Server
	if(!connect_to_restricted_level_phr_access_request_list_loading_service(&ssl_conn))
		goto ERROR;

	// Clear a restricted-level PHR access request table
	clear_restricted_phr_access_request_table_handler_callback();

	// Requested restricted-level PHRs
	while(1)
	{
		// Receive requested restricted-level PHR information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving requested restricted-level PHR information failed");
			goto ERROR;
		}

		// Get requested restricted-level PHR information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_requested_restricted_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_requested_restricted_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_requested_restricted_phr_list_flag failed");
		}

		is_end_of_requested_restricted_phr_list_flag = (strcmp(is_end_of_requested_restricted_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_requested_restricted_phr_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		{
			int_error("Extracting the phr_id failed");
		}

		phr_id = atoi(phr_id_str_tmp);

		if(read_token_from_buffer(buffer, 3, token_name, emergency_unit_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_unit_name") != 0)
		{
			int_error("Extracting the emergency_unit_name failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, emergency_staff_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_staff_name") != 0)
		{
			int_error("Extracting the emergency_staff_name failed");
		}

		if(read_token_from_buffer(buffer, 5, token_name, phr_owner_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
		{
			int_error("Extracting the phr_owner_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 6, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}
		
		if(read_token_from_buffer(buffer, 7, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		if(read_token_from_buffer(buffer, 8, token_name, approvals_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "approvals") != 0)
		{
			int_error("Extracting the approvals failed");
		}

		approvals = atoi(approvals_str_tmp);

		if(read_token_from_buffer(buffer, 9, token_name, threshold_value_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "threshold_value") != 0)
		{
			int_error("Extracting the threshold_value failed");
		}

		threshold_value = atoi(threshold_value_str_tmp);

		if(read_token_from_buffer(buffer, 10, token_name, request_status) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_status") != 0)
		{
			int_error("Extracting the request_status failed");
		}

		sprintf(full_emergency_staff_name, "%s.%s", emergency_unit_name, emergency_staff_name);
		sprintf(full_phr_ownername, "%s.%s", phr_owner_authority_name, phr_ownername);

		// Add a restricted-level PHR access request to table
		add_restricted_phr_access_request_to_table_handler_callback(full_emergency_staff_name, full_phr_ownername, 
			data_description, approvals, threshold_value, request_status, phr_id);
	}

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



