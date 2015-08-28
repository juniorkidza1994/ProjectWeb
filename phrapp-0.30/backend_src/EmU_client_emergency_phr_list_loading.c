#include "EmU_client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH  "EmU_client_cache/EmU_client_emergency_phr_list_loading.calculating_ssl_cert_hash"
#define UNDERSTANDABLE_FILE_SIZE_LENGTH 11

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                   = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)             = NULL;
static void (*clear_secure_phr_to_table_callback_handler)()                          = NULL;
static void (*add_secure_phr_list_to_table_callback_handler)(
	char *data_description, char *file_size, unsigned int phr_id)                = NULL;

static void (*clear_restricted_phr_to_table_callback_handler)()                      = NULL;
static void (*add_restricted_phr_list_to_table_callback_handler)(
	char *data_description, char *file_size, unsigned int approvals, 
	unsigned int threshold_value, char *request_status, unsigned int phr_id)     = NULL;

static void (*clear_requested_restricted_phr_tracking_table_callback_handler)()      = NULL;
static void (*add_requested_restricted_phr_tracking_list_to_table_callback_handler)(
	char *full_phr_ownername, char *data_description, char *file_size, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, 
	unsigned int phr_id, char *emergency_server_ip_addr)                         = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void clear_secure_phr_to_table_handler_callback();
static void add_secure_phr_list_to_table_handler_callback(char *data_description, char *file_size, unsigned int phr_id);
static void clear_restricted_phr_to_table_handler_callback();
static void add_restricted_phr_list_to_table_handler_callback(char *data_description, char *file_size, unsigned int approvals, 
	unsigned int threshold_value, char *request_status, unsigned int phr_id);

static void clear_requested_restricted_phr_tracking_table_handler_callback();
static void add_requested_restricted_phr_tracking_list_to_table_handler_callback(char *full_phr_ownername, char *data_description, 
	char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id, char *emergency_server_ip_addr);

static void convert_file_size_to_understandable_unit(unsigned int file_size, char *understanable_file_size_ret);
static boolean connect_to_emergency_phr_list_loading_service(char *emergency_server_ip_addr, char *target_authority_name, SSL **ssl_conn_ret);

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

static void clear_secure_phr_to_table_handler_callback()
{
	if(clear_secure_phr_to_table_callback_handler)
	{
		clear_secure_phr_to_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_secure_phr_to_table_callback_handler is NULL");
	}
}

static void add_secure_phr_list_to_table_handler_callback(char *data_description, char *file_size, unsigned int phr_id)
{
	if(add_secure_phr_list_to_table_callback_handler)
	{
		add_secure_phr_list_to_table_callback_handler(data_description, file_size, phr_id);
	}
	else  // NULL
	{
		int_error("add_secure_phr_list_to_table_callback_handler is NULL");
	}
}

static void clear_restricted_phr_to_table_handler_callback()
{
	if(clear_restricted_phr_to_table_callback_handler)
	{
		clear_restricted_phr_to_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_restricted_phr_to_table_callback_handler is NULL");
	}
}

static void add_restricted_phr_list_to_table_handler_callback(char *data_description, char *file_size, unsigned int approvals, 
	unsigned int threshold_value, char *request_status, unsigned int phr_id)
{
	if(add_restricted_phr_list_to_table_callback_handler)
	{
		add_restricted_phr_list_to_table_callback_handler(data_description, file_size, approvals, threshold_value, request_status, phr_id);
	}
	else  // NULL
	{
		int_error("add_restricted_phr_list_to_table_callback_handler is NULL");
	}
}

static void clear_requested_restricted_phr_tracking_table_handler_callback()
{
	if(clear_requested_restricted_phr_tracking_table_callback_handler)
	{
		clear_requested_restricted_phr_tracking_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_requested_restricted_phr_tracking_table_callback_handler is NULL");
	}
}

static void add_requested_restricted_phr_tracking_list_to_table_handler_callback(char *full_phr_ownername, char *data_description, 
	char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id, char *emergency_server_ip_addr)
{
	if(add_requested_restricted_phr_tracking_list_to_table_callback_handler)
	{
		add_requested_restricted_phr_tracking_list_to_table_callback_handler(full_phr_ownername, data_description, file_size, approvals, 
			threshold_value, request_status, phr_id, emergency_server_ip_addr);
	}
	else  // NULL
	{
		int_error("add_requested_restricted_phr_tracking_list_to_table_callback_handler is NULL");
	}
}

static void convert_file_size_to_understandable_unit(unsigned int file_size, char *understanable_file_size_ret)
{
	#define GB 1073741824   // in byte unit
	#define MB 1048576
	#define KB 1024

	// GB unit
	if(file_size >= GB)
	{
		unsigned int nGB = file_size/GB;
		unsigned int nMB = (file_size % GB)/MB;

		sprintf(understanable_file_size_ret, "%u.%u GB", nGB, nMB/10);
	}
	else if(file_size >= MB)  // MB unit
	{
		unsigned int nMB = file_size/MB;
		unsigned int nKB = (file_size % MB)/KB;

		sprintf(understanable_file_size_ret, "%u.%u MB", nMB, nKB/10);
	}
	else if(file_size >= KB)  // KB unit
	{
		unsigned int nKB = file_size/KB;
		unsigned int nbytes = file_size % KB;

		sprintf(understanable_file_size_ret, "%u.%u KB", nKB, nbytes/10);
	}
	else // Byte unit
	{
		sprintf(understanable_file_size_ret, "%u bytes", file_size);
	}
}

static boolean connect_to_emergency_phr_list_loading_service(char *emergency_server_ip_addr, char *target_authority_name, SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server of the target authority 
	sprintf(emergency_server_addr, "%s:%s", emergency_server_ip_addr, EMS_EMERGENCY_PHR_LIST_LOADING_PORT);
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

	ctx = setup_client_ctx(SSL_CERT_PATH, GLOBAL_passwd, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	backend_alert_msg_handler_callback("Connecting SSL object failed");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, target_authority_name)) != X509_V_OK)
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

boolean load_emergency_phr_list(char *emergency_server_ip_addr, char *authority_name, char *phr_ownername, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_secure_phr_to_table_callback_handler_ptr)(), 
	void (*add_secure_phr_list_to_table_callback_handler_ptr)(char *data_description, char *file_size, unsigned int phr_id), 
	void (*clear_restricted_phr_to_table_callback_handler_ptr)(), void (*add_restricted_phr_list_to_table_callback_handler_ptr)(
	char *data_description, char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler                  = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler            = backend_fatal_alert_msg_callback_handler_ptr;
	clear_secure_phr_to_table_callback_handler          = clear_secure_phr_to_table_callback_handler_ptr;
	add_secure_phr_list_to_table_callback_handler       = add_secure_phr_list_to_table_callback_handler_ptr;
	clear_restricted_phr_to_table_callback_handler      = clear_restricted_phr_to_table_callback_handler_ptr;
	add_restricted_phr_list_to_table_callback_handler   = add_restricted_phr_list_to_table_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int file_size;
	char         understanable_file_size[UNDERSTANDABLE_FILE_SIZE_LENGTH + 1];

	char         approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int approvals;

	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int threshold_value;

	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	char         is_end_of_secure_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_secure_phr_list_flag;

	char         is_end_of_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_restricted_phr_list_flag;

	boolean      found_secure_phr_flag     = false;
	boolean      found_restricted_phr_flag = false;

	// Connect to Emergency Server of the target authority
	if(!connect_to_emergency_phr_list_loading_service(emergency_server_ip_addr, authority_name, &ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", EMERGENCY_PHR_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send the emergency PHR list loading information
	write_token_into_buffer("phr_ownername", phr_ownername, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the emergency PHR list loading information failed");
		goto ERROR;
	}

	// Clear secure-level and restricted-level PHR tables
	clear_secure_phr_to_table_handler_callback();
	clear_restricted_phr_to_table_handler_callback();

	// Secure-level PHRs
	while(1)
	{
		// Receive secure-level PHR information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving secure-level PHR information failed");
			goto ERROR;
		}

		// Get secure-level PHR information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_secure_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_secure_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_secure_phr_list_flag failed");
		}

		is_end_of_secure_phr_list_flag = (strcmp(is_end_of_secure_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_secure_phr_list_flag)
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

		file_size = atoi(file_size_str_tmp);

		// Convert file size in byte unit to understandable unit
		convert_file_size_to_understandable_unit(file_size, understanable_file_size);

		// Add an secure-level PHR list to table
		add_secure_phr_list_to_table_handler_callback(data_description, understanable_file_size, phr_id);
		
		found_secure_phr_flag = true;
	}

	// Restricted-level PHRs
	while(1)
	{
		// Receive restricted-level PHR information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving restricted-level PHR information failed");
			goto ERROR;
		}

		// Get restricted-level PHR information tokens from buffer
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

		file_size = atoi(file_size_str_tmp);

		if(read_token_from_buffer(buffer, 5, token_name, approvals_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "approvals") != 0)
		{
			int_error("Extracting the approvals failed");
		}

		approvals = atoi(approvals_str_tmp);

		if(read_token_from_buffer(buffer, 6, token_name, threshold_value_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "threshold_value") != 0)
		{
			int_error("Extracting the threshold_value failed");
		}

		threshold_value = atoi(threshold_value_str_tmp);

		if(read_token_from_buffer(buffer, 7, token_name, request_status) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_status") != 0)
		{
			int_error("Extracting the request_status failed");
		}

		// Convert file size in byte unit to understandable unit
		convert_file_size_to_understandable_unit(file_size, understanable_file_size);

		// Add a restricted-level PHR list to table
		add_restricted_phr_list_to_table_handler_callback(data_description, understanable_file_size, approvals, threshold_value, request_status, phr_id);
		
		found_restricted_phr_flag = true;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	if(!found_secure_phr_flag && !found_restricted_phr_flag)
	{
		backend_alert_msg_handler_callback("Do not have any PHR stored on a PHR server");
	}
	else if(!found_secure_phr_flag)
	{
		backend_alert_msg_handler_callback("Do not have any secure-level PHR stored on a PHR server");
	}
	else if(!found_restricted_phr_flag)
	{
		backend_alert_msg_handler_callback("Do not have any restricted-level PHR stored on a PHR server");
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

boolean load_requested_restricted_phr_list(char *authority_name, char *emergency_server_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_requested_restricted_phr_tracking_list_to_table_callback_handler_ptr)(
	char *full_phr_ownername, char *data_description, char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, 
	unsigned int phr_id, char *emergency_server_ip_addr))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler                                   = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler                             = backend_fatal_alert_msg_callback_handler_ptr;
	add_requested_restricted_phr_tracking_list_to_table_callback_handler = add_requested_restricted_phr_tracking_list_to_table_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int file_size;
	char         understanable_file_size[UNDERSTANDABLE_FILE_SIZE_LENGTH + 1];

	char         approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int approvals;

	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int threshold_value;

	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	char         is_end_of_requested_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_requested_restricted_phr_list_flag;

	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         full_phr_ownername[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 2];

	// Connect to Emergency Server of the target authority
	if(!connect_to_emergency_phr_list_loading_service(emergency_server_ip_addr, authority_name, &ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", REQUESTED_RESTRICTED_LEVEL_PHR_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

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

		if(read_token_from_buffer(buffer, 3, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		{
			int_error("Extracting the data_description failed");
		}

		if(read_token_from_buffer(buffer, 5, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
		{
			int_error("Extracting the file_size failed");
		}

		file_size = atoi(file_size_str_tmp);

		if(read_token_from_buffer(buffer, 6, token_name, approvals_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "approvals") != 0)
		{
			int_error("Extracting the approvals failed");
		}

		approvals = atoi(approvals_str_tmp);

		if(read_token_from_buffer(buffer, 7, token_name, threshold_value_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "threshold_value") != 0)
		{
			int_error("Extracting the threshold_value failed");
		}

		threshold_value = atoi(threshold_value_str_tmp);

		if(read_token_from_buffer(buffer, 8, token_name, request_status) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_status") != 0)
		{
			int_error("Extracting the request_status failed");
		}

		// Convert file size in byte unit to understandable unit
		convert_file_size_to_understandable_unit(file_size, understanable_file_size);

		sprintf(full_phr_ownername, "%s.%s", authority_name, phr_ownername);

		// Add a requested restricted-level PHR list to table
		add_requested_restricted_phr_tracking_list_to_table_handler_callback(full_phr_ownername, data_description, understanable_file_size, 
			approvals, threshold_value, request_status, phr_id, emergency_server_ip_addr);
		
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

boolean update_restricted_phr_list(char *emergency_server_ip_addr, char *authority_name, char *phr_ownername, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_restricted_phr_to_table_callback_handler_ptr)(), 
	void (*add_restricted_phr_list_to_table_callback_handler_ptr)(char *data_description, char *file_size, unsigned int approvals, unsigned int threshold_value, 
	char *request_status, unsigned int phr_id))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler                = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler          = backend_fatal_alert_msg_callback_handler_ptr;
	clear_restricted_phr_to_table_callback_handler    = clear_restricted_phr_to_table_callback_handler_ptr;
	add_restricted_phr_list_to_table_callback_handler = add_restricted_phr_list_to_table_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int file_size;
	char         understanable_file_size[UNDERSTANDABLE_FILE_SIZE_LENGTH + 1];

	char         approvals_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int approvals;

	char         threshold_value_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int threshold_value;

	char         request_status[RESTRICTED_PHR_REQUEST_STATUS_LENGTH + 1];

	char         is_end_of_restricted_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_restricted_phr_list_flag;

	// Connect to Emergency Server of the target authority
	if(!connect_to_emergency_phr_list_loading_service(emergency_server_ip_addr, authority_name, &ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", ONLY_RESTRICTED_LEVEL_PHR_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send the restricted-level PHR list loading information
	write_token_into_buffer("phr_ownername", phr_ownername, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the restricted-level PHR list loading information failed");
		goto ERROR;
	}

	// Clear a restricted-level PHR table
	clear_restricted_phr_to_table_handler_callback();

	// Restricted-level PHRs
	while(1)
	{
		// Receive restricted-level PHR information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving restricted-level PHR information failed");
			goto ERROR;
		}

		// Get restricted-level PHR information tokens from buffer
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

		file_size = atoi(file_size_str_tmp);

		if(read_token_from_buffer(buffer, 5, token_name, approvals_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "approvals") != 0)
		{
			int_error("Extracting the approvals failed");
		}

		approvals = atoi(approvals_str_tmp);

		if(read_token_from_buffer(buffer, 6, token_name, threshold_value_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "threshold_value") != 0)
		{
			int_error("Extracting the threshold_value failed");
		}

		threshold_value = atoi(threshold_value_str_tmp);

		if(read_token_from_buffer(buffer, 7, token_name, request_status) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_status") != 0)
		{
			int_error("Extracting the request_status failed");
		}

		// Convert file size in byte unit to understandable unit
		convert_file_size_to_understandable_unit(file_size, understanable_file_size);

		// Add a restricted-level PHR list to table
		add_restricted_phr_list_to_table_handler_callback(data_description, understanable_file_size, approvals, threshold_value, request_status, phr_id);
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

boolean update_requested_restricted_phr_list(char *authority_name, char *emergency_server_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_requested_restricted_phr_tracking_table_callback_handler_ptr)(), 
	void (*add_requested_restricted_phr_tracking_list_to_table_callback_handler_ptr)(char *full_phr_ownername, char *data_description, char *file_size, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id, char *emergency_server_ip_addr))
{
	// Setup a callback handler
	clear_requested_restricted_phr_tracking_table_callback_handler = clear_requested_restricted_phr_tracking_table_callback_handler_ptr;

	// Clear a requested restricted-level PHR tracking table
	clear_requested_restricted_phr_tracking_table_handler_callback();

	return load_requested_restricted_phr_list(authority_name, emergency_server_ip_addr, backend_alert_msg_callback_handler_ptr, 
		backend_fatal_alert_msg_callback_handler_ptr, add_requested_restricted_phr_tracking_list_to_table_callback_handler_ptr);
}



