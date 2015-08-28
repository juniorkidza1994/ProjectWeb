#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH            "Client_cache/client_authorized_phr_list_loading.calculating_ssl_cert_hash"
#define CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH "Client_cache/client_authorized_phr_list_loading.calculating_full_phr_owner_name_hash"
#define SGN_ACCESS_GRANTING_TICKET_PATH           "Client_cache/client_authorized_phr_list_loading.sgn_access_granting_ticket"

#define UNDERSTANDABLE_FILE_SIZE_LENGTH           11

const char PHR_CONF_LEVEL_STR[][11] = {"secure", "restricted", "exclusive"};

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                          = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                    = NULL;
static void (*add_authorized_phr_list_to_table_callback_handler)(
	char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void add_authorized_phr_list_to_table_handler_callback(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id);

static void convert_file_size_to_understandable_unit(unsigned int file_size, char *understanable_file_size_ret);
static boolean connect_to_authorized_phr_list_loading_service(SSL **ssl_conn_ret);
static const char *convert_phr_conf_level_flag_to_str(char *phr_conf_level_flag);
static boolean load_authorized_phr_list(char *phr_owner_name, char *phr_owner_authority_name, char *required_operation);

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

static void add_authorized_phr_list_to_table_handler_callback(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id)
{
	if(add_authorized_phr_list_to_table_callback_handler)
	{
		add_authorized_phr_list_to_table_callback_handler(data_description, file_size, phr_conf_level, phr_id);
	}
	else  // NULL
	{
		int_error("add_authorized_phr_list_to_table_callback_handler is NULL");
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

static boolean connect_to_authorized_phr_list_loading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    phr_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to PHR Server
	sprintf(phr_server_addr, "%s:%s", GLOBAL_phr_server_ip_addr, PHRSV_AUTHORIZED_PHR_LIST_LOADING_PORT);
	bio_conn = BIO_new_connect(phr_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to PHR server failed");
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

	hosts[0] = PHR_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, false, NULL)) != X509_V_OK)
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

static const char *convert_phr_conf_level_flag_to_str(char *phr_conf_level_flag)
{
	return (const char *)PHR_CONF_LEVEL_STR[atoi(phr_conf_level_flag)];
}

static boolean load_authorized_phr_list(char *phr_owner_name, char *phr_owner_authority_name, char *required_operation)
{
	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         phr_access_permission_verification_result_flag_str_tmp[FLAG_LENGTH + 1];     // "0" or "1"
	boolean      phr_access_permission_verification_result_flag;

	char         err_msg[ERR_MSG_LENGTH + 1];
	char         full_phr_owner_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 1];
	char         full_phr_owner_name_hash[SHA1_DIGEST_LENGTH + 1];
	char         access_granting_ticket_path[PATH_LENGTH + 1];

	char         is_end_of_authorized_phr_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_authorized_phr_list_flag;
	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int file_size;
	char         understanable_file_size[UNDERSTANDABLE_FILE_SIZE_LENGTH + 1];
	char	     phr_conf_level_flag[FLAG_LENGTH + 1];   // 0 - secure level, 1 - restricted level, 2 - exclusive level

	boolean      found_phr_flag = false;

	// Connect to PHR Server
	if(!connect_to_authorized_phr_list_loading_service(&ssl_conn))
		goto ERROR;

	// Send authorized PHR list loading information
	write_token_into_buffer("desired_phr_owner_name", phr_owner_name, true, buffer);
	write_token_into_buffer("desired_phr_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("required_operation", required_operation, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending authorized PHR list loading information failed");
		goto ERROR;
	}

	// Generate an access granting ticket path
	sprintf(full_phr_owner_name, "%s%s", phr_owner_authority_name, phr_owner_name);
	sum_sha1_from_string(full_phr_owner_name, strlen(full_phr_owner_name), full_phr_owner_name_hash, CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH);
	sprintf(access_granting_ticket_path, "%s/%s", CACHE_DIRECTORY_PATH, full_phr_owner_name_hash);

	if(!file_exists(access_granting_ticket_path))
	{
		backend_fatal_alert_msg_handler_callback("The access granting ticket does not exist");
		goto ERROR;
	}

	// Decrypt the access granting ticket with the user's password
	if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
		backend_fatal_alert_msg_handler_callback("Decrypting the access granting ticket failed");
		goto ERROR;
	}

	// Send the access granting ticket
	if(!SSL_send_file(ssl_conn, SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		backend_alert_msg_handler_callback("Sending the access granting ticket failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Receive a PHR access permission verification result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a PHR access permission verification result failed");
		goto ERROR;
	}

	// Get a PHR access permission verification result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_access_permission_verification_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_access_permission_verification_result_flag") != 0)
	{
		int_error("Extracting the phr_access_permission_verification_result_flag failed");
	}

	phr_access_permission_verification_result_flag = (strcmp(phr_access_permission_verification_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!phr_access_permission_verification_result_flag)
	{
		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(err_msg);
		goto ERROR;
	}

	while(1)
	{
		// Receive authorized PHR information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving authorized PHR information failed");
			goto ERROR;
		}

		// Get authorized PHR information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_authorized_phr_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_authorized_phr_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_authorized_phr_list_flag failed");
		}

		is_end_of_authorized_phr_list_flag = (strcmp(is_end_of_authorized_phr_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_authorized_phr_list_flag)
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

		if(read_token_from_buffer(buffer, 5, token_name, phr_conf_level_flag) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_conf_level_flag") != 0)
		{
			int_error("Extracting the phr_conf_level_flag failed");
		}

		file_size = atoi(file_size_str_tmp);

		// Convert file size in byte unit to understandable unit
		convert_file_size_to_understandable_unit(file_size, understanable_file_size);

		// Add an authorized PHR list to table
		add_authorized_phr_list_to_table_handler_callback(data_description, understanable_file_size, 
			(char *)convert_phr_conf_level_flag_to_str(phr_conf_level_flag), phr_id);

		found_phr_flag = true;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	if(!found_phr_flag)
	{
		backend_alert_msg_handler_callback("Do not have any PHR stored on a PHR server");
	}

	return true;

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

boolean load_downloading_authorized_phr_list(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_authorized_phr_list_to_table_callback_handler_ptr)
	(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler                = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler          = backend_fatal_alert_msg_callback_handler_ptr;
	add_authorized_phr_list_to_table_callback_handler = add_authorized_phr_list_to_table_callback_handler_ptr;

	return load_authorized_phr_list(phr_owner_name, phr_owner_authority_name, PHR_DOWNLOADING);
}

boolean load_deletion_authorized_phr_list(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_authorized_phr_list_to_table_callback_handler_ptr)
	(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler                = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler          = backend_fatal_alert_msg_callback_handler_ptr;
	add_authorized_phr_list_to_table_callback_handler = add_authorized_phr_list_to_table_callback_handler_ptr;

	return load_authorized_phr_list(phr_owner_name, phr_owner_authority_name, PHR_DELETION);
}



