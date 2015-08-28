#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH            "Client_cache/client_phr_downloading.calculating_ssl_cert_hash"
#define CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH "Client_cache/client_phr_downloading.calculating_full_phr_owner_name_hash"
#define SGN_ACCESS_GRANTING_TICKET_PATH           "Client_cache/client_phr_downloading.sgn_access_granting_ticket"

#define LARGE_FILE_BUF_SIZE 		           1000000  // Include null-terminated character
#define LARGE_FILE_PREFIX_SIZE 		           7	    // Exclude null-terminated character
#define LARGE_FILE_MAX_DATA_DIGIT_LENGTH           6

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)          = NULL;
static void (*update_received_progression_callback_handler)(unsigned int percent) = NULL;

// Local Variables
static sem_t   send_signal_to_confirm_cancellation_thread_mutex;
static sem_t   cancellation_thread_got_confirmation_mutex;
static boolean phr_downloading_cancellation_flag;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void update_received_progression_handler_callback(unsigned int percent);
static boolean SSL_recv_phr_file(SSL *peer, char *file_path);
static boolean connect_to_phr_downloading_service(SSL **ssl_conn_ret);
static boolean download_phr_main(char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id);
static void init_main();
static void uninit_main();

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

static void update_received_progression_handler_callback(unsigned int percent)
{
	if(update_received_progression_callback_handler)
	{
		update_received_progression_callback_handler(percent);
	}
	else  // NULL
	{
		int_error("update_received_progression_callback_handler is NULL");
	}
}

static boolean SSL_recv_phr_file(SSL *peer, char *file_path)
{
	unlink(file_path);

	char         *buf = NULL;  // Include null-terminated character
	unsigned int data_len;
	char         data_len_str[LARGE_FILE_MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int file_size;
	unsigned int nreceived = 0;
	float        received_percent;

	// Allocate heap variable
	buf = (char *)malloc(sizeof(char)*LARGE_FILE_BUF_SIZE);
	if(!buf)
	{
		int_error("Allocating memory for \"buf\" failed");
	}

	// Receive the PHR file size
	if(SSL_recv_buffer(peer, buffer, NULL) == 0)
		goto ERROR;

	// Get the PHR file size token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, file_size_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "file_size") != 0)
	{
		int_error("Extracting the file_size failed");
	}

	file_size = atoi(file_size_str_tmp);

	for(;;)
    	{
		if(phr_downloading_cancellation_flag)
			goto OPERATION_HAS_BEEN_CANCELLED;

		// Read data from peer
		ret_code = SSL_recv(peer, buf, LARGE_FILE_BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			goto ERROR;
		}

		if(buf[0] == '1')    	// End of file
			break;

		memcpy(data_len_str, buf + 1, LARGE_FILE_MAX_DATA_DIGIT_LENGTH);
		data_len_str[LARGE_FILE_MAX_DATA_DIGIT_LENGTH] = 0;

		if(phr_downloading_cancellation_flag)
			goto OPERATION_HAS_BEEN_CANCELLED;
	
		// Write data to file
		data_len = atoi(data_len_str);
		if(!write_bin_file(file_path, "ab", buf + LARGE_FILE_PREFIX_SIZE, data_len))
		{
			// Writing file failed
			goto ERROR;
		}

		nreceived        += data_len;
		received_percent =  ((float)nreceived)/file_size*100.0F;
		update_received_progression_handler_callback(received_percent);
    	}

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	return true;

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	return false;
}

static boolean connect_to_phr_downloading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    phr_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to PHR Server
	sprintf(phr_server_addr, "%s:%s", GLOBAL_phr_server_ip_addr, PHRSV_PHR_SERVICES_PORT);
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

static boolean download_phr_main(char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    phr_access_permission_verification_result_flag_str_tmp[FLAG_LENGTH + 1];     // "0" or "1"
	boolean phr_access_permission_verification_result_flag;

	char    err_msg[ERR_MSG_LENGTH + 1];
	char    full_phr_owner_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 1];
	char    full_phr_owner_name_hash[SHA1_DIGEST_LENGTH + 1];
	char    access_granting_ticket_path[PATH_LENGTH + 1];

	char    phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	char    is_requested_phr_available_to_download_flag_str_tmp[FLAG_LENGTH + 1];        // "0" or "1"
	boolean is_requested_phr_available_to_download_flag;

	boolean phr_downloading_status;

	// Connect to PHR Server
	if(!connect_to_phr_downloading_service(&ssl_conn))
		goto ERROR;

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Send PHR downloading information
	write_token_into_buffer("desired_phr_owner_name", phr_owner_name, true, buffer);
	write_token_into_buffer("desired_phr_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("required_operation", PHR_DOWNLOADING, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending PHR downloading information failed");
		goto ERROR;
	}

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

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

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Send the access granting ticket
	if(!SSL_send_file(ssl_conn, SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		backend_alert_msg_handler_callback("Sending the access granting ticket failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Receive a PHR access permission verification result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a PHR access permission verification result flag failed");
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

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Send the PHR id information
	sprintf(phr_id_str, "%u", phr_id);
	write_token_into_buffer("phr_id", phr_id_str, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending PHR id information failed");
		goto ERROR;
	}

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Receive the "is_requested_phr_available_to_download_flag"
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving the is_requested_phr_available_to_download_flag failed");
		goto ERROR;
	}

	// Get the is_requested_phr_available_to_download_flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, is_requested_phr_available_to_download_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_requested_phr_available_to_download_flag") != 0)
	{
		int_error("Extracting the is_requested_phr_available_to_download_flag failed");
	}

	is_requested_phr_available_to_download_flag = (strcmp(is_requested_phr_available_to_download_flag_str_tmp, "1") == 0) ? true : false;
	if(!is_requested_phr_available_to_download_flag)
	{
		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(err_msg);
		goto ERROR;
	}

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Download the PHR
	phr_downloading_status = SSL_recv_phr_file(ssl_conn, DECRYPTED_PHR_TARGET_FILE_PATH);

	if(phr_downloading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	if(!phr_downloading_status && !phr_downloading_cancellation_flag)
	{
		backend_alert_msg_callback_handler("Receiving the PHR file failed");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return phr_downloading_status;

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(DECRYPTED_PHR_TARGET_FILE_PATH);

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

static void init_main()
{	
	// Initial the signal transmissters
	if(sem_init(&send_signal_to_confirm_cancellation_thread_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");

	if(sem_init(&cancellation_thread_got_confirmation_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");

	phr_downloading_cancellation_flag = false;
}

static void uninit_main()
{
	if(sem_destroy(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Destroying a mutex failed");
}

boolean download_phr(char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*update_received_progression_callback_handler_ptr)(unsigned int percent))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler           = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler     = backend_fatal_alert_msg_callback_handler_ptr;
	update_received_progression_callback_handler = update_received_progression_callback_handler_ptr;

	boolean downloading_status;

	init_main();

	// Download the PHR
	downloading_status = download_phr_main(phr_owner_name, phr_owner_authority_name, phr_id);

	// Send signal to confirm that the download operation has been cancelled if the action was performed by a cancellation thread
	if(phr_downloading_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");
	}

	uninit_main();
	return downloading_status;
}

void cancel_phr_downloading()
{
	phr_downloading_cancellation_flag = true;

	// Wait for the confirmation
	if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Unlocking the mutex failed");
}



