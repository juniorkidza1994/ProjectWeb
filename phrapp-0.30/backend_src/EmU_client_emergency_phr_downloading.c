#include "EmU_client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH   "EmU_client_cache/EmU_client_emergency_phr_downloading.calculating_ssl_cert_hash"

#define LARGE_FILE_BUF_SIZE 		 1000000  // Include null-terminated character
#define LARGE_FILE_PREFIX_SIZE 		 7	  // Exclude null-terminated character
#define LARGE_FILE_MAX_DATA_DIGIT_LENGTH 6

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                              = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                        = NULL;
static void (*set_emergency_phr_ems_side_processing_success_state_callback_handler)()           = NULL;
static void (*update_emergency_phr_received_progression_callback_handler)(unsigned int percent) = NULL;

// Local Variables
static SSL         *ssl_conn = NULL;
static char        **ptr_target_emergency_server_ip_addr;

// These variables are used during waiting for processing at the emergency server only
static sem_t       wake_up_main_thread_mutex;
static sem_t       confirm_err_msg_sending_to_frontend_mutex;
static char        err_msg_to_frontend[ERR_MSG_LENGTH + 1];
static boolean     waiting_server_processing_thread_terminated_flag;
static boolean     waiting_server_processing_success_status_flag;

static THREAD_TYPE waiting_server_processing_thread_id;
static boolean     waiting_server_processing_flag;
static boolean     emergency_phr_downloading_flag;

// These variables are used for both waiting the processing at the emergency server 
// and during the downloading emergency PHR from the emergency server to a client
static sem_t       send_signal_to_confirm_cancellation_thread_mutex;
static sem_t       cancellation_thread_got_confirmation_mutex;
static boolean     emergency_phr_downloading_cancellation_flag;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void set_emergency_phr_ems_side_processing_success_state_handler_callback();
static void update_emergency_phr_received_progression_handler_callback(unsigned int percent);
static boolean SSL_recv_phr_file(SSL *peer, char *file_path);
static boolean connect_to_emergency_phr_downloading_service(char *authority_name, SSL **ssl_conn_ret);
static void init_main();
static void uninit_main();
static void set_waiting_server_processing_flag(boolean flag);
static boolean get_waiting_server_processing_flag();
static void set_emergency_phr_downloading_flag(boolean flag);
static boolean get_emergency_phr_downloading_flag();
static void tell_waiting_server_processing_thread_terminates();
static void send_error_msg_to_frontend(char *error_msg);
static void *wait_server_processing_main(void *arg);

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

static void set_emergency_phr_ems_side_processing_success_state_handler_callback()
{
	if(set_emergency_phr_ems_side_processing_success_state_callback_handler)
	{
		set_emergency_phr_ems_side_processing_success_state_callback_handler();
	}
	else  // NULL
	{
		int_error("set_emergency_phr_ems_side_processing_success_state_callback_handler is NULL");
	}
}

static void update_emergency_phr_received_progression_handler_callback(unsigned int percent)
{
	if(update_emergency_phr_received_progression_callback_handler)
	{
		update_emergency_phr_received_progression_callback_handler(percent);
	}
	else  // NULL
	{
		int_error("update_emergency_phr_received_progression_callback_handler is NULL");
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
		if(emergency_phr_downloading_cancellation_flag)
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

		if(emergency_phr_downloading_cancellation_flag)
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
		update_emergency_phr_received_progression_handler_callback(received_percent);
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

static boolean connect_to_emergency_phr_downloading_service(char *authority_name, SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to emergency Server
	sprintf(emergency_server_addr, "%s:%s", *ptr_target_emergency_server_ip_addr, EMS_EMERGENCY_PHR_ACCESSING_PORT);
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
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, authority_name)) != X509_V_OK)
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

static void init_main()
{
	// Initial the signal transmissters
	if(sem_init(&wake_up_main_thread_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");

	if(sem_init(&confirm_err_msg_sending_to_frontend_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");
	
	if(sem_init(&send_signal_to_confirm_cancellation_thread_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");

	if(sem_init(&cancellation_thread_got_confirmation_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");

	strcpy(err_msg_to_frontend, "");
	waiting_server_processing_thread_terminated_flag = false;
	waiting_server_processing_success_status_flag    = false; 
	emergency_phr_downloading_cancellation_flag      = false;

	set_waiting_server_processing_flag(false);
	set_emergency_phr_downloading_flag(false);
}

static void uninit_main()
{
	if(sem_destroy(&wake_up_main_thread_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&confirm_err_msg_sending_to_frontend_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Destroying a mutex failed");
}

static void set_waiting_server_processing_flag(boolean flag)
{
	waiting_server_processing_flag = flag;
}

static boolean get_waiting_server_processing_flag()
{
	return waiting_server_processing_flag;
}

static void set_emergency_phr_downloading_flag(boolean flag)
{
	emergency_phr_downloading_flag = flag;
}

static boolean get_emergency_phr_downloading_flag()
{
	return emergency_phr_downloading_flag;
}

// Tell the main thread that the waiting server processing thread terminates
static void tell_waiting_server_processing_thread_terminates()
{
	waiting_server_processing_thread_terminated_flag = true;
	
	// Wake up the main thread in order to quit the infinite loop
	if(sem_post(&wake_up_main_thread_mutex) != 0)
		int_error("Unlocking the mutex failed");
}

static void send_error_msg_to_frontend(char *error_msg)
{
	strcpy(err_msg_to_frontend, error_msg);

	// Wake up the main thread in order to send an error message to frontend
	if(sem_post(&wake_up_main_thread_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Wait for the confirmation
	if(sem_wait(&confirm_err_msg_sending_to_frontend_mutex) != 0)
		int_error("Locking the mutex failed");
}

static void *wait_server_processing_main(void *arg)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    token_value[TOKEN_VALUE_LENGTH + 1];

	char    emergency_phr_processing_success_flag_str_tmp[FLAG_LENGTH + 1];
	boolean emergency_phr_processing_success_flag;

	while(1)
	{
		// Receive the "ask_connection_still_alive" or "emergency_phr_processing_success_flag"
		if(!SSL_recv_buffer(ssl_conn, buffer, NULL))
		{
			send_error_msg_to_frontend("Receiving the ask_connection_still_alive or emergency_phr_processing_success_flag failed");

			waiting_server_processing_success_status_flag = false;
			goto ERROR;
		}

		// Out of this loop if we got the "emergency_phr_processing_success_flag"
		if(read_token_from_buffer(buffer, 1, token_name, token_value) == READ_TOKEN_SUCCESS && 
			strcmp(token_name, "emergency_phr_processing_success_flag") == 0)
		{
			break;
		}

		// Send the "ask_connection_still_alive" back to the server again to tell that the client still alive
		if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
		{
			send_error_msg_to_frontend("Sending the ask_connection_still_alive failed");

			waiting_server_processing_success_status_flag = false;
			goto ERROR;
		}
	}

	// Get the emergency_phr_processing_success_flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, emergency_phr_processing_success_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_phr_processing_success_flag") != 0)
	{
		int_error("Extracting the emergency_phr_processing_success_flag failed");
	}

	emergency_phr_processing_success_flag = (strcmp(emergency_phr_processing_success_flag_str_tmp, "1") == 0) ? true : false;
	if(!emergency_phr_processing_success_flag)
	{
		char err_msg[ERR_MSG_LENGTH + 1];

		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
		{
			int_error("Extracting the error_msg failed");
		}

		send_error_msg_to_frontend(err_msg);

		waiting_server_processing_success_status_flag = false;
		goto ERROR;
	}

	waiting_server_processing_success_status_flag = true;	

ERROR:

	tell_waiting_server_processing_thread_terminates();
	pthread_exit(NULL);
	return NULL;
}

boolean download_emergency_phr(char *target_emergency_server_ip_addr, char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id, char *phr_description, 
	boolean is_restricted_level_phr_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*set_emergency_phr_ems_side_processing_success_state_callback_handler_ptr)(), 
	void (*update_emergency_phr_received_progression_callback_handler_ptr)(unsigned int percent))
{
	// Setup allback handlers
	backend_alert_msg_callback_handler                                   = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler                             = backend_fatal_alert_msg_callback_handler_ptr;
	set_emergency_phr_ems_side_processing_success_state_callback_handler = set_emergency_phr_ems_side_processing_success_state_callback_handler_ptr;
	update_emergency_phr_received_progression_callback_handler           = update_emergency_phr_received_progression_callback_handler_ptr;

	// Passing variable
	ptr_target_emergency_server_ip_addr = &target_emergency_server_ip_addr;

	char    buffer[BUFFER_LENGTH + 1];
	char    phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	boolean emergency_phr_downloading_status;

	init_main();
	set_waiting_server_processing_flag(false);
	set_emergency_phr_downloading_flag(false);

	// Connect to the emergency server
	if(!connect_to_emergency_phr_downloading_service(phr_owner_authority_name, &ssl_conn))
		goto ERROR;

	// Send request type information
	write_token_into_buffer("request_type", (is_restricted_level_phr_flag) ? RESTRICTED_LEVEL_PHR_ACCESSING : SECURE_LEVEL_PHR_ACCESSING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request type information failed");
		goto ERROR;
	}

	sprintf(phr_id_str_tmp, "%u", phr_id);

	// Send the requested emergency PHR information
	write_token_into_buffer("desired_phr_owner_name", phr_owner_name, true, buffer);
	write_token_into_buffer("phr_id", phr_id_str_tmp, false, buffer);
	write_token_into_buffer("phr_description", phr_description, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the requested emergency PHR information failed");
		goto ERROR;
	}

	// Create a waiting server processing thread
	if(THREAD_CREATE(waiting_server_processing_thread_id, wait_server_processing_main, NULL) != 0)
		int_error("Creating a thread for \"wait_server_processing_main\" failed");

	set_waiting_server_processing_flag(true);

	while(1)
	{
		if(sem_wait(&wake_up_main_thread_mutex) != 0)
			int_error("Locking the mutex failed");

		// The waiting server processing thread terminated
		if(waiting_server_processing_thread_terminated_flag)
			break;

		// Send an error message to frontend
		if(strlen(err_msg_to_frontend) > 0)
		{
			backend_alert_msg_handler_callback(err_msg_to_frontend);
			strcpy(err_msg_to_frontend, "");

			if(sem_post(&confirm_err_msg_sending_to_frontend_mutex) != 0)
				int_error("Unlocking the mutex failed");
		}
	}

	set_waiting_server_processing_flag(false);

	// Join the waiting server processing thread
	if(THREAD_JOIN(waiting_server_processing_thread_id) != 0)
		int_error("Joining a thread \"wait_server_processing_main\" failed");

	// Send signal to confirm that the waiting server processing thread has been terminated if the action was performed by a cancellation thread
	if(emergency_phr_downloading_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");

		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	if(!waiting_server_processing_success_status_flag)
	{
		goto ERROR;
	}

	set_emergency_phr_ems_side_processing_success_state_handler_callback();
	set_emergency_phr_downloading_flag(true);

	// Download the emergency PHR
	emergency_phr_downloading_status = SSL_recv_phr_file(ssl_conn, UNARCHIVED_EMERGENCY_PHR_TARGET_FILE_PATH);

	if(!emergency_phr_downloading_status && !emergency_phr_downloading_cancellation_flag)
	{
		char err_msg[ERR_MSG_LENGTH + 1];

		sprintf(err_msg, "Receiving the %s-level PHR file failed", (is_restricted_level_phr_flag) ? "restricted" : "secure");
		backend_alert_msg_callback_handler(err_msg);
		goto ERROR;
	}

	set_emergency_phr_downloading_flag(false);

	// Send signal to confirm that the download operation has been cancelled if the action was performed by a cancellation thread
	if(emergency_phr_downloading_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");

		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	uninit_main();
	return true;

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	set_emergency_phr_downloading_flag(false);
	set_waiting_server_processing_flag(false);

	unlink(UNARCHIVED_EMERGENCY_PHR_TARGET_FILE_PATH);

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	uninit_main();
	return false;
}

void cancel_emergency_phr_downloading()
{
	if(get_waiting_server_processing_flag())
	{
		emergency_phr_downloading_cancellation_flag = true;

		// Cancel the PHR decryption thread
		if(THREAD_CANCEL(waiting_server_processing_thread_id) != 0)
	    		int_error("Cancelling a thread \"wait_server_processing_main\" failed");

		tell_waiting_server_processing_thread_terminates();

		// Wait for the confirmation
		if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Locking the mutex failed");

		if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Unlocking the mutex failed");
	}
	else if(get_emergency_phr_downloading_flag())
	{
		emergency_phr_downloading_cancellation_flag = true;

		// Wait for the confirmation
		if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Locking the mutex failed");

		if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Unlocking the mutex failed");
	}
}



