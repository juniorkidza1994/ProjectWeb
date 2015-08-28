#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH            "Client_cache/client_phr_uploading.calculating_ssl_cert_hash"
#define CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH "Client_cache/client_phr_uploading.calculating_full_phr_owner_name_hash"
#define SGN_ACCESS_GRANTING_TICKET_PATH           "Client_cache/client_phr_uploading.sgn_access_granting_ticket"

#define LARGE_FILE_BUF_SIZE 		           1000000  // Include null-terminated character
#define LARGE_FILE_PREFIX_SIZE 		           7	    // Exclude null-terminated character
#define LARGE_FILE_MAX_DATA_DIGIT_LENGTH           6

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                         = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                   = NULL;
static void (*update_sent_progression_callback_handler)(unsigned int percent)              = NULL;
static void (*update_remote_site_phr_id_callback_handler)(unsigned int remote_site_phr_id) = NULL;

static sem_t   send_signal_to_confirm_cancellation_thread_mutex;
static sem_t   cancellation_thread_got_confirmation_mutex;
static boolean phr_uploading_cancellation_flag;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void update_sent_progression_handler_callback(unsigned int percent);
static void update_remote_site_phr_id_handler_callback(unsigned int remote_site_phr_id);
boolean SSL_send_phr_file(SSL *peer, char *file_path);
static boolean connect_to_phr_uploading_service(SSL **ssl_conn_ret);
static boolean upload_phr_main(char *phr_owner_name, char *phr_owner_authority_name, char *data_description, char *confidentiality_level_flag);
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

static void update_sent_progression_handler_callback(unsigned int percent)
{
	if(update_sent_progression_callback_handler)
	{
		update_sent_progression_callback_handler(percent);
	}
	else  // NULL
	{
		int_error("update_sent_progression_callback_handler is NULL");
	}
}

static void update_remote_site_phr_id_handler_callback(unsigned int remote_site_phr_id)
{
	if(update_remote_site_phr_id_callback_handler)
	{
		update_remote_site_phr_id_callback_handler(remote_site_phr_id);
	}
	else  // NULL
	{
		int_error("update_remote_site_phr_id_callback_handler is NULL");
	}
}

boolean SSL_send_phr_file(SSL *peer, char *file_path)
{
	FILE         *fp  = NULL;
	char         *buf = NULL;	                  // Include null-terminated character
	char         prefix[LARGE_FILE_PREFIX_SIZE + 1];  // Exclude null-terminated character
	unsigned int nread;
	unsigned int read_length;
	int          ret_code;

	unsigned int file_size;
	unsigned int nsent = 0;
	float        sent_percent;

	if(!get_file_size(file_path, &file_size))
		goto ERROR;

	fp = fopen(file_path, "rb");
	if(!fp)
		goto ERROR;

	// Allocate heap variable
	buf = (char *)malloc(sizeof(char)*LARGE_FILE_BUF_SIZE);
	if(!buf)
	{
		int_error("Allocating memory for \"buf\" failed");
	}

	while(!feof(fp))
	{
		if(phr_uploading_cancellation_flag)
			goto OPERATION_HAS_BEEN_CANCELLED;

		// Read data from file
		read_length = 0;
		while(!feof(fp) && read_length < (LARGE_FILE_BUF_SIZE - LARGE_FILE_PREFIX_SIZE))
		{
	  		nread = fread(buf + LARGE_FILE_PREFIX_SIZE + read_length, 1, LARGE_FILE_BUF_SIZE - LARGE_FILE_PREFIX_SIZE - read_length, fp);
			read_length += nread;

			if(nread == 0 && ferror(fp))
				int_error("fread() failed");
		}

		if(phr_uploading_cancellation_flag)
			goto OPERATION_HAS_BEEN_CANCELLED;

		// Send data to peer
		sprintf(prefix, "0%06d", read_length);		// '0' at first character means the data segment isn't the end of file
		memcpy(buf, prefix, LARGE_FILE_PREFIX_SIZE);
		
		ret_code = SSL_send(peer, buf, LARGE_FILE_BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			goto ERROR;
		}

		if(phr_uploading_cancellation_flag)
			goto OPERATION_HAS_BEEN_CANCELLED;

		nsent        += read_length;
		sent_percent =  ((float)nsent)/file_size*100.0F;
		update_sent_progression_handler_callback(sent_percent);
	}

	fclose(fp);
	fp = NULL;

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of file
	ret_code = SSL_send(peer, buf, LARGE_FILE_BUF_SIZE);

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	if(ret_code != SSL_ERROR_NONE)
	{
		// Transmission error occurred
		goto ERROR;
	}
	else
	{
		return true;
	}

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	if(fp)
	{
		fclose(fp);
		fp = NULL;
	}

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	return false;
}

static boolean connect_to_phr_uploading_service(SSL **ssl_conn_ret)
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

static boolean upload_phr_main(char *phr_owner_name, char *phr_owner_authority_name, char *data_description, char *confidentiality_level_flag)
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

	char         phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	boolean      phr_uploading_status;

	// Connect to PHR Server
	if(!connect_to_phr_uploading_service(&ssl_conn))
		goto ERROR;

	if(phr_uploading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Send PHR uploading information
	write_token_into_buffer("desired_phr_owner_name", phr_owner_name, true, buffer);
	write_token_into_buffer("desired_phr_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("required_operation", PHR_UPLOADING, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending PHR uploading information failed");
		goto ERROR;
	}

	if(phr_uploading_cancellation_flag)
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

	if(phr_uploading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Send the access granting ticket
	if(!SSL_send_file(ssl_conn, SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		backend_alert_msg_handler_callback("Sending the access granting ticket failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	if(phr_uploading_cancellation_flag)
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

	if(phr_uploading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Send a data description information
	write_token_into_buffer("data_description", data_description, true, buffer);
	write_token_into_buffer("phr_conf_level_flag", confidentiality_level_flag, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending a data description failed");
		goto ERROR;
	}

	if(phr_uploading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	// Upload the PHR
	phr_uploading_status = SSL_send_phr_file(ssl_conn, ENCRYPTED_PHR_TARGET_FILE_PATH);

	if(phr_uploading_cancellation_flag)
		goto OPERATION_HAS_BEEN_CANCELLED;

	if(!phr_uploading_status && !phr_uploading_cancellation_flag)
	{
		backend_alert_msg_callback_handler("Sending the PHR file failed");
		goto ERROR;
	}

	// Receive a PHR id
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a PHR id failed");
		goto ERROR;
	}

	// Get a PHR id token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
	{
		int_error("Extracting the phr_id failed");
	}

	phr_id = atoi(phr_id_str);
	update_remote_site_phr_id_handler_callback(phr_id);

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return phr_uploading_status;

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

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

	phr_uploading_cancellation_flag = false;
}

static void uninit_main()
{
	if(sem_destroy(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Destroying a mutex failed");
}

boolean upload_phr(char *phr_owner_name, char *phr_owner_authority_name, char *data_description, char *confidentiality_level_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*update_sent_progression_callback_handler_ptr)(unsigned int percent), void (*update_remote_site_phr_id_callback_handler_ptr)(
	unsigned int remote_site_phr_id))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler         = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler   = backend_fatal_alert_msg_callback_handler_ptr;
	update_sent_progression_callback_handler   = update_sent_progression_callback_handler_ptr;
	update_remote_site_phr_id_callback_handler = update_remote_site_phr_id_callback_handler_ptr;

	boolean uploading_status;

	init_main();

	// Upload the PHR
	uploading_status = upload_phr_main(phr_owner_name, phr_owner_authority_name, data_description, confidentiality_level_flag);

	// Send signal to confirm that the upload operation has been cancelled if the action was performed by a cancellation thread
	if(phr_uploading_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");
	}

	unlink(ENCRYPTED_PHR_TARGET_FILE_PATH);

	uninit_main();
	return uploading_status;
}

void cancel_phr_uploading()
{
	phr_uploading_cancellation_flag = true;

	// Wait for the confirmation
	if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Unlocking the mutex failed");
}



