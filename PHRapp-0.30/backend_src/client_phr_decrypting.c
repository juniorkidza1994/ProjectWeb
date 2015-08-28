#include "client_common.h"

#define CALCULATING_CPABE_PRIV_KEY_HASH_PATH "Client_cache/client_phr_decrypting.calculating_cpabe_priv_key_hash"

#define UNARCHIVED_PHR_TARGET_FILE_PATH      "Client_cache/decrypted_phr_target_file.tar"					
#define PLNT_CPABE_PRIV_KEY_PATH             "Client_cache/client_phr_decrypting.plnt_cpabe_priv_key"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg) = NULL;

static char        **ptr_phr_download_to_path;

static sem_t       wake_up_main_thread_mutex;
static sem_t       confirm_err_msg_sending_to_frontend_mutex;
static char        err_msg_to_frontend[ERR_MSG_LENGTH + 1];
static boolean     phr_decryption_thread_terminated_flag;
static boolean     transaction_success_status_flag;

static sem_t       send_signal_to_confirm_cancellation_thread_mutex;
static sem_t       cancellation_thread_got_confirmation_mutex;
static boolean     phr_decrypting_cancellation_flag;

static THREAD_TYPE phr_decryption_thread_id;
static char        *shell_cmd;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void tell_phr_decryption_thread_terminates();
static void send_error_msg_to_frontend(char *error_msg);
static void init_phr_decryption();
static void uninit_phr_decryption(void *arg);
static void *decrypt_phr_main(void *arg);
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

// Tell the main thread that the PHR decryption thread terminates
static void tell_phr_decryption_thread_terminates()
{
	phr_decryption_thread_terminated_flag = true;
	
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

static void init_phr_decryption()
{
	// Allocate a heap variable
	shell_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!shell_cmd)
	{
		int_error("Allocating memory for \"shell_cmd\" failed");
	}

	unlink(UNARCHIVED_PHR_TARGET_FILE_PATH);
}

static void uninit_phr_decryption(void *arg)
{
	unlink(DECRYPTED_PHR_TARGET_FILE_PATH);
	unlink(UNARCHIVED_PHR_TARGET_FILE_PATH);
	unlink(PLNT_CPABE_PRIV_KEY_PATH);

	// Release memory
	free(shell_cmd);
}

static void *decrypt_phr_main(void *arg)
{
	char err_code[ERR_MSG_LENGTH + 1];

	init_phr_decryption();

	// Release heap allocated items even if this thread doesn't exit normally
	pthread_cleanup_push(uninit_phr_decryption, NULL);

	/* Hash value is used for verifying a CP-ABE private key to make sure that the key is the latest updated version, 
	   preventing a user uses the revoked key to feign to be a real one */
	if(!verify_file_integrity(CPABE_PRIV_KEY_PATH, GLOBAL_cpabe_priv_key_hash, CALCULATING_CPABE_PRIV_KEY_HASH_PATH))
	{
		fprintf(stderr, "Verifying the CP-ABE private key failed\n");
		send_error_msg_to_frontend("Verifying the CP-ABE private key failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	// Decrypt the CP-ABE private key with the user's password
	if(!des3_decrypt(CPABE_PRIV_KEY_PATH, PLNT_CPABE_PRIV_KEY_PATH, GLOBAL_passwd, err_code))
	{
		fprintf(stderr, "Decrypting the CP-ABE private key failed\n\"%s\"\n", err_code);
		send_error_msg_to_frontend("Decrypting the CP-ABE private key failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	// Decrypt the PHR
	sprintf(shell_cmd, "%s %s %s %s", CPABE_DEC_PATH, CPABE_PUB_KEY_PATH, PLNT_CPABE_PRIV_KEY_PATH, DECRYPTED_PHR_TARGET_FILE_PATH);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		fprintf(stderr, "Decrypting the PHR failed\n\"%s\"\n", err_code);
		send_error_msg_to_frontend("Decrypting the PHR failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	unlink(PLNT_CPABE_PRIV_KEY_PATH);
	unlink(DECRYPTED_PHR_TARGET_FILE_PATH);

	// Unarchive the PHR
	sprintf(shell_cmd, "tar -xf %s -C \"%s\"", UNARCHIVED_PHR_TARGET_FILE_PATH, *ptr_phr_download_to_path);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		fprintf(stderr, "Unarchieving the PHR failed\n\"%s\"\n", err_code);
		send_error_msg_to_frontend("Unarchieving the PHR failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	transaction_success_status_flag = true;	

ERROR:

	unlink(DECRYPTED_PHR_TARGET_FILE_PATH);
	unlink(UNARCHIVED_PHR_TARGET_FILE_PATH);
	unlink(PLNT_CPABE_PRIV_KEY_PATH);

	pthread_cleanup_pop(1);
	tell_phr_decryption_thread_terminates();
	pthread_exit(NULL);
	return NULL;
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
	phr_decryption_thread_terminated_flag = false;
	transaction_success_status_flag       = false; 
	phr_decrypting_cancellation_flag      = false;
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

boolean decrypt_phr(char *phr_download_to_path, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handler
	backend_alert_msg_callback_handler = backend_alert_msg_callback_handler_ptr;

	// Passing variable
	ptr_phr_download_to_path = &phr_download_to_path;

	init_main();

	// Create a PHR decryption thread
	if(THREAD_CREATE(phr_decryption_thread_id, decrypt_phr_main, NULL) != 0)
		int_error("Creating a thread for \"decrypt_phr_main\" failed");

	while(1)
	{
		if(sem_wait(&wake_up_main_thread_mutex) != 0)
			int_error("Locking the mutex failed");

		// The PHR decryption thread terminated
		if(phr_decryption_thread_terminated_flag)
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

	// Join the PHR decryption thread
	if(THREAD_JOIN(phr_decryption_thread_id) != 0)
		int_error("Joining a thread \"decrypt_phr_main\" failed");

	// Send signal to confirm that the PHR decryption thread has been terminated if the action was performed by a cancellation thread
	if(phr_decrypting_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");
	}

	uninit_main();
	return transaction_success_status_flag;
}

void cancel_phr_decrypting()
{
	phr_decrypting_cancellation_flag = true;

	// Cancel the PHR decryption thread
	if(THREAD_CANCEL(phr_decryption_thread_id) != 0)
		int_error("Cancelling a thread \"decrypt_phr_main\" failed");

	tell_phr_decryption_thread_terminates();

	// Wait for the confirmation
	if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Unlocking the mutex failed");
}



