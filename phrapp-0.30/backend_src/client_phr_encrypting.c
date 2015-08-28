#include "client_common.h"

#define ARCHIVED_PHR_TARGET_FILE_PATH "Client_cache/client_phr_encrypting.archived_phr_target_file.tar"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg) = NULL;

static char        **ptr_phr_upload_from_path;
static char        **ptr_access_policy;

static sem_t       wake_up_main_thread_mutex;
static sem_t       confirm_err_msg_sending_to_frontend_mutex;
static char        err_msg_to_frontend[ERR_MSG_LENGTH + 1];
static boolean     phr_encryption_thread_terminated_flag;
static boolean     transaction_success_status_flag;

static sem_t       send_signal_to_confirm_cancellation_thread_mutex;
static sem_t       cancellation_thread_got_confirmation_mutex;
static boolean     phr_encrypting_cancellation_flag;

static THREAD_TYPE phr_encryption_thread_id;
static char        *shell_cmd;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void tell_phr_encryption_thread_terminates();
static void send_error_msg_to_frontend(char *error_msg);
static void get_parent_directory(char *phr_path, char *phr_parent_directory_path_ret);
static void get_filename(char *phr_path, char *phr_filename_ret);
static void init_phr_encryption();
static void uninit_phr_encryption(void *arg);
static void *encrypt_phr_main(void *arg);
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

// Tell the main thread that the PHR encryption thread terminates
static void tell_phr_encryption_thread_terminates()
{
	phr_encryption_thread_terminated_flag = true;
	
	// Wake up the main thread in order to quit the infinity loop
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

// Usage of get_parent_directory() and get_filename() is not memory safe, please make sure that "phr_path" contains valid path format
static void get_parent_directory(char *phr_path, char *phr_parent_directory_path_ret)
{
	strncpy(phr_parent_directory_path_ret, phr_path, strrchr(phr_path, '/') - phr_path);
}

static void get_filename(char *phr_path, char *phr_filename_ret)
{
	strcpy(phr_filename_ret, strrchr(phr_path, '/') + 1);
}

static void init_phr_encryption()
{
	// Allocate a heap variable
	shell_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!shell_cmd)
	{
		int_error("Allocating memory for \"shell_cmd\" failed");
	}

	unlink(ENCRYPTED_PHR_TARGET_FILE_PATH);
}

static void uninit_phr_encryption(void *arg)
{
	unlink(ARCHIVED_PHR_TARGET_FILE_PATH);

	// Delete the encrypted PHR file if a user cancels the transaction
	if(phr_encrypting_cancellation_flag)
		unlink(ENCRYPTED_PHR_TARGET_FILE_PATH);

	// Release memory
	free(shell_cmd);
}

static void *encrypt_phr_main(void *arg)
{
	char err_code[ERR_MSG_LENGTH + 1];
	char phr_parent_directory_path[PATH_LENGTH + 1];
	char phr_filename[FILENAME_LENGTH + 1];

	init_phr_encryption();

	// Release heap allocated items even if this thread doesn't exit normally
	pthread_cleanup_push(uninit_phr_encryption, NULL);

	get_parent_directory(*ptr_phr_upload_from_path, phr_parent_directory_path);
	get_filename(*ptr_phr_upload_from_path, phr_filename);

	// Archive the PHR (This command is necessary because the CP-ABE encryption module could not encrypt the directory file)
	sprintf(shell_cmd, "tar -cf %s -C \"%s\" \"%s\"", ARCHIVED_PHR_TARGET_FILE_PATH, phr_parent_directory_path, phr_filename);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		fprintf(stderr, "Archieving the PHR failed\n\"%s\"\n", err_code);
		send_error_msg_to_frontend("Archieving the PHR failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	// Encrypt the PHR
	sprintf(shell_cmd, "%s -k -o %s %s %s \"%s\"", CPABE_ENC_PATH, ENCRYPTED_PHR_TARGET_FILE_PATH, 
		CPABE_PUB_KEY_PATH, ARCHIVED_PHR_TARGET_FILE_PATH, *ptr_access_policy);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		fprintf(stderr, "Encrypting the PHR failed\n\"%s\"\n", err_code);
		send_error_msg_to_frontend("Encrypting the PHR failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	transaction_success_status_flag = true;

ERROR:

	unlink(ARCHIVED_PHR_TARGET_FILE_PATH);

	pthread_cleanup_pop(1);
	tell_phr_encryption_thread_terminates();
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
	phr_encryption_thread_terminated_flag = false;
	transaction_success_status_flag       = false; 
	phr_encrypting_cancellation_flag      = false;
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

boolean encrypt_phr(char *phr_upload_from_path, char *access_policy, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handler
	backend_alert_msg_callback_handler = backend_alert_msg_callback_handler_ptr;

	// Passing variables
	ptr_phr_upload_from_path = &phr_upload_from_path;
	ptr_access_policy        = &access_policy;

	init_main();

	// Create a PHR encryption thread
	if(THREAD_CREATE(phr_encryption_thread_id, encrypt_phr_main, NULL) != 0)
		int_error("Creating a thread for \"phr_encryption_main\" failed");

	while(1)
	{
		if(sem_wait(&wake_up_main_thread_mutex) != 0)
			int_error("Locking the mutex failed");

		// The PHR encryption thread terminated
		if(phr_encryption_thread_terminated_flag)
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

	// Join the PHR encryption thread
	if(THREAD_JOIN(phr_encryption_thread_id) != 0)
		int_error("Joining a thread \"phr_encryption_main\" failed");

	// Send signal to confirm that the PHR encryption thread has been terminated if the action was performed by a cancellation thread
	if(phr_encrypting_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");
	}

	uninit_main();
	return transaction_success_status_flag;
}

void cancel_phr_encrypting()
{
	phr_encrypting_cancellation_flag = true;

	// Cancel the PHR encryption thread
	if(THREAD_CANCEL(phr_encryption_thread_id) != 0)
    		int_error("Cancelling a thread \"phr_encryption_main\" failed");

	tell_phr_encryption_thread_terminates();

	// Wait for the confirmation
	if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Unlocking the mutex failed");
}



