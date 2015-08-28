#include "EmU_client_common.h"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg) = NULL;

static char        **ptr_phr_download_to_path;

static sem_t       wake_up_main_thread_mutex;
static sem_t       confirm_err_msg_sending_to_frontend_mutex;
static char        err_msg_to_frontend[ERR_MSG_LENGTH + 1];
static boolean     emergency_phr_extraction_thread_terminated_flag;
static boolean     transaction_success_status_flag;

static sem_t       send_signal_to_confirm_cancellation_thread_mutex;
static sem_t       cancellation_thread_got_confirmation_mutex;
static boolean     emergency_phr_extracting_cancellation_flag;

static THREAD_TYPE emergency_phr_extraction_thread_id;
static char        *shell_cmd;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void tell_emergency_phr_extraction_thread_terminates();
static void send_error_msg_to_frontend(char *error_msg);
static void init_emergency_phr_extraction();
static void uninit_emergency_phr_extraction(void *arg);
static void *extract_emergency_phr_main(void *arg);
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

// Tell the main thread that the emergenct PHR extraction thread terminates
static void tell_emergency_phr_extraction_thread_terminates()
{
	emergency_phr_extraction_thread_terminated_flag = true;
	
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

static void init_emergency_phr_extraction()
{
	// Allocate a heap variable
	shell_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!shell_cmd)
	{
		int_error("Allocating memory for \"shell_cmd\" failed");
	}
}

static void uninit_emergency_phr_extraction(void *arg)
{
	unlink(UNARCHIVED_EMERGENCY_PHR_TARGET_FILE_PATH);

	// Release memory
	free(shell_cmd);
}

static void *extract_emergency_phr_main(void *arg)
{
	char err_code[ERR_MSG_LENGTH + 1];

	init_emergency_phr_extraction();

	// Release heap allocated items even if this thread doesn't exit normally
	pthread_cleanup_push(uninit_emergency_phr_extraction, NULL);

	// Unarchive the emergency PHR
	sprintf(shell_cmd, "tar -xf %s -C \"%s\"", UNARCHIVED_EMERGENCY_PHR_TARGET_FILE_PATH, *ptr_phr_download_to_path);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		fprintf(stderr, "Unarchieving the emergency PHR failed\n\"%s\"\n", err_code);
		send_error_msg_to_frontend("Unarchieving the emergency PHR failed");

		transaction_success_status_flag = false;
		goto ERROR;
	}

	transaction_success_status_flag = true;	

ERROR:

	unlink(UNARCHIVED_EMERGENCY_PHR_TARGET_FILE_PATH);

	pthread_cleanup_pop(1);
	tell_emergency_phr_extraction_thread_terminates();
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
	emergency_phr_extraction_thread_terminated_flag = false;
	transaction_success_status_flag                 = false; 
	emergency_phr_extracting_cancellation_flag      = false;
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

boolean extract_emergency_phr(char *phr_download_to_path, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handler
	backend_alert_msg_callback_handler = backend_alert_msg_callback_handler_ptr;

	// Passing variable
	ptr_phr_download_to_path = &phr_download_to_path;

	init_main();

	// Create an emergency PHR extraction thread
	if(THREAD_CREATE(emergency_phr_extraction_thread_id, extract_emergency_phr_main, NULL) != 0)
		int_error("Creating a thread for \"extract_emergency_phr_main\" failed");

	while(1)
	{
		if(sem_wait(&wake_up_main_thread_mutex) != 0)
			int_error("Locking the mutex failed");

		// The emergency PHR extraction thread terminated
		if(emergency_phr_extraction_thread_terminated_flag)
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

	// Join the emergency PHR extraction thread
	if(THREAD_JOIN(emergency_phr_extraction_thread_id) != 0)
		int_error("Joining a thread \"extract_emergency_phr_main\" failed");

	// Send signal to confirm that the emergency PHR extraction thread has been terminated if the action was performed by a cancellation thread
	if(emergency_phr_extracting_cancellation_flag)
	{
		if(sem_post(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_wait(&cancellation_thread_got_confirmation_mutex) != 0)
			int_error("Locking the mutex failed");
	}

	uninit_main();
	return transaction_success_status_flag;
}

void cancel_emergency_phr_extracting()
{
	emergency_phr_extracting_cancellation_flag = true;

	// Cancel the emergency PHR extraction thread
	if(THREAD_CANCEL(emergency_phr_extraction_thread_id) != 0)
		int_error("Cancelling a thread \"extract_emergency_phr_main\" failed");

	tell_emergency_phr_extraction_thread_terminates();

	// Wait for the confirmation
	if(sem_wait(&send_signal_to_confirm_cancellation_thread_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_post(&cancellation_thread_got_confirmation_mutex) != 0)
		int_error("Unlocking the mutex failed");
}



