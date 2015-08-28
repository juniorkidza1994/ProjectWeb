#include "common.h"
#include "AS_common.h"

// Local Function Prototypes
static void assert_cache_directory_existence();
static void get_necessary_info();
static void init_server();
static void uninit_server();

// Implementation
static void assert_cache_directory_existence()
{
	// We do not consider the cache directory's mode yet. Must be considerd regarding it later.
	if(!directory_exists(CACHE_DIRECTORY_PATH))
	{
		if(!make_directory(CACHE_DIRECTORY_PATH, CACHE_DIRECTORY_PERMISSION_MODE))
			int_error("Creating a cache directory failed");
	}
}

static void get_necessary_info()
{
	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the authority's id and name
	sprintf(stat, "SELECT BAI.authority_id, AU.authority_name FROM %s AU, %s BAI WHERE AU.authority_id = BAI.authority_id", AS__AUTHORITIES, AS__BASIC_AUTHORITY_INFO);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);
	if(!row)
		int_error("Getting authority's id and name from the database failed");

	GLOBAL_authority_id = atoi(row[0]);
	strcpy(GLOBAL_authority_name, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Query the no reference user id
	GLOBAL_no_reference_user_id = get_user_id(db_conn, NO_REFERENCE_USERNAME, GLOBAL_authority_name, false);

	// Query the "reference to all admin id"
	GLOBAL_reference_to_all_admins_id = get_user_id(db_conn, REFERENCE_TO_ALL_ADMIN_NAMES, GLOBAL_authority_name, true);

	disconnect_db(&db_conn);
}

static void init_server()
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
    	init_openssl();

	assert_cache_directory_existence();
	get_necessary_info();
}

static void uninit_server()
{
	uninit_openssl();
}

int main(int argc, char *argv[])
{
	THREAD_TYPE transaction_log_recording_thread_id;
	THREAD_TYPE transaction_log_auditing_thread_id;
	THREAD_TYPE phr_transaction_log_synchronization_thread_id;

	init_server();

	// Create threads
	if(THREAD_CREATE(transaction_log_recording_thread_id, transaction_log_recording_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"transaction_log_recording_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(transaction_log_auditing_thread_id, transaction_log_auditing_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"transaction_log_auditing_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(phr_transaction_log_synchronization_thread_id, phr_transaction_log_synchronization_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"phr_transaction_log_synchronization_main\" failed");
		return 1;
	}

	printf("PHR system: %s.Audit_Server started...\n", GLOBAL_authority_name);

	// Join threads
	if(THREAD_JOIN(transaction_log_recording_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"transaction_log_recording_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(transaction_log_auditing_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"transaction_log_auditing_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(phr_transaction_log_synchronization_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"phr_transaction_log_synchronization_main\" failed");
		return 1;
	}

	uninit_server();
    	return 0;
}



