#include "common.h"
#include "EmS_common.h"

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

	// Query for authority's id and name
	sprintf(stat, "SELECT BAI.authority_id, AU.authority_name FROM %s AU, %s BAI WHERE AU.authority_id = BAI.authority_id", EMS__AUTHORITIES, EMS__BASIC_AUTHORITY_INFO);
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

	// Query for server information
	sprintf(stat, "SELECT user_auth_ip_addr, audit_server_ip_addr, phr_server_ip_addr, mail_server_url, "
		"authority_email_address, authority_email_passwd FROM %s", EMS__BASIC_AUTHORITY_INFO);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);
	if(!row)
		int_error("Getting server information from the database failed");

	strcpy(GLOBAL_user_auth_ip_addr, row[0]);
	strcpy(GLOBAL_audit_server_ip_addr, row[1]);
	strcpy(GLOBAL_phr_server_ip_addr, row[2]);
	strcpy(GLOBAL_mail_server_url, row[3]);
	strcpy(GLOBAL_authority_email_address, row[4]);
	strcpy(GLOBAL_authority_email_passwd, row[5]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
}

static void init_server()
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
    	init_openssl();

	assert_cache_directory_existence();
	get_necessary_info();

	// The server serves concurrent operating threads at most "MAX_CONCURRENT_OPERATING_THREADS"
	if(sem_init(&remaining_operating_thread_counter_sem, 0, MAX_CONCURRENT_OPERATING_THREADS) != 0)
		int_error("Initial a mutex failed");

	// Initial the signal transmisster
	if(sem_init(&wait_for_creating_new_child_thread_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");
}

static void uninit_server()
{
	if(sem_destroy(&remaining_operating_thread_counter_sem) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Destroying a mutex failed");

	uninit_openssl();
}

int main(int argc, char *argv[])
{
	THREAD_TYPE server_info_management_thread_id;
	THREAD_TYPE emergency_trusted_user_management_thread_id;
	THREAD_TYPE emergency_delegation_list_loading_thread_id;
	THREAD_TYPE restricted_level_phr_key_params_management_thread_id;
	THREAD_TYPE restricted_level_phr_key_params_management_remote_ems_thread_id;
	THREAD_TYPE phr_owner_existence_checking_thread_id;
	THREAD_TYPE emergency_phr_list_loading_thread_id;
	THREAD_TYPE synchronization_receiving_thread_id;
	THREAD_TYPE synchronization_responding_thread_id;
	THREAD_TYPE emergency_phr_accessing_thread_id;
	THREAD_TYPE restricted_level_phr_access_requesting_thread_id;
	THREAD_TYPE restricted_level_phr_access_request_list_loading_thread_id;
	THREAD_TYPE restricted_level_phr_access_request_list_loading_remote_ems_thread_id;
	THREAD_TYPE restricted_level_phr_access_request_responding_thread_id;
	THREAD_TYPE restricted_level_phr_access_request_responding_remote_ems_thread_id;

	init_server();

	// Create threads
	if(THREAD_CREATE(server_info_management_thread_id, server_info_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"server_info_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(emergency_trusted_user_management_thread_id, emergency_trusted_user_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"emergency_trusted_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(emergency_delegation_list_loading_thread_id, emergency_delegation_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"emergency_delegation_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_key_params_management_thread_id, restricted_level_phr_key_params_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_key_params_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_key_params_management_remote_ems_thread_id, restricted_level_phr_key_params_management_remote_ems_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_key_params_management_remote_ems_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(phr_owner_existence_checking_thread_id, phr_owner_existence_checking_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"phr_owner_existence_checking_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(emergency_phr_list_loading_thread_id, emergency_phr_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"emergency_phr_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(synchronization_receiving_thread_id, synchronization_receiving_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"synchronization_receiving_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(synchronization_responding_thread_id, synchronization_responding_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"synchronization_responding_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(emergency_phr_accessing_thread_id, emergency_phr_accessing_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"emergency_phr_accessing_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_access_requesting_thread_id, restricted_level_phr_access_requesting_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_access_requesting_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_access_request_list_loading_thread_id, restricted_level_phr_access_request_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_access_request_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_access_request_list_loading_remote_ems_thread_id, restricted_level_phr_access_request_list_loading_remote_ems_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_access_request_list_loading_remote_ems_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_access_request_responding_thread_id, restricted_level_phr_access_request_responding_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_access_request_responding_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(restricted_level_phr_access_request_responding_remote_ems_thread_id, restricted_level_phr_access_request_responding_remote_ems_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"restricted_level_phr_access_request_responding_remote_ems_main\" failed");
		return 1;
	}

	printf("PHR system: %s.Emergency_Server started...\n", GLOBAL_authority_name);

	// Join threads
	if(THREAD_JOIN(server_info_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"server_info_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(emergency_trusted_user_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"emergency_trusted_user_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(emergency_delegation_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"emergency_delegation_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_key_params_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_key_params_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_key_params_management_remote_ems_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_key_params_management_remote_ems_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(phr_owner_existence_checking_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"phr_owner_existence_checking_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(emergency_phr_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"emergency_phr_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(synchronization_receiving_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"synchronization_receiving_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(synchronization_responding_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"synchronization_responding_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(emergency_phr_accessing_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"emergency_phr_accessing_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_access_requesting_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_access_requesting_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_access_request_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_access_request_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_access_request_list_loading_remote_ems_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_access_request_list_loading_remote_ems_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_access_request_responding_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_access_request_responding_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(restricted_level_phr_access_request_responding_remote_ems_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"restricted_level_phr_access_request_responding_remote_ems_main\" failed");
		return 1;
	}

	uninit_server();
    	return 0;
}



