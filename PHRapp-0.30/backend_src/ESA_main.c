#include "common.h"
#include "ESA_common.h"

// Local Function Prototypes
static void assert_cache_directory_existence();
static void get_necessary_info();
static void load_pub_key();
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

	// Query for the authority's information
	sprintf(stat, "SELECT authority_name, mail_server_url, authority_email_address, authority_email_passwd FROM %s", ESA__BASIC_AUTHORITY_INFO);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);
	if(!row)
		int_error("Getting the authority's information from the database failed");

	strcpy(GLOBAL_authority_name, row[0]);
	strcpy(GLOBAL_mail_server_url, row[1]);
	strcpy(GLOBAL_authority_email_address, row[2]);
	strcpy(GLOBAL_authority_email_passwd, row[3]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
}

static void load_pub_key()
{
	unsigned int file_size;

	if(!get_file_size(ESA_PUB_CERTFILE_PATH, &file_size))
		int_error("Getting an emergency staff authority's public key size failed");

	GLOBAL_pub_key_data = (char *)malloc(sizeof(char)*(file_size));
	if(!GLOBAL_pub_key_data)
		int_error("Allocating memory for \"GLOBAL_pub_key_data\" failed");

	if(!read_bin_file(ESA_PUB_CERTFILE_PATH, GLOBAL_pub_key_data, file_size, NULL))
		int_error("Reading an emergency staff authority's public key failed");
}

static void init_server()
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
    	init_openssl();

	assert_cache_directory_existence();
	get_necessary_info();
	load_pub_key();

	// Initial the e-mail sending lock mutex
	if(sem_init(&email_sending_lock_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");
}

static void uninit_server()
{
	if(sem_destroy(&email_sending_lock_mutex) != 0)
		int_error("Destroying a mutex failed");

	uninit_openssl();
}

int main(int argc, char *argv[])
{
	THREAD_TYPE user_authentication_thread_id;
	THREAD_TYPE pub_key_serving_thread_id;
	THREAD_TYPE user_info_management_thread_id;
	THREAD_TYPE server_info_management_thread_id;
	THREAD_TYPE user_list_loading_thread_id;
	THREAD_TYPE phr_authority_list_loading_thread_id;
	THREAD_TYPE user_management_thread_id;
	THREAD_TYPE phr_authority_management_thread_id;
	THREAD_TYPE user_passwd_resetting_thread_id;

	init_server();

	// Create threads
	if(THREAD_CREATE(user_authentication_thread_id, user_authentication_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"user_authentication_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(pub_key_serving_thread_id, pub_key_serving_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"pub_key_serving_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(user_info_management_thread_id, user_info_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"user_info_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(server_info_management_thread_id, server_info_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"server_info_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(user_list_loading_thread_id, user_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"user_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(phr_authority_list_loading_thread_id, phr_authority_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"phr_authority_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(user_management_thread_id, user_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"user_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(phr_authority_management_thread_id, phr_authority_management_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"phr_authority_management_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(user_passwd_resetting_thread_id, user_passwd_resetting_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"user_passwd_resetting_main\" failed");
		return 1;
	}

	printf("Emergency unit: %s.Emergency_Staff_Authority started...\n", GLOBAL_authority_name);

	// Join threads
	if(THREAD_JOIN(user_authentication_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"user_authentication_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(pub_key_serving_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"pub_key_serving_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(user_info_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"user_info_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(server_info_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"server_info_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(user_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"user_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(phr_authority_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"phr_authority_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(user_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"user_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(phr_authority_management_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"phr_authority_management_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(user_passwd_resetting_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"user_passwd_resetting_main\" failed");
		return 1;
	}

	uninit_server();
    	return 0;
}



