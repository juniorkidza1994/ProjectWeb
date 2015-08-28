#include "common.h"
#include "PHRsv_common.h"

// Local Function Prototypes
static void assert_cache_directory_existence();
static void assert_phr_directory_existence();
static size_t list_meter_active_phr_node_t(const void *element);
static int list_seeker_by_database_phr_id(const void *element, const void *key);
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

static void assert_phr_directory_existence()
{
	// We do not consider the PHR directory's mode yet. Must be considerd regarding it later.
	if(!directory_exists(PHR_DIRECTORY_PATH))
	{
		if(!make_directory(PHR_DIRECTORY_PATH, PHR_DIRECTORY_PERMISSION_MODE))
			int_error("Creating a PHR directory failed");
	}
}

static size_t list_meter_active_phr_node_t(const void *element)
{
	return sizeof(active_phr_node_t);
}

static int list_seeker_by_database_phr_id(const void *element, const void *key)
{
	const active_phr_node_t *node = (active_phr_node_t *)element;

	if(node->phr_id == *(unsigned int *)key)
		return 1;
	else
		return 0;
}

static void init_server()
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
    	init_openssl();

	assert_cache_directory_existence();
	assert_phr_directory_existence();

	// Initialize a linked list
	if(list_init(&active_phr_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&active_phr_node_list, list_meter_active_phr_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&active_phr_node_list, list_seeker_by_database_phr_id) < 0)
		int_error("Initial a custom seeker function failed");

	if(sem_init(&active_phr_node_list_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");

	// The server serves concurrent operating threads at most "MAX_CONCURRENT_OPERATING_THREADS"
	if(sem_init(&remaining_operating_thread_counter_sem, 0, MAX_CONCURRENT_OPERATING_THREADS) != 0)
		int_error("Initial a mutex failed");

	// Initial the signal transmisster
	if(sem_init(&wait_for_creating_new_child_thread_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");
}

static void uninit_server()
{
	// Destroy a linked list
	list_destroy(&active_phr_node_list);

	if(sem_destroy(&active_phr_node_list_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&remaining_operating_thread_counter_sem) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Destroying a mutex failed");

	uninit_openssl();
}

int main(int argc, char *argv[])
{
	THREAD_TYPE authorized_phr_list_loading_thread_id;
	THREAD_TYPE inactive_node_release_thread_id;
	THREAD_TYPE phr_services_thread_id;
	THREAD_TYPE phr_confidentiality_level_changing_thread_id;
	THREAD_TYPE emergency_phr_list_loading_thread_id;
	
	init_server();

	// Create threads
	if(THREAD_CREATE(authorized_phr_list_loading_thread_id, authorized_phr_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"authorized_phr_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(inactive_node_release_thread_id, inactive_node_release_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"inactive_node_release_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(phr_services_thread_id, phr_services_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"phr_services_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(phr_confidentiality_level_changing_thread_id, phr_confidentiality_level_changing_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"phr_confidentiality_level_changing_main\" failed");
		return 1;
	}

	if(THREAD_CREATE(emergency_phr_list_loading_thread_id, emergency_phr_list_loading_main, NULL) != 0)
	{
		uninit_server();
		int_error("Creating a thread for \"emergency_phr_list_loading_main\" failed");
		return 1;
	}

	printf("PHR system: PHR_Server started...\n");

	// Join threads
	if(THREAD_JOIN(authorized_phr_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"authorized_phr_list_loading_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(inactive_node_release_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"inactive_node_release_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(phr_services_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"phr_services_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(phr_confidentiality_level_changing_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"phr_confidentiality_level_changing_main\" failed");
		return 1;
	}

	if(THREAD_JOIN(emergency_phr_list_loading_thread_id) != 0)
	{
		uninit_server();
		int_error("Joining a thread \"emergency_phr_list_loading_main\" failed");
		return 1;
	}

	uninit_server();
    	return 0;
}



