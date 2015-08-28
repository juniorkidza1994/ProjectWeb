#include "PHRsv_common.h"

// Local Function Prototypes
static void uninit_inactive_node(active_phr_node_t *pre_active_node);

// Implementation
static void uninit_inactive_node(active_phr_node_t *ptr_active_node)
{
	if(sem_destroy(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&ptr_active_node->downloading_mutex) != 0)
		int_error("Destroying a mutex failed");

	if(sem_destroy(&ptr_active_node->deletion_mutex) != 0)
		int_error("Destroying a mutex failed");
}

void *inactive_node_release_main(void *arg)
{
	active_phr_node_t *ptr_active_node = NULL;
	unsigned int      i;
	unsigned int      size;
	unsigned int      nthread;

	while(1)
	{
		sleep(INACTIVE_NODE_RELEASE_TIME_PERIOD*60);

		// Lock the "active_phr_node_list"
		if(sem_wait(&active_phr_node_list_mutex) != 0)
			int_error("Locking the mutex failed");

printf("inactive_node_release_main() started\n");

		i    = 0;
		size = list_size(&active_phr_node_list);

		while(i < size)
		{
			// Get node number "i"
			ptr_active_node = (active_phr_node_t *)list_get_at(&active_phr_node_list, i);
			if(ptr_active_node == NULL)
				int_error("Getting an active node failed");

			// Get the "working_thread_counter"
			if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
				int_error("Locking the mutex failed");

			nthread = ptr_active_node->working_thread_counter;

			if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
				int_error("Unlocking the mutex failed");

			// If the node is no longer need to be used then delete it
			if(nthread == 0)
			{
				// Release memory
				uninit_inactive_node(ptr_active_node);

				// Delete the node "i" from linked list
				if(list_delete_at(&active_phr_node_list, i) < 0)
					int_error("Deleting an inactive node failed");
else
printf("delete an inactive node\n");

				// And then set "i" to the first node of linked list, in order to check all active nodes at head of the list again
				i    = 0;
				size = list_size(&active_phr_node_list);
			}
			else
			{
				i++;
			}
		}

printf("inactive_node_release_main() stopped\n");

		// Unlock the "active_PHR_node_list"
		if(sem_post(&active_phr_node_list_mutex) != 0)
			int_error("Unlocking the mutex failed");
	}

	pthread_exit(NULL);
	return NULL;
}



