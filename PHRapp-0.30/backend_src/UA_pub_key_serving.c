#include "UA_common.h"

// Local Function Prototype
static boolean serve_pub_key(BIO *bio_client);

// Implementation
static boolean serve_pub_key(BIO *bio_client)
{
	// We can send the public key without encryption because it can reveal to public
	if(!BIO_send_buffer(bio_client, GLOBAL_pub_key_data, strlen(GLOBAL_pub_key_data)))
	{
		fprintf(stderr, "Sending a user authority's public key failed\n");
		return false;
	}

	return true;
}

void *pub_key_serving_main(void *arg)
{
    	BIO *bio_acc    = NULL;
	BIO *bio_client = NULL;

    	bio_acc = BIO_new_accept(UA_PUB_KEY_SERVING_PORT);
    	if(!bio_acc)
        	int_error("Creating server socket failed");
  
    	if(BIO_do_accept(bio_acc) <= 0)
        	int_error("Binding server socket failed");
  
    	for(;;)
    	{
        	if(BIO_do_accept(bio_acc) <= 0)
            		int_error("Accepting connection failed");
 
        	bio_client = BIO_pop(bio_acc);

		// Serve a user authority's public key
		if(!serve_pub_key(bio_client))
			goto ERROR;
ERROR:

		BIO_free(bio_client);
		bio_client = NULL;
		ERR_remove_state(0);
    	}
    
    	BIO_free(bio_acc);
	bio_acc = NULL;

	pthread_exit(NULL);
    	return NULL;
}



