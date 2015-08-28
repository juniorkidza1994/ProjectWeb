#include "EmU_client_common.h"

// Local Variable
static void (*backend_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototype
static void backend_alert_msg_handler_callback(char *alert_msg);

// Implementation
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

boolean load_emergency_staff_authority_pub_key(char *emergency_staff_auth_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handler
	backend_alert_msg_callback_handler = backend_alert_msg_callback_handler_ptr;

	BIO  *bio_conn = NULL;
	char emergency_staff_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Check for existence of the emergency staff authority's public key
	// If exists then return a process without connecting to the emergency staff authority
	if(file_exists(ESA_PUB_CERTFILE_PATH))
		return true;

	// Connect to Emergency Staff Authority
	sprintf(emergency_staff_auth_addr, "%s:%s", emergency_staff_auth_ip_addr, ESA_PUB_KEY_SERVING_PORT);
	bio_conn = BIO_new_connect(emergency_staff_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_handler_callback("Connecting to emergency staff authority failed");
		goto ERROR;
	}

	// Receive the emergency staff authority's public key and store it on local cache
	if(!BIO_recv_file(bio_conn, ESA_PUB_CERTFILE_PATH))
	{
		backend_alert_msg_handler_callback("Receiving an emergency staff authority's public key failed");
		goto ERROR;
	}

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);
	return true;

ERROR:

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);
	return false;
}



