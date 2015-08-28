#include <curl/curl.h>
#include "ESA_common.h"

// Local Variables
struct upload_status
{
	int no_read_line;
};

typedef struct upload_status upload_status_t;

static char payload_msg[9][EMAIL_MSG_LINE_LENGTH + 1];
static char error_msg[ERR_MSG_LENGTH + 1];

// Local Function Prototypes
static void set_send_email_error_msg(char *msg);
static size_t payload_source(void *ptr, size_t size, size_t n_mem_block, void *userp);

// Implementation
static void set_send_email_error_msg(char *msg)
{
	strcpy(error_msg, msg);
}

static size_t payload_source(void *ptr, size_t size, size_t n_mem_block, void *userp)
{
	upload_status_t *upload_ctx = (upload_status_t *)userp;
  	const char      *data;

	if((size == 0) || (n_mem_block == 0) || ((size*n_mem_block) < 1))
		return 0;

	data = payload_msg[upload_ctx->no_read_line];
	if(data)
	{
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_ctx->no_read_line++;
		return len;
	}

	return 0;
}

void send_email_config_payload(int index, char *msg)
{
	strcpy(payload_msg[index], msg);
}

boolean send_email(char *email_to)
{	
	CURL              *curl       = NULL;
	CURLcode          ret_code;
	struct curl_slist *recipients = NULL;
	upload_status_t   upload_ctx;

	set_send_email_error_msg("");
	upload_ctx.no_read_line = 0;

	// Initial a curl object
	curl = curl_easy_init();
	if(!curl)
	{
		set_send_email_error_msg("Initial a curl object failed");
		goto ERROR;
	}

	// Set a mail server
	if(curl_easy_setopt(curl, CURLOPT_URL, GLOBAL_mail_server_url) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a mail server failed");
		goto ERROR;
	}

	// Set an SSL enabled variable
	if(curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL) != CURLE_OK)
	{
		set_send_email_error_msg("Setting an SSL enabled variable failed");
		goto ERROR;
	}

	// Set a mail server's username
	if(curl_easy_setopt(curl, CURLOPT_USERNAME, GLOBAL_authority_email_address) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a mail server's username failed");
		goto ERROR;
	}

	// Set an e-mail's password
	if(curl_easy_setopt(curl, CURLOPT_PASSWORD, GLOBAL_authority_email_passwd) != CURLE_OK)
	{
		set_send_email_error_msg("Setting an e-mail's password failed");
		goto ERROR;
	}

	// Set a sender's e-mail address
	if(curl_easy_setopt(curl, CURLOPT_MAIL_FROM, GLOBAL_authority_email_address) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a sender's e-mail address failed");
		goto ERROR;
	}

	// Set a recipient's e-mail address
	recipients = curl_slist_append(recipients, email_to);
	if(curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a recipient's e-mail address failed");
		goto ERROR;
	}

	// Set a payload function
	if(curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a payload function failed");
		goto ERROR;
	}

	// Set a upload status object
	if(curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a upload status object failed");
		goto ERROR;
	}

	// Send the message
	ret_code = curl_easy_perform(curl);
	if(ret_code != CURLE_OK)
	{
		char error_msg[ERR_MSG_LENGTH + 1];
		sprintf(error_msg, "Sending an e-mail failed (%s)", curl_easy_strerror(ret_code));
		set_send_email_error_msg(error_msg);
		goto ERROR;
	}

	// Memory cleanup
	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);

	return true;

ERROR:

	if(recipients)
	{
		curl_slist_free_all(recipients);
	}

	if(curl)
	{
		curl_easy_cleanup(curl);
	}	

	return false;
}

char *get_send_email_error_msg()
{
	return error_msg;
}



