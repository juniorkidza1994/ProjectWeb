#include <curl/curl.h>
#include "EmS_common.h"

// Local Type Definition
struct mail_upload_payload
{
	unsigned int no_read_line;
	unsigned int nline_payload_msg;
	char *ptr_payload_msg_list;
};

typedef struct mail_upload_payload mail_upload_payload_t;

// Local Function Prototypes
static void set_send_email_error_msg(char *msg, char *error_msg_ret);
static size_t payload_source(void *ptr, size_t size, size_t n_mem_block, void *userp);

// Implementation
static void set_send_email_error_msg(char *msg, char *error_msg_ret)
{
	if(error_msg_ret)
	{
		strcpy(error_msg_ret, msg);
	}
}

static size_t payload_source(void *ptr, size_t size, size_t n_mem_block, void *userp)
{
	mail_upload_payload_t *upload_ctx = (mail_upload_payload_t *)userp;
  	const char            *ptr_data;
	size_t                len;

	if((size == 0) || (n_mem_block == 0) || ((size*n_mem_block) < 1))
		return 0;

	if(upload_ctx->no_read_line >= upload_ctx->nline_payload_msg)
		return 0;

	ptr_data = upload_ctx->ptr_payload_msg_list + upload_ctx->no_read_line*(EMAIL_MSG_LINE_LENGTH + 1);

	len = strlen(ptr_data);
	memcpy(ptr, ptr_data, len);

	upload_ctx->no_read_line++;
	return len;
}

// "error_msg_ret" can be NULL
boolean send_email(unsigned int nrecipient, char *ptr_target_email_list, unsigned int nline_payload_msg, char *ptr_payload_msg_list, char *error_msg_ret)
{	
	CURL                  *curl       = NULL;
	struct curl_slist     *recipients = NULL;
	CURLcode              ret_code;
	mail_upload_payload_t upload_ctx;
	unsigned int          i;

	set_send_email_error_msg("", error_msg_ret);
	upload_ctx.no_read_line         = 0;
	upload_ctx.nline_payload_msg    = nline_payload_msg;
	upload_ctx.ptr_payload_msg_list = ptr_payload_msg_list;

	// Initial a curl object
	curl = curl_easy_init();
	if(!curl)
	{
		set_send_email_error_msg("Initial a curl object failed", error_msg_ret);
		goto ERROR;
	}

	// Set a mail server
	if(curl_easy_setopt(curl, CURLOPT_URL, GLOBAL_mail_server_url) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a mail server failed", error_msg_ret);
		goto ERROR;
	}

	// Set an SSL enabled variable
	if(curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL) != CURLE_OK)
	{
		set_send_email_error_msg("Setting an SSL enabled variable failed", error_msg_ret);
		goto ERROR;
	}

	// Set a mail server's username
	if(curl_easy_setopt(curl, CURLOPT_USERNAME, GLOBAL_authority_email_address) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a mail server's username failed", error_msg_ret);
		goto ERROR;
	}

	// Set an e-mail's password
	if(curl_easy_setopt(curl, CURLOPT_PASSWORD, GLOBAL_authority_email_passwd) != CURLE_OK)
	{
		set_send_email_error_msg("Setting an e-mail's password failed", error_msg_ret);
		goto ERROR;
	}

	// Set a sender's e-mail address
	if(curl_easy_setopt(curl, CURLOPT_MAIL_FROM, GLOBAL_authority_email_address) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a sender's e-mail address failed", error_msg_ret);
		goto ERROR;
	}

	// Set recipients' e-mail addresses
	for(i = 0; i < nrecipient; i++)
	{
		recipients = curl_slist_append(recipients, ptr_target_email_list + i*(EMAIL_ADDRESS_LENGTH + 1));
		if(curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients) != CURLE_OK)
		{
			set_send_email_error_msg("Setting recipients' e-mail addresses failed", error_msg_ret);
			goto ERROR;
		}
	}

	// Set a payload function
	if(curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a payload function failed", error_msg_ret);
		goto ERROR;
	}

	// Set a upload status object
	if(curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx) != CURLE_OK)
	{
		set_send_email_error_msg("Setting a upload status object failed", error_msg_ret);
		goto ERROR;
	}

	// Send the message
	ret_code = curl_easy_perform(curl);
	if(ret_code != CURLE_OK)
	{
		char error_msg[ERR_MSG_LENGTH + 1];
		sprintf(error_msg, "Sending an e-mail failed (%s)", curl_easy_strerror(ret_code));
		set_send_email_error_msg(error_msg, error_msg_ret);
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

void config_email_payload(int index, char *msg, char payload_msg_list_ret[][EMAIL_MSG_LINE_LENGTH + 1])
{
	strncpy(payload_msg_list_ret[index], msg, EMAIL_MSG_LINE_LENGTH);
}



