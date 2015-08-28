#include "PHRsv_common.h"

// Implementation
boolean verify_access_granting_ticket(char *access_granting_ticket_buffer, char *ticket_owner_name_cmp, 
	char *ticket_owner_authority_name_cmp, char *phr_owner_name_cmp, char *phr_owner_authority_name_cmp)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char ticket_owner_name[USER_NAME_LENGTH + 1];
	char ticket_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char phr_owner_name[USER_NAME_LENGTH + 1];
	char phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Get the access granting ticket info tokens from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 1, token_name, ticket_owner_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_owner_name") != 0)
	{
		int_error("Extracting the ticket_owner_name failed");
	}

	if(strcmp(ticket_owner_name, ticket_owner_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 2, token_name, ticket_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_owner_authority_name") != 0)
	{
		int_error("Extracting the ticket_owner_authority_name failed");
	}

	if(strcmp(ticket_owner_authority_name, ticket_owner_authority_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 3, token_name, phr_owner_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_name") != 0)
	{
		int_error("Extracting the phr_owner_name failed");
	}

	if(strcmp(phr_owner_name, phr_owner_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 4, token_name, phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
	{
		int_error("Extracting the phr_owner_authority_name failed");
	}

	if(strcmp(phr_owner_authority_name, phr_owner_authority_name_cmp) != 0)
		return false;

	return true;
}

boolean verify_access_granting_ticket_lifetime(char *access_granting_ticket_buffer)
{
	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      expired_date_time_str[DATETIME_STR_LENGTH + 1];      // Format is "YYYY-MM-DD.HH:mm:ss"

	int       diff_time;   // In second unit
	time_t    now, expired_date_time;
	struct tm tm_expired_date_time;

	// Get the access granting ticket lifetime token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 8, token_name, expired_date_time_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "expired_date_time") != 0)
	{
		int_error("Extracting the expired_date_time failed");
	}

	// Construct ticket expired date and time from string format to time_t format
	memset(&tm_expired_date_time, 0, sizeof(struct tm));
	strptime(expired_date_time_str, "%Y-%m-%d.%X", &tm_expired_date_time); 
	expired_date_time = mktime(&tm_expired_date_time);

	// Get current date and time
	now = time(NULL);

	// Find different time
	diff_time = (int)difftime(expired_date_time, now);
	if(diff_time >= 0)
		return true;
	else
		return false;
}

boolean verify_access_permission(char *access_granting_ticket_buffer, char *required_operation)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"

	// Get the permission flag token from buffer
	if(strcmp(required_operation, PHR_UPLOADING) == 0)
	{
		if(read_token_from_buffer(access_granting_ticket_buffer, 5, token_name, permission_flag_str) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "upload_permission_flag") != 0)
		{
			int_error("Extracting the upload_permission_flag failed");
		}
	}
	else if(strcmp(required_operation, PHR_DOWNLOADING) == 0)
	{
		if(read_token_from_buffer(access_granting_ticket_buffer, 6, token_name, permission_flag_str) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "download_permission_flag") != 0)
		{
			int_error("Extracting the download_permission_flag failed");
		}
	}
	else if(strcmp(required_operation, PHR_DELETION) == 0)
	{
		if(read_token_from_buffer(access_granting_ticket_buffer, 7, token_name, permission_flag_str) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "delete_permission_flag") != 0)
		{
			int_error("Extracting the delete_permission_flag failed");
		}
	}
	else
	{
		fprintf(stderr, "Unknown operation\n");
		return false;
	}

	if(strcmp(permission_flag_str, "1") == 0)
		return true;
	else
		return false;
}



