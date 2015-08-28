#include "common.h"

#define DH512_FILE_PATH          "Certs_and_keys_pool/dh512.pem"
#define DH1024_FILE_PATH         "Certs_and_keys_pool/dh1024.pem"

#define CIPHER_LIST              "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CA_DIR_PATH 	         NULL 

// Local Variables
static DH         *dh512  = NULL;
static DH         *dh1024 = NULL;

static boolean    using_safety_threads_for_openssl_flag = false;

// This array will store all of the mutexes available to OpenSSL
static MUTEX_TYPE *mutex_buf = NULL;

static char       server_certfile_passwd[PASSWD_LENGTH + 1];
static sem_t      server_certfile_passwd_mutex;

static char       client_certfile_passwd[PASSWD_LENGTH + 1];
static sem_t      client_certfile_passwd_mutex;

// Local Function Prototypes
static boolean is_using_safety_threads_for_openssl();
static void locking_function(int mode, int n, const char *file, int line);
static unsigned long id_function();
static void thread_setup();
static void thread_cleanup();
static void init_dhparams();
static DH *tmp_dh_callback(SSL *ssl, int is_export_flag, int key_length);
static void setup_server_certfile_password(char *passwd);
static void setup_client_certfile_password(char *passwd);
static int ctx_verify_callback(int ok, X509_STORE_CTX *store);
static int server_certfile_password_callback(char *buffer, int num, int rw_flag, void *user_data);
static int client_certfile_password_callback(char *buffer, int num, int rw_flag, void *user_data);
static char *get_SSL_error(SSL *peer, int value, char *err_status_ret);

// Implementation
void set_using_safety_threads_for_openssl(boolean mode_flag)
{
	using_safety_threads_for_openssl_flag = mode_flag;
}

static boolean is_using_safety_threads_for_openssl()
{
	return using_safety_threads_for_openssl_flag;
}

static void locking_function(int mode, int n, const char *file, int line)
{
  	if(mode & CRYPTO_LOCK)
	{
   		if(MUTEX_LOCK(mutex_buf[n]) != 0)
			int_error("Mutex lock function failed");
	}
  	else
	{
   		if(MUTEX_UNLOCK(mutex_buf[n]) != 0)
			int_error("Mutex unlock function failed");
	}
}

static unsigned long id_function()
{
  	return ((unsigned long)THREAD_ID);
}

static void thread_setup()
{
  	int i;

  	mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if(!mutex_buf)
	{
		int_error("Allocating memory for \"mutex_buf\" failed");
	}

  	for(i = 0; i < CRYPTO_num_locks(); i++)
	{
    		if(MUTEX_SETUP(mutex_buf[i]) != 0)
			int_error("Initial an array of mutex failed");
	}

  	CRYPTO_set_id_callback(id_function);
  	CRYPTO_set_locking_callback(locking_function);
}

static void thread_cleanup()
{
  	int i;

  	if(!mutex_buf)
    		int_error("\"mutex_buf\" is NULL");

  	CRYPTO_set_id_callback(NULL);
  	CRYPTO_set_locking_callback(NULL);

  	for(i = 0; i < CRYPTO_num_locks(); i++)
	{
    		if(MUTEX_CLEANUP(mutex_buf[i]) != 0)
			int_error("Uninitial an array of mutex failed");
	}

  	free(mutex_buf);
  	mutex_buf = NULL;
}

void handle_error(const char *file, int line_no, const char *err_msg)
{
    	fprintf(stderr, "** %s:%i %s\n", file, line_no, err_msg);
    	ERR_print_errors_fp(stderr);
    	exit(-1);
}

// Seeding OpenSSL's PRNG with /dev/random with 16 random bytes
void seed_prng()
{
	if(!RAND_load_file("/dev/random", 16))
		int_error("Seeding PRNG failed");
}

void init_openssl()
{
    	if(!SSL_library_init())
		int_error("OpenSSL initialization failed");

	if(is_using_safety_threads_for_openssl())
		thread_setup();

    	SSL_load_error_strings();

	// Initial Mutexes
	if(sem_init(&server_certfile_passwd_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");

	if(sem_init(&client_certfile_passwd_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");
}

void uninit_openssl()
{
	if(is_using_safety_threads_for_openssl())
		thread_cleanup();

	ERR_free_strings();

	// Uninitial Mutexes
	if(sem_destroy(&server_certfile_passwd_mutex) != 0)
		int_error("Destroy a mutex failed");

	if(sem_destroy(&client_certfile_passwd_mutex) != 0)
		int_error("Destroy a mutex failed");
}

static void init_dhparams()
{
    	BIO *bio = NULL;

    	bio = BIO_new_file(DH512_FILE_PATH, "r");
    	if(!bio)
        	int_error("Opening file \"DH512_FILE_PATH\" failed");

    	dh512 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    	if(!dh512)
        	int_error("Reading DH parameters from file \"DH512_FILE_PATH\" failed");

    	BIO_free(bio);
	bio = NULL;

	bio = BIO_new_file(DH1024_FILE_PATH, "r");
    	if(!bio)
        	int_error("Opening file \"DH1024_FILE_PATH\" failed");

    	dh1024 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    	if(!dh1024)
        	int_error("Reading DH parameters from file \"DH1024_FILE_PATH\" failed");

    	BIO_free(bio);
	bio = NULL;
}

static DH *tmp_dh_callback(SSL *ssl, int is_export_flag, int key_length)
{
    	DH *ret = NULL;

    	if(!dh512 || !dh1024)
        	init_dhparams();

    	switch(key_length)
    	{
        	case 512:
            		ret = dh512;
            		break;

        	case 1024:
        	default: // Generating DH params is too costly to do on the fly
            		ret = dh1024;
            		break;
    	}

    	return ret;
}

static void setup_server_certfile_password(char *passwd)
{
	if(sem_wait(&server_certfile_passwd_mutex) != 0)
		int_error("Mutex lock function failed");

	strcpy(server_certfile_passwd, passwd);

	if(sem_post(&server_certfile_passwd_mutex) != 0)
		int_error("Mutex unlock function failed");
}

static void setup_client_certfile_password(char *passwd)
{
	if(sem_wait(&client_certfile_passwd_mutex) != 0)
		int_error("Mutex lock function failed");

	strcpy(client_certfile_passwd, passwd);

	if(sem_post(&client_certfile_passwd_mutex) != 0)
		int_error("Mutex unlock function failed");
}

static int server_certfile_password_callback(char *buffer, int num, int rw_flag, void *user_data)
{
	int passwd_length;

	if(sem_wait(&server_certfile_passwd_mutex) != 0)
		int_error("Mutex lock function failed");

	passwd_length = strlen(server_certfile_passwd);
	if(num < (passwd_length + 1))
	{
		if(sem_post(&server_certfile_passwd_mutex) != 0)
			int_error("Mutex unlock function failed");

		return 0;
	}

	strncpy(buffer, server_certfile_passwd, passwd_length);

	if(sem_post(&server_certfile_passwd_mutex) != 0)
		int_error("Mutex unlock function failed");

	return passwd_length;
}

static int client_certfile_password_callback(char *buffer, int num, int rw_flag, void *user_data)
{
	int passwd_length;

	if(sem_wait(&client_certfile_passwd_mutex) != 0)
		int_error("Mutex lock function failed");

	passwd_length = strlen(client_certfile_passwd);
	if(num < (passwd_length + 1))
	{
		if(sem_post(&client_certfile_passwd_mutex) != 0)
			int_error("Mutex unlock function failed");

		return 0;
	}

	strncpy(buffer, client_certfile_passwd, passwd_length);

	if(sem_post(&client_certfile_passwd_mutex) != 0)
		int_error("Mutex unlock function failed");

	return passwd_length;
}

static int ctx_verify_callback(int ok, X509_STORE_CTX *store)
{
    	char data[256];
 
    	if(!ok)
    	{
        	X509 *cert = X509_STORE_CTX_get_current_cert(store);
        	int  depth = X509_STORE_CTX_get_error_depth(store);
        	int  err   = X509_STORE_CTX_get_error(store);
 
        	fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        	X509_NAME_oneline(X509_get_issuer_name(cert), data, sizeof(data));
        	fprintf(stderr, "  issuer   = %s\n", data);
        	X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
        	fprintf(stderr, "  subject  = %s\n", data);
        	fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    	}
 
    	return ok;
}

SSL_CTX *setup_server_ctx(const char *cert_path, char *passwd, const char *rootca_pub_certfile_path)
{
    	SSL_CTX *ctx = NULL;
 
    	ctx = SSL_CTX_new(SSLv23_method());
    	if(SSL_CTX_load_verify_locations(ctx, rootca_pub_certfile_path, CA_DIR_PATH) != 1)
        	int_error("Loading CA file or directory failed");

    	if(SSL_CTX_set_default_verify_paths(ctx) != 1)
        	int_error("Loading default CA file or directory failed");

    	if(SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1)
        	int_error("Loading certificate from file \"cert_path\" failed");

	setup_server_certfile_password(passwd);
	SSL_CTX_set_default_passwd_cb(ctx, server_certfile_password_callback);

    	if(SSL_CTX_use_PrivateKey_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1)
        	int_error("Loading private key from file \"cert_path\" failed");

    	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ctx_verify_callback);
   	SSL_CTX_set_verify_depth(ctx, 4);
    	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
    	SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_callback);

    	if(SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        	int_error("Setting cipher list (no valid ciphers) failed");

    	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    	return ctx;
}

SSL_CTX *setup_client_ctx(const char *cert_path, char *passwd, const char *rootca_pub_certfile_path)
{
	SSL_CTX *ctx = NULL;
 
	ctx = SSL_CTX_new(SSLv23_method());
	if(SSL_CTX_load_verify_locations(ctx, rootca_pub_certfile_path, CA_DIR_PATH) != 1)
		int_error("Loading CA file or directory failed");

    	if(SSL_CTX_set_default_verify_paths(ctx) != 1)
        	int_error("Loading default CA file or directory failed");

    	if(SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1)
        	int_error("Loading certificate from file \"cert_path\" failed");

	setup_client_certfile_password(passwd);
	SSL_CTX_set_default_passwd_cb(ctx, client_certfile_password_callback);

    	if(SSL_CTX_use_PrivateKey_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1)
        	int_error("Loading private key from file \"cert_path\" failed");

    	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ctx_verify_callback);
    	SSL_CTX_set_verify_depth(ctx, 4);
    	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);

    	if(SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        	int_error("Setting cipher list (no valid ciphers) failed");

   	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    	return ctx;
}

// "authority_name" can be NULL if authority_verification_flag is set to be false
long post_connection_check(SSL *ssl, char **hosts, unsigned int no_hosts, boolean authority_verification_flag, char *authority_name)
{
    	X509      *cert = NULL;
    	X509_NAME *subj = NULL;
    	char      data[80];
    	int       ext_count;
	int       i;

	if(authority_verification_flag && !authority_name)
		goto err_occured;

    	if(!(cert = SSL_get_peer_certificate(ssl)))
        	goto err_occured;

    	if((ext_count = X509_get_ext_count(cert)) > 0)
    	{
        	for(i = 0; i < ext_count; i++)
        	{
            		char              *extstr = NULL;
            		X509_EXTENSION    *ext    = NULL;
 
            		ext = X509_get_ext(cert, i);
            		extstr = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
 
            		if(!strcmp(extstr, "subjectAltName"))
            		{
                		int                  j;
                		unsigned char        *data    = NULL;
                		STACK_OF(CONF_VALUE) *val     = NULL;
                		CONF_VALUE           *nval    = NULL;
                		X509V3_EXT_METHOD    *meth    = NULL;
                		void                 *ext_str = NULL;
 
                		if(!(meth = (X509V3_EXT_METHOD *)X509V3_EXT_get(ext)))
                    			break;

                		data = ext->value->data;
 
				#if (OPENSSL_VERSION_NUMBER > 0x00907000L)     
                		if(meth->it)
                  			ext_str = ASN1_item_d2i(NULL, (const unsigned char **)&data, ext->value->length, ASN1_ITEM_ptr(meth->it));
                		else
                  			ext_str = meth->d2i(NULL, (const unsigned char **)&data, ext->value->length);
				#else
                			ext_str = meth->d2i(NULL, (const unsigned char **)&data, ext->value->length);
				#endif

                		val = meth->i2v(meth, ext_str, NULL);
                		for(j = 0; j < sk_CONF_VALUE_num(val); j++)
                		{
					int k;

                    			nval = sk_CONF_VALUE_value(val, j);
					if(strcmp(nval->name, "DNS") == 0)
					{
						for(k = 0; k < no_hosts; k++)
						{
							if(authority_verification_flag)
							{
								if(strstr(nval->value, hosts[k]) && strstr(nval->value, authority_name))
								{
		                					goto hostname_confirmed;
								}
								else if(strcmp(hosts[k], USER_CN) == 0 && 
									strstr(nval->value, USER_IDENTITY_TOKEN) && 
									strstr(nval->value, authority_name))
								{
									goto hostname_confirmed;
								}
								else if(strcmp(hosts[k], ADMIN_CN) == 0 && 
									strstr(nval->value, ADMIN_IDENTITY_TOKEN) && 
									strstr(nval->value, authority_name))
								{
									goto hostname_confirmed;
								}
							}
							else
							{
								if(strstr(nval->value, hosts[k]))
		                					goto hostname_confirmed;
								else if(strcmp(hosts[k], USER_CN) == 0 && strstr(nval->value, USER_IDENTITY_TOKEN))
									goto hostname_confirmed;
								else if(strcmp(hosts[k], ADMIN_CN) == 0 && strstr(nval->value, ADMIN_IDENTITY_TOKEN))
									goto hostname_confirmed;
							}
						}
					}
                		}
            		}
        	}
    	}
 
    	if((subj = X509_get_subject_name(cert)) && X509_NAME_get_text_by_NID(subj, NID_commonName, data, sizeof(data)) > 0)
    	{
		int i;
        	data[sizeof(data)-1] = 0;

		for(i = 0; i < no_hosts; i++)
		{
			if(authority_verification_flag)
			{
				if(strstr(data, hosts[i]) && strstr(data, authority_name))
		                	goto hostname_confirmed;
				else if(strcmp(hosts[i], USER_CN) == 0 && strstr(data, USER_IDENTITY_TOKEN) && strstr(data, authority_name))
					goto hostname_confirmed;
				else if(strcmp(hosts[i], ADMIN_CN) == 0 && strstr(data, ADMIN_IDENTITY_TOKEN) && strstr(data, authority_name))
					goto hostname_confirmed;
			}
			else
			{
				if(strstr(data, hosts[i]))
		                	goto hostname_confirmed;
				else if(strcmp(hosts[i], USER_CN) == 0 && strstr(data, USER_IDENTITY_TOKEN))
					goto hostname_confirmed;
				else if(strcmp(hosts[i], ADMIN_CN) == 0 && strstr(data, ADMIN_IDENTITY_TOKEN))
					goto hostname_confirmed;
			}
		}
    	}

err_occured:
    	if(cert)
        	X509_free(cert);

    	return X509_V_ERR_APPLICATION_VERIFICATION;

hostname_confirmed:
 
    	X509_free(cert);
    	return SSL_get_verify_result(ssl);
}

// Either "cert_ownername_ret" or "entity_type_ret" or both of them can be NULL
void get_cert_ownername(SSL *ssl_client, char *authority_name, char *cert_ownername_ret, entity_type *entity_type_ret)
{
	X509      *cert    = NULL;
	X509_NAME *subject = NULL;
	char      cert_owner_info[USER_NAME_LENGTH + AUTHORITY_NAME_LENGTH + 10];

	// Get a certificate owner info from an SSL certificate
	if(!(cert = SSL_get_peer_certificate(ssl_client)))
		int_error("Getting a client's certificate failed");

	subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subject, NID_commonName, cert_owner_info, sizeof(cert_owner_info));

	if(strstr(cert_owner_info, ADMIN_IDENTITY_TOKEN))   // Admin
	{
		if(entity_type_ret)
		{
			*entity_type_ret = admin;
		}

		if(cert_ownername_ret)
		{
			strncpy(cert_ownername_ret, cert_owner_info + strlen(authority_name) + 1, 
				strlen(cert_owner_info) - (strlen(authority_name) + 1) - strlen(ADMIN_IDENTITY_TOKEN));
			cert_ownername_ret[strlen(cert_owner_info) - (strlen(authority_name) + 1) - strlen(ADMIN_IDENTITY_TOKEN)] = 0;
		}
	}
	else if(strstr(cert_owner_info, USER_IDENTITY_TOKEN))  // Normal user
	{
		if(entity_type_ret)
		{
			*entity_type_ret = user;
		}

		if(cert_ownername_ret)
		{
			strncpy(cert_ownername_ret, cert_owner_info + strlen(authority_name) + 1, 
				strlen(cert_owner_info) - (strlen(authority_name) + 1) - strlen(USER_IDENTITY_TOKEN));
			cert_ownername_ret[strlen(cert_owner_info) - (strlen(authority_name) + 1) - strlen(USER_IDENTITY_TOKEN)] = 0;
		}
	}
	else  // Server
	{
		if(entity_type_ret)
		{
			*entity_type_ret = server;
		}

		if(cert_ownername_ret)
		{
			strcpy(cert_ownername_ret, cert_owner_info + strlen(authority_name) + 1);
		}
	}
}

// Either "cert_owner_authority_name_ret" or "cert_ownername_ret" or both of them can be NULL
void get_cert_owner_info(SSL *ssl_client, char *cert_owner_authority_name_ret, char *cert_ownername_ret)
{
	X509      *cert    = NULL;
	X509_NAME *subject = NULL;
	char      cert_owner_info[USER_NAME_LENGTH + AUTHORITY_NAME_LENGTH + 10];
	char      authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Get a certificate owner info from an SSL certificate
	if(!(cert = SSL_get_peer_certificate(ssl_client)))
		int_error("Getting a client's certificate failed");

	subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subject, NID_commonName, cert_owner_info, sizeof(cert_owner_info));

	strncpy(authority_name, cert_owner_info, strstr(cert_owner_info, ".") - cert_owner_info);
	authority_name[strstr(cert_owner_info, ".") - cert_owner_info] = 0;

	if(cert_owner_authority_name_ret)
	{
		strcpy(cert_owner_authority_name_ret, authority_name);
	}

	if(cert_ownername_ret)
	{
		strncpy(cert_ownername_ret, cert_owner_info + strlen(authority_name) + 1, 
			strlen(cert_owner_info) - (strlen(authority_name) + 1) - strlen(USER_IDENTITY_TOKEN));
		cert_ownername_ret[strlen(cert_owner_info) - (strlen(authority_name) + 1) - strlen(USER_IDENTITY_TOKEN)] = 0;
	}
}

void exec_cmd(char *cmd, unsigned int cmd_length, char *result, unsigned int result_size)
{
	FILE *pipe      = NULL;
	char *final_cmd = NULL;

	final_cmd = (char *)malloc(sizeof(char)*(cmd_length + sizeof(char)*strlen(" 2>&1") + 100));
	if(!final_cmd)
	{
		int_error("Allocating memory for \"final_cmd\" failed");
	}

	sprintf(final_cmd, "%s 2>&1", cmd);
	pipe = popen(final_cmd, "r");
	free(final_cmd);
	final_cmd = NULL;

    	if(!pipe) 
	{
		strcpy(result, "ERROR");
		return;
	}

	#define MAX_NREAD_EMPTY_STRING 100
	unsigned int nread_empty_string = 0;
	unsigned int result_count       = 0;

	strcpy(result, "");
    	while(!feof(pipe) && result_count < result_size)
	{
		unsigned int nread;
		char buffer[200];

		if((result_size-1) - result_count >= sizeof(buffer)-1)
			nread = sizeof(buffer)-1;
		else
			nread = (result_size-1) - result_count;	

        	if(fgets(buffer, nread+1, pipe) != NULL)
		{
			if(strcmp(buffer, "") == 0)
			{
				nread_empty_string++;
				if(nread_empty_string > MAX_NREAD_EMPTY_STRING)
					break;
			}
			else
			{
				nread_empty_string = 0;
				buffer[nread] = 0;
				strcat(result, buffer);
				result_count += strlen(buffer);
			}
		}
    	}

	result[result_count] = 0;
    	pclose(pipe);

/*	#define WEXITSTATUS(status) (((status)>>8) & 0xFF)

	int res;
	res = system(cmd);

	strcpy(result, "");
    	if(WEXITSTATUS(res) != 0) 
        	strcpy(result, "System call error!");*/
}

boolean get_file_size(const char *file_path, unsigned int *file_size_ret)
{
	int         fd;
	struct stat stat_file;
 
	fd = open(file_path, O_RDONLY);
	if(fd == -1)
		return false;
 
	if(fstat(fd, &stat_file) == -1)
		int_error("fstat() failed");

	close(fd);

	*file_size_ret = stat_file.st_size;
	return true;
}

// "data_size_ret" can be NULL
boolean read_bin_file(const char *file_path, char *buffer_ret, unsigned int buffer_size, unsigned int *data_size_ret)
{
	FILE         *fp = NULL;
	unsigned int nread;
	unsigned int read_length;

	fp = fopen(file_path, "rb");
	if(!fp)
		return false;

	read_length = 0;
	while(!feof(fp) && read_length < buffer_size)
	{
  		nread = fread(buffer_ret + read_length, 1, buffer_size - read_length, fp);
		read_length += nread;

		if(nread == 0 && ferror(fp))
			int_error("fread() failed");
	}

	fclose(fp);
	fp = NULL;

	if(data_size_ret)
	{
		*data_size_ret = read_length;
	}

	buffer_ret[read_length] = 0;
	return true;
}

boolean write_bin_file(const char *file_path, char *mode, char *buffer, unsigned int data_len)
{
	FILE         *fp = NULL;
	unsigned int nwritten;

	fp = fopen(file_path, mode);
	if(!fp)
		return false;

	nwritten = 0;
	do
	{
		unsigned int n;
		n = fwrite(buffer + nwritten, 1, data_len - nwritten, fp);
		nwritten += n;

		if(ferror(fp))
			int_error("fwrite() failed");
	}
	while(nwritten < data_len);

	fclose(fp);
	fp = NULL;

	return true;
}

// Generate a random 8 character password
void gen_random_password(char *passwd_ret)
{
	char cmd[23];
	char ret_code[ERR_MSG_LENGTH + 1];

	sprintf(cmd, "openssl rand -base64 6");
	exec_cmd(cmd, strlen(cmd), ret_code, sizeof(ret_code));

	// Function returns an 8 character password with new line character
	if(strlen(ret_code) != 9)
	{
		fprintf(stderr, "err_code: \"%s\"\n", ret_code);
		int_error("Generating a random password failed");
	}

	strncpy(passwd_ret, ret_code, 8);
	passwd_ret[8] = 0;
}

/* 
*  Notice that: encryption by using SMIME will affect to some special character 
*  (i.e., '\n' will be encoded as '\r\n' when data is decrypted).
*/ 

// "err_msg_ret" can be NULL
boolean smime_encrypt_with_cert(const char *plaintext_path, const char *ciphertext_path, const char *certfile_path, char *err_msg_ret)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	if(err_msg_ret)
		strcpy(err_msg_ret, "");

	sprintf(cmd, "openssl smime -encrypt -binary -des3 -in \"%s\" -out \"%s\" -outform DER \"%s\"", plaintext_path, ciphertext_path, certfile_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		if(err_msg_ret)
			strcpy(err_msg_ret, err_code);
		else
			fprintf(stderr, "err_code: \"%s\"\n", err_code);

		return false;
	}

	return true;
}

// "err_msg_ret" can be NULL
boolean smime_decrypt_with_cert(const char *ciphertext_path, const char *plaintext_path, const char *certfile_path, char *passwd, char *err_msg_ret)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	if(err_msg_ret)
		strcpy(err_msg_ret, "");
	
	sprintf(cmd, "openssl smime -decrypt -binary -in \"%s\" -inform DER -out \"%s\" -inkey \"%s\" -passin pass:%s", 
		ciphertext_path, plaintext_path, certfile_path, passwd);

	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		if(err_msg_ret)
			strcpy(err_msg_ret, err_code);
		else
			fprintf(stderr, "err_code: \"%s\"\n", err_code);

		return false;
	}

	return true;
}

// "err_msg_ret" can be NULL
boolean smime_sign_with_cert(const char *data_path, const char *signed_data_path, const char *certfile_path, char *passwd, char *err_msg_ret)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	if(err_msg_ret)
		strcpy(err_msg_ret, "");

	sprintf(cmd, "openssl smime -sign -in \"%s\" -out \"%s\" -signer \"%s\" -inkey \"%s\" -certfile \"%s\" -passin pass:%s", 
		data_path, signed_data_path, certfile_path, certfile_path, certfile_path, passwd);

	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		if(err_msg_ret)
			strcpy(err_msg_ret, err_code);
		else
			fprintf(stderr, "err_code: \"%s\"\n", err_code);

		return false;
	}

	return true;
}

// "err_msg_ret" can be NULL
boolean smime_verify_with_cert(const char *signed_data_path, const char *data_path, const char *CAfile_path, char *err_msg_ret)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	if(err_msg_ret)
		strcpy(err_msg_ret, "");

	sprintf(cmd, "openssl smime -verify -in \"%s\" -CAfile \"%s\" -out \"%s\"", signed_data_path, CAfile_path, data_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));
	if(strstr(err_code, "Verification successful") == NULL)
	{
		if(err_msg_ret)
			strcpy(err_msg_ret, err_code);
		else
			fprintf(stderr, "err_code: \"%s\"\n", err_code);

		return false;
	}

	return true;
}

// "err_msg_ret" can be NULL
boolean des3_encrypt(const char *plaintext_path, const char *ciphertext_path, char *passwd, char *err_msg_ret)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	if(err_msg_ret)
		strcpy(err_msg_ret, "");

	sprintf(cmd, "openssl des3 -in \"%s\" -out \"%s\" -pass pass:%s", plaintext_path, ciphertext_path, passwd);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		if(err_msg_ret)
			strcpy(err_msg_ret, err_code);
		else
			fprintf(stderr, "err_code: \"%s\"\n", err_code);

		return false;
	}

	return true;
}

// "err_msg_ret" can be NULL
boolean des3_decrypt(const char *ciphertext_path, const char *plaintext_path, char *passwd, char *err_msg_ret)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	if(err_msg_ret)
		strcpy(err_msg_ret, "");

	sprintf(cmd, "openssl des3 -d -in \"%s\" -out \"%s\" -pass pass:%s", ciphertext_path, plaintext_path, passwd);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		if(err_msg_ret)
			strcpy(err_msg_ret, err_code);
		else
			fprintf(stderr, "err_code: \"%s\"\n", err_code);

		return false;
	}

	return true;
}

int BIO_recv(BIO *peer, char *buf, int buf_len)
{
	int          err = 0;
	unsigned int nread;

	for(nread = 0; nread < buf_len; nread += err)
        {
        	err = BIO_read(peer, buf + nread, buf_len - nread);
             	if(err <= 0)
                 	break;
        }

	return err;
}

int BIO_send(BIO *peer, char *buf, int buf_len)
{
	int err = 0;
	int nwritten;

	for(nwritten = 0; nwritten < buf_len; nwritten += err)
        {
            	err = BIO_write(peer, buf + nwritten, buf_len - nwritten);
            	if(err <= 0)
                	break;
        }

	return err;
}

static char *get_SSL_error(SSL *peer, int value, char *err_status_ret)
{
	switch(SSL_get_error(peer, value))
	{
		case SSL_ERROR_NONE:
			strcpy(err_status_ret, "SSL_ERROR_NONE");
			break;

		case SSL_ERROR_ZERO_RETURN:
			strcpy(err_status_ret, "SSL_ERROR_ZERO_RETURN");
			break;

		case SSL_ERROR_WANT_READ:
			strcpy(err_status_ret, "SSL_ERROR_WANT_READ");
			break;

		case SSL_ERROR_WANT_WRITE:
			strcpy(err_status_ret, "SSL_ERROR_WANT_WRITE");
			break;

		case SSL_ERROR_WANT_CONNECT:
			strcpy(err_status_ret, "SSL_ERROR_WANT_CONNECT");
			break;

		case SSL_ERROR_WANT_ACCEPT:
			strcpy(err_status_ret, "SSL_ERROR_WANT_ACCEPT");
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			strcpy(err_status_ret, "SSL_ERROR_WANT_X509_LOOKUP");
			break;

		case SSL_ERROR_SYSCALL:
			strcpy(err_status_ret, "SSL_ERROR_SYSCALL");
			break;

		case SSL_ERROR_SSL:
			strcpy(err_status_ret, "SSL_ERROR_SSL");
			break;

		default:
			strcpy(err_status_ret, "INVALID_ERROR");
			break;
	}

	return err_status_ret;
}

int SSL_recv(SSL *peer, char *buf, int buf_len)
{
	int          err = 0;
	unsigned int nread;

	for(nread = 0; nread < buf_len; nread += err)
        {
        	err = SSL_read(peer, buf + nread, buf_len - nread);
             	if(err <= 0)
		{
			int error_meaning = SSL_get_error(peer, err);
			if(error_meaning == SSL_ERROR_WANT_READ)
			{
				err = 0;
				sleep(1);
			}
			else if(error_meaning != SSL_ERROR_NONE)
			{
				char err_msg[ERR_MSG_LENGTH + 1];
				printf("SSL_read(): %s\n", get_SSL_error(peer, err, err_msg));
                 		return error_meaning;
			}
		}
        }

	return SSL_ERROR_NONE;
}

int SSL_send(SSL *peer, char *buf, int buf_len)
{
	int err = 0;
	int nwritten;

	for(nwritten = 0; nwritten < buf_len; nwritten += err)
        {
            	err = SSL_write(peer, buf + nwritten, buf_len - nwritten);
		if(err <= 0)
		{
			int error_meaning = SSL_get_error(peer, err);
			if(error_meaning == SSL_ERROR_WANT_WRITE)
			{
				err = 0;
				sleep(1);
			}
			else if(error_meaning != SSL_ERROR_NONE)
			{
				char err_msg[ERR_MSG_LENGTH + 1];
				printf("SSL_write(): %s", get_SSL_error(peer, err, err_msg));
                 		return error_meaning;
			}
		}
        }

	return SSL_ERROR_NONE;
}

void SSL_cleanup(SSL *conn)
{
	if(SSL_get_shutdown(conn) & SSL_RECEIVED_SHUTDOWN)
		SSL_shutdown(conn);
    	else
        	SSL_clear(conn);

	SSL_free(conn);
	conn = NULL;
}

// If any error occur, it will not show the error message to the console
int SSL_send_ignore_error(SSL *peer, char *buf, int buf_len)
{
	int err = 0;
	int nwritten;

	for(nwritten = 0; nwritten < buf_len; nwritten += err)
        {
            	err = SSL_write(peer, buf + nwritten, buf_len - nwritten);
		if(err <= 0)
		{
			int error_meaning = SSL_get_error(peer, err);
			if(error_meaning == SSL_ERROR_WANT_WRITE)
			{
				err = 0;
				sleep(1);
			}
			else if(error_meaning != SSL_ERROR_NONE)
			{
                 		return error_meaning;
			}
		}
        }

	return SSL_ERROR_NONE;
}

// If any error occur, it will not show the error message to the console
int SSL_recv_ignore_error(SSL *peer, char *buf, int buf_len)
{
	int          err = 0;
	unsigned int nread;

	for(nread = 0; nread < buf_len; nread += err)
        {
        	err = SSL_read(peer, buf + nread, buf_len - nread);
             	if(err <= 0)
		{
			int error_meaning = SSL_get_error(peer, err);
			if(error_meaning == SSL_ERROR_WANT_READ)
			{
				err = 0;
				sleep(1);
			}
			else if(error_meaning != SSL_ERROR_NONE)
			{
                 		return error_meaning;
			}
		}
        }

	return SSL_ERROR_NONE;
}

#define BUF_SIZE 		1000	// Include null-terminated character
#define PREFIX_SIZE 		4	// Exclude null-terminated character
#define MAX_DATA_DIGIT_LENGTH 	3

boolean BIO_recv_file(BIO *peer, const char *file_path)
{
	unlink(file_path);

	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int data_len;
	char         data_len_str[MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	for(;;)
    	{
		// Read data from peer
		ret_code = BIO_recv(peer, buf, BUF_SIZE);
		if(ret_code <= 0)
		{
			// Transmission error occurred
			return false;
		}

		if(buf[0] == '1')    	// End of file
			break;

		memcpy(data_len_str, buf + 1, MAX_DATA_DIGIT_LENGTH);
		data_len_str[MAX_DATA_DIGIT_LENGTH] = 0;
	
		// Write data to file
		data_len = atoi(data_len_str);
		if(!write_bin_file(file_path, "ab", buf + PREFIX_SIZE, data_len))
		{
			// Writing file failed
			return false;
		}
    	}

	return true;
}

boolean BIO_send_file(BIO *peer, const char *file_path)
{
	FILE         *fp = NULL;
	char         buf[BUF_SIZE];		// Include null-terminated character
	char         prefix[PREFIX_SIZE + 1];	// Exclude null-terminated character
	unsigned int nread;
	unsigned int read_length;
	int          ret_code;

	fp = fopen(file_path, "rb");
	if(!fp)
		return false;

	while(!feof(fp))
	{
		// Read data from file
		read_length = 0;
		while(!feof(fp) && read_length < (BUF_SIZE - PREFIX_SIZE))
		{
	  		nread = fread(buf + PREFIX_SIZE + read_length, 1, BUF_SIZE - PREFIX_SIZE - read_length, fp);
			read_length += nread;

			if(nread == 0 && ferror(fp))
				int_error("fread() failed");
		}

		// Send data to peer
		sprintf(prefix, "0%03d", read_length);     // '0' at first character means the data segment isn't the end of file
		memcpy(buf, prefix, PREFIX_SIZE);
		
		ret_code = BIO_send(peer, buf, BUF_SIZE);
		if(ret_code <= 0)
		{
			// Transmission error occurred
			fclose(fp);
			fp = NULL;
			return false;
		}
	}

	fclose(fp);
	fp = NULL;

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of file
	ret_code = BIO_send(peer, buf, BUF_SIZE);
	if(ret_code <= 0)
	{
		// Transmission error occurred
		return false;
	}
	else
	{
		return true;
	}
}

boolean SSL_recv_file(SSL *peer, const char *file_path)
{
	unlink(file_path);

	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int data_len;
	char         data_len_str[MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	for(;;)
    	{
		// Read data from peer
		ret_code = SSL_recv(peer, buf, BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			return false;
		}

		if(buf[0] == '1')    	// End of file
			break;

		memcpy(data_len_str, buf + 1, MAX_DATA_DIGIT_LENGTH);
		data_len_str[MAX_DATA_DIGIT_LENGTH] = 0;
	
		// Write data to file
		data_len = atoi(data_len_str);
		if(!write_bin_file(file_path, "ab", buf + PREFIX_SIZE, data_len))
		{
			// Writing file failed
			return false;
		}
    	}

	return true;
}

boolean SSL_send_file(SSL *peer, const char *file_path)
{
	FILE         *fp = NULL;
	char         buf[BUF_SIZE];		// Include null-terminated character
	char         prefix[PREFIX_SIZE + 1];	// Exclude null-terminated character
	unsigned int nread;
	unsigned int read_length;
	int          ret_code;

	fp = fopen(file_path, "rb");
	if(!fp)
		return false;

	while(!feof(fp))
	{
		// Read data from file
		read_length = 0;
		while(!feof(fp) && read_length < (BUF_SIZE - PREFIX_SIZE))
		{
	  		nread = fread(buf + PREFIX_SIZE + read_length, 1, BUF_SIZE - PREFIX_SIZE - read_length, fp);
			read_length += nread;

			if(nread == 0 && ferror(fp))
				int_error("fread() failed");
		}

		// Send data to peer
		sprintf(prefix, "0%03d", read_length);     // '0' at first character means the data segment isn't the end of file
		memcpy(buf, prefix, PREFIX_SIZE);
		
		ret_code = SSL_send(peer, buf, BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			fclose(fp);
			fp = NULL;
			return false;
		}
	}

	fclose(fp);
	fp = NULL;

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of file
	ret_code = SSL_send(peer, buf, BUF_SIZE);
	if(ret_code != SSL_ERROR_NONE)
	{
		// Transmission error occurred
		return false;
	}
	else
	{
		return true;
	}
}

#define LARGE_FILE_BUF_SIZE 		  1000000  // Include null-terminated character
#define LARGE_FILE_PREFIX_SIZE 		  7	   // Exclude null-terminated character
#define LARGE_FILE_MAX_DATA_DIGIT_LENGTH  6

boolean SSL_recv_large_file(SSL *peer, const char *file_path)
{
	unlink(file_path);

	char         *buf = NULL;  // Include null-terminated character
	unsigned int data_len;
	char         data_len_str[LARGE_FILE_MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	// Allocate heap variable
	buf = (char *)malloc(sizeof(char)*LARGE_FILE_BUF_SIZE);
	if(!buf)
	{
		int_error("Allocating memory for \"buf\" failed");
	}

	for(;;)
    	{
		// Read data from peer
		ret_code = SSL_recv(peer, buf, LARGE_FILE_BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			goto ERROR;
		}

		if(buf[0] == '1')    	// End of file
			break;

		memcpy(data_len_str, buf + 1, LARGE_FILE_MAX_DATA_DIGIT_LENGTH);
		data_len_str[LARGE_FILE_MAX_DATA_DIGIT_LENGTH] = 0;
	
		// Write data to file
		data_len = atoi(data_len_str);
		if(!write_bin_file(file_path, "ab", buf + LARGE_FILE_PREFIX_SIZE, data_len))
		{
			// Writing file failed
			goto ERROR;
		}
    	}

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	return true;

ERROR:

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	return false;
}

boolean SSL_send_large_file(SSL *peer, const char *file_path)
{
	FILE         *fp  = NULL;
	char         *buf = NULL;	                  // Include null-terminated character
	char         prefix[LARGE_FILE_PREFIX_SIZE + 1];  // Exclude null-terminated character
	unsigned int nread;
	unsigned int read_length;
	int          ret_code;

	fp = fopen(file_path, "rb");
	if(!fp)
		goto ERROR;

	// Allocate heap variable
	buf = (char *)malloc(sizeof(char)*LARGE_FILE_BUF_SIZE);
	if(!buf)
	{
		int_error("Allocating memory for \"buf\" failed");
	}

	while(!feof(fp))
	{
		// Read data from file
		read_length = 0;
		while(!feof(fp) && read_length < (LARGE_FILE_BUF_SIZE - LARGE_FILE_PREFIX_SIZE))
		{
	  		nread = fread(buf + LARGE_FILE_PREFIX_SIZE + read_length, 1, LARGE_FILE_BUF_SIZE - LARGE_FILE_PREFIX_SIZE - read_length, fp);
			read_length += nread;

			if(nread == 0 && ferror(fp))
				int_error("fread() failed");
		}

		// Send data to peer
		sprintf(prefix, "0%06d", read_length);		// '0' at first character means the data segment isn't the end of file
		memcpy(buf, prefix, LARGE_FILE_PREFIX_SIZE);
		
		ret_code = SSL_send(peer, buf, LARGE_FILE_BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			goto ERROR;
		}
	}

	fclose(fp);
	fp = NULL;

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of file
	ret_code = SSL_send(peer, buf, LARGE_FILE_BUF_SIZE);

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	if(ret_code != SSL_ERROR_NONE)
	{
		// Transmission error occurred
		goto ERROR;
	}
	else
	{
		return true;
	}

ERROR:

	if(fp)
	{
		fclose(fp);
		fp = NULL;
	}

	// Free heap variable
	if(buf)
	{
		free(buf);
		buf = NULL;
	}

	return false;
}

boolean BIO_recv_buffer(BIO *peer, char *buffer_ret, unsigned int *buffer_size_ret)
{
	unsigned int base_index = 0;
	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int data_len;
	char         data_len_str[MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	for(;;)
    	{
		// Read data from peer
		ret_code = BIO_recv(peer, buf, BUF_SIZE);
		if(ret_code <= 0)
		{
			if(buffer_size_ret)
				*buffer_size_ret = 0;

			// Transmission error occurred
			return false;
		}

		if(buf[0] == '1')    	// End of buffer
			break;

		memcpy(data_len_str, buf+1, MAX_DATA_DIGIT_LENGTH);
		data_len_str[MAX_DATA_DIGIT_LENGTH] = 0;
	
		// Write data to buffer
		data_len = atoi(data_len_str);
		memcpy(buffer_ret+base_index, buf + PREFIX_SIZE, data_len);

		base_index += data_len;
    	}

	if(buffer_size_ret)
		*buffer_size_ret = base_index;

	return true;
}

boolean BIO_send_buffer(BIO *peer, char *buffer, int data_length)
{
	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int ch_count = 0;
	unsigned int ch_remainder, nread;
	int          ret_code;

	while(ch_count < data_length)
	{
		ch_remainder = data_length - ch_count;
		if(ch_remainder >= (BUF_SIZE - PREFIX_SIZE))
			nread = BUF_SIZE - PREFIX_SIZE;
		else
			nread = ch_remainder;

		sprintf(buf, "0%03d", nread);     // '0' at first character means the data segment isn't the end of file
		memcpy(buf + PREFIX_SIZE, buffer + ch_count, nread);

		// Send data to peer
		ret_code = BIO_send(peer, buf, BUF_SIZE);
		if(ret_code <= 0)
		{
			// Transmission error occurred
			return false;
		}

		ch_count += nread;
	}

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of buffer
	ret_code = BIO_send(peer, buf, BUF_SIZE);
	if(ret_code <= 0)
	{
		// Transmission error occurred
		return false;
	}
	else
	{
		return true;
	}
}

// "buffer_size_ret" can be NULL
boolean SSL_recv_buffer(SSL *peer, char *buffer_ret, unsigned int *buffer_size_ret)
{
	unsigned int base_index = 0;
	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int data_len;
	char         data_len_str[MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	for(;;)
    	{
		// Read data from peer
		ret_code = SSL_recv(peer, buf, BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			if(buffer_size_ret)
				*buffer_size_ret = 0;

			// Transmission error occurred
			return false;
		}

		if(buf[0] == '1')    	// End of buffer
			break;

		memcpy(data_len_str, buf+1, MAX_DATA_DIGIT_LENGTH);
		data_len_str[MAX_DATA_DIGIT_LENGTH] = 0;
	
		// Write data to buffer
		data_len = atoi(data_len_str);
		memcpy(buffer_ret+base_index, buf + PREFIX_SIZE, data_len);

		base_index += data_len;
    	}

	if(buffer_size_ret)
		*buffer_size_ret = base_index;

	return true;
}

boolean SSL_send_buffer(SSL *peer, char *buffer, int data_length)
{
	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int ch_count = 0;
	unsigned int ch_remainder, nread;
	int          ret_code;

	while(ch_count < data_length)
	{
		ch_remainder = data_length - ch_count;
		if(ch_remainder >= (BUF_SIZE - PREFIX_SIZE))
			nread = BUF_SIZE - PREFIX_SIZE;
		else
			nread = ch_remainder;

		sprintf(buf, "0%03d", nread);     // '0' at first character means the data segment isn't the end of file
		memcpy(buf + PREFIX_SIZE, buffer + ch_count, nread);

		// Send data to peer
		ret_code = SSL_send(peer, buf, BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			return false;
		}

		ch_count += nread;
	}

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of buffer
	ret_code = SSL_send(peer, buf, BUF_SIZE);
	if(ret_code != SSL_ERROR_NONE)
	{
		// Transmission error occurred
		return false;
	}
	else
	{
		return true;
	}
}

// If any error occur, it will not show the error message to the console ("buffer_size_ret" can be NULL)
boolean SSL_recv_buffer_ignore_error(SSL *peer, char *buffer_ret, unsigned int *buffer_size_ret)
{
	unsigned int base_index = 0;
	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int data_len;
	char         data_len_str[MAX_DATA_DIGIT_LENGTH + 1];
	int          ret_code;

	for(;;)
    	{
		// Read data from peer
		ret_code = SSL_recv_ignore_error(peer, buf, BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			if(buffer_size_ret)
				*buffer_size_ret = 0;

			// Transmission error occurred
			return false;
		}

		if(buf[0] == '1')    	// End of buffer
			break;

		memcpy(data_len_str, buf+1, MAX_DATA_DIGIT_LENGTH);
		data_len_str[MAX_DATA_DIGIT_LENGTH] = 0;
	
		// Write data to buffer
		data_len = atoi(data_len_str);
		memcpy(buffer_ret+base_index, buf + PREFIX_SIZE, data_len);

		base_index += data_len;
    	}

	if(buffer_size_ret)
		*buffer_size_ret = base_index;

	return true;
}

// If any error occur, it will not show the error message to the console
boolean SSL_send_buffer_ignore_error(SSL *peer, char *buffer, int data_length)
{
	char         buf[BUF_SIZE];	// Include null-terminated character
	unsigned int ch_count = 0;
	unsigned int ch_remainder, nread;
	int          ret_code;

	while(ch_count < data_length)
	{
		ch_remainder = data_length - ch_count;
		if(ch_remainder >= (BUF_SIZE - PREFIX_SIZE))
			nread = BUF_SIZE - PREFIX_SIZE;
		else
			nread = ch_remainder;

		sprintf(buf, "0%03d", nread);     // '0' at first character means the data segment isn't the end of file
		memcpy(buf + PREFIX_SIZE, buffer + ch_count, nread);

		// Send data to peer
		ret_code = SSL_send_ignore_error(peer, buf, BUF_SIZE);
		if(ret_code != SSL_ERROR_NONE)
		{
			// Transmission error occurred
			return false;
		}

		ch_count += nread;
	}

	strcpy(buf, "1");       // '1' at first character means the data segment is the end of buffer
	ret_code = SSL_send_ignore_error(peer, buf, BUF_SIZE);
	if(ret_code != SSL_ERROR_NONE)
	{
		// Transmission error occurred
		return false;
	}
	else
	{
		return true;
	}
}

// Either "ip_address_ret" or "port_number_ret" or both of them can be NULL
void BIO_get_peer_address(BIO *bio_peer, char *ip_address_ret, char *port_number_ret)
{
	int                sockfd;
	struct sockaddr_in adrr_inet;
	socklen_t          len_inet;
		
	if(BIO_get_fd(bio_peer, &sockfd) == 0)
		int_error("Getting file descriptor failed");

	len_inet = sizeof(adrr_inet);
	if(getpeername(sockfd, (struct sockaddr *)&adrr_inet, &len_inet) == -1)
		int_error("Getting peer name information failed");

	if(ip_address_ret)
	{
		strcpy(ip_address_ret, inet_ntoa(adrr_inet.sin_addr));
	}

	if(port_number_ret)
	{
		sprintf(port_number_ret, "%u", (unsigned)ntohs(adrr_inet.sin_port));
	}
}

// Either "ip_address_ret" or "port_number_ret" or both of them can be NULL
void SSL_get_peer_address(SSL *ssl_peer, char *ip_address_ret, char *port_number_ret)
{
	BIO_get_peer_address(SSL_get_rbio(ssl_peer), ip_address_ret, port_number_ret);
}

// "token_value" can be NULL
void write_token_into_buffer(char *token_name, char *token_value, boolean is_first_token_flag, char *buffer)
{
	if(!token_name)
		int_error("Token name is NULL");

	if(is_first_token_flag)
		buffer[0] = 0;

	char *tmp = NULL;
	if(token_value)
	{
		tmp = (char *)malloc(sizeof(char)*(strlen(token_name) + strlen(token_value) + 9));
		if(!tmp)
		{
			int_error("Allocating memory for \"tmp\" failed");
		}

		sprintf(tmp, "[\"%s\"=\"%s\"]\n", token_name, token_value);	
	}
	else
	{
		tmp = (char *)malloc(sizeof(char)*(strlen(token_name) + 6));
		if(!tmp)
		{
			int_error("Allocating memory for \"tmp\" failed");
		}

		sprintf(tmp, "[\"%s\"]\n", token_name);
	}

	strcat(buffer, tmp);

	free(tmp);
	tmp = NULL;
}

int read_token_from_buffer(char *buffer, int token_no, char *token_name_ret, char *token_value_ret)
{
	int token_count;
	int ret_val, i;

	ret_val            = READ_TOKEN_SUCCESS;
	token_count        = 1;
	token_name_ret[0]  = 0;
	token_value_ret[0] = 0;
	i                  = 0;

	while(token_count <= token_no)
	{
		int j = 0;

		if(buffer[i] == '\0')
		{
			token_count--;
			break;
		}

		// Read '['
		if(buffer[i] != '[')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read '"'
		i++;
		if(buffer[i] != '"')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read token name
		if(token_count == token_no)
			j = 0;

		while(1)
		{
			// Read '"'
			i++;
			if(buffer[i] == '"')
			{
				if(token_count == token_no)
					token_name_ret[j] = 0;
				break;
			}

			// Read invalid format if occurred
			if(buffer[i] == '[' || buffer[i] == ']' || buffer[i] == '=')
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}

			if(token_count == token_no)
			{
				token_name_ret[j] = buffer[i];
				j++;
			}
		}

		// Read ']' or '='
		i++;
		if(buffer[i] == ']')
		{
			if(token_count == token_no)
			{
				token_value_ret[0] = 0;
				break;
			}

			// Read '\r' or '\n'
			i++;
			if(buffer[i] != '\r' && buffer[i] != '\n')
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}

			// If read '\r' then a next read must be '\n'
			if(buffer[i] == '\r')
			{
				i++;
				if(buffer[i] != '\n')
				{
					ret_val = READ_TOKEN_INVALID;
					goto ERROR;
				}
			}

			i++;
			token_count++;
			continue;
		}

		if(buffer[i] != '=')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read '"'
		i++;
		if(buffer[i] != '"')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read token value
		if(token_count == token_no)
			j = 0;

		while(1)
		{
			// Read '"'
			i++;
			if(buffer[i] == '"')
			{
				if(token_count == token_no)
					token_value_ret[j] = 0;
				break;
			}
			
			// Read invalid format if occurred
			if(buffer[i] == '[' || buffer[i] == ']' /*|| buffer[i] == '='*/)
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}

			if(token_count == token_no)
			{
				token_value_ret[j] = buffer[i];
				j++;
			}
		}

		// Read ']'
		i++;
		if(buffer[i] != ']')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read '\r' or '\n'
		i++;
		if(buffer[i] != '\r' && buffer[i] != '\n')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// If read '\r' then a next read must be '\n'
		if(buffer[i] == '\r')
		{
			i++;
			if(buffer[i] != '\n')
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}
		}

		if(token_count == token_no)
			break;

		i++;
		token_count++;
	}

	if(token_count < token_no)
	{
		ret_val            = READ_TOKEN_END;
		token_name_ret[0]  = 0;
		token_value_ret[0] = 0;
	}

ERROR:

	return ret_val;
}

// "token_value" can be NULL
boolean write_token_into_file(char *token_name, char *token_value, boolean is_first_token_flag, const char *file_path)
{
	if(!token_name)
		int_error("Token name is NULL");

	FILE *fp = NULL;
	if(is_first_token_flag)
	{
		fp = fopen(file_path, "w");
	}
	else
	{
		fp = fopen(file_path, "a");
	}

	if(!fp)
		return false;

	char *tmp = NULL;
	if(token_value)
	{
		tmp = (char *)malloc(sizeof(char)*(strlen(token_name) + strlen(token_value) + 9));
		if(!tmp)
		{
			int_error("Allocating memory for \"tmp\" failed");
		}

		sprintf(tmp, "[\"%s\"=\"%s\"]\n", token_name, token_value);	
	}
	else
	{
		tmp = (char *)malloc(sizeof(char)*(strlen(token_name) + 6));
		if(!tmp)
		{
			int_error("Allocating memory for \"tmp\" failed");
		}

		sprintf(tmp, "[\"%s\"]\n", token_name);
	}
	
	fprintf(fp, "%s", tmp);
	free(tmp);
	tmp = NULL;

	fclose(fp);
	fp = NULL;
	return true;
}

int read_token_from_file(const char *file_path, int token_no, char *token_name_ret, char *token_value_ret)
{
	FILE *fp = NULL;
	int  token_count;
	int  ret_val;

	ret_val            = READ_TOKEN_SUCCESS;
	token_count        = 1;
	token_name_ret[0]  = 0;
	token_value_ret[0] = 0;

	fp = fopen(file_path, "r");
	if(!fp)
		goto FILE_OPEN_ERROR;

	while(!feof(fp) && token_count <= token_no)
	{
		int  i = 0, ch;

		// Read '['
		ch = fgetc(fp);
		if(ch == EOF)
		{
			token_count--;
			break;
		}

		if(ch != '[')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read '"'
		ch = fgetc(fp);
		if(ch != '"')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read token name
		if(token_count == token_no)
			i = 0;

		while(1)
		{
			// Read '"'
			ch = fgetc(fp);
			if(ch == '"')
			{
				if(token_count == token_no)
					token_name_ret[i] = 0;
				break;
			}
			
			// Read invalid format if occurred
			if(ch == '[' || ch == ']' || ch == '=' || ch == EOF)
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}

			if(token_count == token_no)
			{
				token_name_ret[i] = ch;
				i++;
			}
		}

		// Read ']' or '='
		ch = fgetc(fp);
		if(ch == ']')
		{
			if(token_count == token_no)
			{
				token_value_ret[0] = 0;
				break;
			}

			// Read '\r' or '\n'
			ch = fgetc(fp);
			if(ch != '\r' && ch != '\n')
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}

			// If read '\r' then a next read must be '\n'
			if(ch == '\r')
			{
				ch = fgetc(fp);
				if(ch != '\n')
				{
					ret_val = READ_TOKEN_INVALID;;
					goto ERROR;
				}
			}

			token_count++;
			continue;
		}

		if(ch != '=')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read '"'
		ch = fgetc(fp);
		if(ch != '"')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read token value
		if(token_count == token_no)
			i = 0;

		while(1)
		{
			// Read '"'
			ch = fgetc(fp);
			if(ch == '"')
			{
				if(token_count == token_no)
					token_value_ret[i] = 0;
				break;
			}
			
			// Read invalid format if occurred
			if(ch == '[' || ch == ']' /*|| ch == '='*/ || ch == EOF)
			{
				ret_val = READ_TOKEN_INVALID;
				goto ERROR;
			}

			if(token_count == token_no)
			{
				token_value_ret[i] = ch;
				i++;
			}
		}

		// Read ']'
		ch = fgetc(fp);
		if(ch != ']')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// Read '\r' or '\n'
		ch = fgetc(fp);
		if(ch != '\r' && ch != '\n')
		{
			ret_val = READ_TOKEN_INVALID;
			goto ERROR;
		}

		// If read '\r' then a next read must be '\n'
		if(ch == '\r')
		{
			ch = fgetc(fp);
			if(ch != '\n')
			{
				ret_val = READ_TOKEN_INVALID;;
				goto ERROR;
			}
		}

		if(token_count == token_no)
			break;

		token_count++;
	}

	if(token_count < token_no)
	{
		ret_val            = READ_TOKEN_END;
		token_name_ret[0]  = 0;
		token_value_ret[0] = 0;
	}

ERROR:

	fclose(fp);
	fp = NULL;
	return ret_val;

FILE_OPEN_ERROR:

	return READ_TOKEN_INVALID;
}

void sum_sha1_from_file(const char *file_path, char *sum_ret, const char *digest_path)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	sprintf(cmd, "sha1sum \"%s\" > \"%s\"", file_path, digest_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));

	if(strcmp(err_code, "") != 0)
		int_error("Hashing file failed");

	// Read the digest value from file
	if(!read_bin_file(digest_path, sum_ret, SHA1_DIGEST_LENGTH, NULL))
		int_error("Reading SHA1 checksum failed");

	sum_ret[SHA1_DIGEST_LENGTH] = 0;
	unlink(digest_path);
}

void sum_sha1_from_string(char *string, unsigned int length, char *hash_value_ret, const char *digest_path)
{
	char *cmd = NULL;
	char err_code[ERR_MSG_LENGTH + 1];

	cmd = (char *)malloc(sizeof(char)*(length + strlen(digest_path) + 21));
	if(!cmd)
	{
		int_error("Allocating memory for \"cmd\" failed");
	}

	sprintf(cmd, "echo \"%s\" | sha1sum > %s", string, digest_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));

	if(strcmp(err_code, "") != 0)
		int_error("Hashing string failed");

	// Read the digest value from file
	if(!read_bin_file(digest_path, hash_value_ret, SHA1_DIGEST_LENGTH, NULL))
		int_error("Reading SHA1 checksum failed");

	hash_value_ret[SHA1_DIGEST_LENGTH] = 0;
	unlink(digest_path);

	free(cmd);
	cmd = NULL;
}

boolean verify_file_integrity(const char *file_path, char *cmp_hash_value, const char *digest_path)
{
	char hash_value[SHA1_DIGEST_LENGTH + 1];

	sum_sha1_from_file(file_path, hash_value, digest_path);
	if(strncmp(hash_value, cmp_hash_value, SHA1_DIGEST_LENGTH) == 0)
		return true;
	else
		return false;
}

// Get current date/time in format "YYYY-MM-DD HH:mm:ss"
void get_current_date_time(char *current_date_time_ret) 
{
	time_t    current_time;
	struct tm tm_current_time;

	current_time    = time(NULL);
	tm_current_time = *localtime(&current_time);
	strftime(current_date_time_ret, strlen("YYYY-MM-DD HH:mm:ss") + 1, "%Y-%m-%d %X", &tm_current_time);
}

boolean file_exists(const char *file_path)
{
	struct stat st;
	if((stat(file_path, &st) == 0) && (((st.st_mode) & S_IFMT) == S_IFREG))
		return true;
	else
		return false;
}

boolean directory_exists(const char *dir_path)
{
	struct stat st;
	if((stat(dir_path, &st) == 0) && (((st.st_mode) & S_IFMT) == S_IFDIR))
		return true;
	else
		return false;
}

// "octet_mode" specifies, for example, 777
boolean make_directory(const char *dir_path, mode_t octet_mode)
{
	if(mkdir(dir_path, 0777) == 0 && change_directory_permission(dir_path, octet_mode))
		return true;
	else
		return false;
}

boolean determine_file_permission(const char *file_path, char *octet_mode_ret)
{
	if(!file_exists(file_path))
		return false;

	char cmd[BUFFER_LENGTH + 1];
	sprintf(cmd, "stat -c \"%%a %%n\" \"%s\"", file_path);
	exec_cmd(cmd, strlen(cmd), octet_mode_ret, OCTET_PERMISSION_MODE_LENGTH + 1);
	return true;
}

boolean determine_directory_permission(const char *dir_path, char *octet_mode_ret)
{
	if(!directory_exists(dir_path))
		return false;

	char cmd[BUFFER_LENGTH + 1];
	sprintf(cmd, "stat -c \"%%a %%n\" \"%s\"", dir_path);
	exec_cmd(cmd, strlen(cmd), octet_mode_ret, OCTET_PERMISSION_MODE_LENGTH + 1);
	return true;
}

boolean change_file_permission(const char *file_path, mode_t octet_mode)
{
	if(!file_exists(file_path))
		return false;

	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	sprintf(cmd, "chmod %d \"%s\"", (int)octet_mode, file_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));

	if(strcmp(err_code, "") == 0)
		return true;
	else
		return false;
}

boolean change_directory_permission(const char *dir_path, mode_t octet_mode)
{
	if(!directory_exists(dir_path))
		return false;

	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	sprintf(cmd, "chmod %d \"%s\"", (int)octet_mode, dir_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));

	if(strcmp(err_code, "") == 0)
		return true;
	else
		return false;
}

boolean rename_file(const char *src_path, const char *dest_path)
{
	if(!file_exists(src_path))
		return false;

	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	sprintf(cmd, "mv \"%s\" \"%s\"", src_path, dest_path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));

	if(strcmp(err_code, "") == 0)
		return true;
	else
		return false;
}

boolean recursive_remove(const char *path)
{
	char cmd[BUFFER_LENGTH + 1];
	char err_code[ERR_MSG_LENGTH + 1];

	sprintf(cmd, "rm -R \"%s\"", path);
	exec_cmd(cmd, strlen(cmd), err_code, sizeof(err_code));

	if(strcmp(err_code, "") == 0)
		return true;
	else
		return false;
}

void allocate_2d_string_array(char ***array, int n, int m)
{
	int i;

	*array = (char**)malloc(n * sizeof(char *));
	if(!(*array))
	{
		int_error("Allocating memory for \"2d_string_array\" failed");
	}

	for(i=0; i < n; i++)
	{
		(*array)[i] = (char*)malloc(m * sizeof(char));
		if(!((*array)[i]))
		{
			int_error("Allocating memory for \"2d_string_array\" failed");
		}
	}
} 

void deallocate_2d_string_array(char ***array, int n)
{
	int i;

	if(*array)
	{
		return;
	}

	for(i = 0; i < n; i++)
	{
		if((*array)[i])
		{
			free((*array)[i]);
		}
	}

	free(*array); 
}



