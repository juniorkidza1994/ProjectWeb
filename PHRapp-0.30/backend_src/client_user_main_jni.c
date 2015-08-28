// For the Java Native Interface calls
#include <jni.h>

#include "common.h"
#include "client_common.h"

// JNI Variables
static JNIEnv    *Java_env;
static jobject   Java_object;

static jmethodID Java_backend_alert_msg_callback_handler_id;
static jmethodID Java_backend_fatal_alert_msg_callback_handler_id;
static jmethodID Java_clear_authority_list_callback_handler_id;
static jmethodID Java_add_authority_to_list_callback_handler_id;
static jmethodID Java_add_numerical_user_attribute_to_table_callback_handler_id;
static jmethodID Java_add_non_numerical_user_attribute_to_table_callback_handler_id;
static jmethodID Java_clear_access_permission_table_callback_handler_id;
static jmethodID Java_add_access_permission_to_table_callback_handler_id;
static jmethodID Java_clear_attribute_table_callback_handler_id;
static jmethodID Java_add_attribute_to_table_callback_handler_id;
static jmethodID Java_update_phr_sent_progression_callback_handler_id;
static jmethodID Java_update_remote_site_phr_id_callback_handler_id;
static jmethodID Java_add_downloading_authorized_phr_list_to_table_callback_handler_id;
static jmethodID Java_add_deletion_authorized_phr_list_to_table_callback_handler_id;
static jmethodID Java_update_phr_received_progression_callback_handler_id;
static jmethodID Java_add_transaction_login_log_to_table_callback_handler_id;
static jmethodID Java_add_transaction_event_log_to_table_callback_handler_id;
static jmethodID Java_clear_emergency_trusted_user_table_callback_handler_id;
static jmethodID Java_add_emergency_trusted_user_to_table_callback_handler_id;
static jmethodID Java_clear_emergency_phr_owner_table_callback_handler_id;
static jmethodID Java_add_emergency_phr_owner_to_table_callback_handler_id;
static jmethodID Java_clear_restricted_phr_access_request_table_callback_handler_id;
static jmethodID Java_add_restricted_phr_access_request_to_table_callback_handler_id;

// Local Variables
static boolean   phr_encrypting_working_flag;
static boolean   phr_uploading_working_flag;

static boolean   phr_downloading_working_flag;
static boolean   phr_decrypting_working_flag;

// Local Function Prototypes
static void backend_alert_msg_callback_handler(char *alert_msg);
static void backend_fatal_alert_msg_callback_handler(char *alert_msg);
static void clear_authority_list_callback_handler();
static void add_authority_to_list_callback_handler(char *authority_name);
static void add_numerical_user_attribute_to_table_callback_handler(char *attribute_name, char *authority_name, unsigned int attribute_value);
static void add_non_numerical_user_attribute_to_table_callback_handler(char *attribute_name, char *authority_name);
static void clear_access_permission_table_callback_handler();
static void add_access_permission_to_table_callback_handler(char *assigned_username, char *assigned_user_authority_name, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag);

static void clear_attribute_table_callback_handler();
static void add_attribute_to_table_callback_handler(char *attribute_name, boolean is_numerical_attribute_flag);
static void update_phr_sent_progression_callback_handler(unsigned int percent);
static void update_remote_site_phr_id_callback_handler(unsigned int remote_site_phr_id);
static void add_downloading_authorized_phr_list_to_table_callback_handler(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id);
static void add_deletion_authorized_phr_list_to_table_callback_handler(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id);
static void update_phr_received_progression_callback_handler(unsigned int percent);
static void add_transaction_login_log_to_table_callback_handler(char *date_time, char *ip_address, boolean is_logout_flag);
static void add_transaction_event_log_to_table_callback_handler(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address);

static void clear_emergency_trusted_user_table_callback_handler();
static void add_emergency_trusted_user_to_table_callback_handler(char *trusted_username, char *trusted_user_authority_name);
static void clear_emergency_phr_owner_table_callback_handler();
static void add_emergency_phr_owner_to_table_callback_handler(char *phr_owner_name, char *phr_owner_authority_name);
static void clear_restricted_phr_access_request_table_callback_handler();
static void add_restricted_phr_access_request_to_table_callback_handler(char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id);

static void assert_cache_directory_existence();
static void set_phr_encrypting_working_flag(boolean flag);
static boolean get_phr_encrypting_working_flag();
static void set_phr_uploading_working_flag(boolean flag);
static boolean get_phr_uploading_working_flag();
static void set_phr_downloading_working_flag(boolean flag);
static boolean get_phr_downloading_working_flag();
static void set_phr_decrypting_working_flag(boolean flag);
static boolean get_phr_decrypting_working_flag();

// Implementation
static void backend_alert_msg_callback_handler(char *alert_msg)
{
	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_backend_alert_msg_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, alert_msg));
}

static void backend_fatal_alert_msg_callback_handler(char *alert_msg)
{
	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_backend_fatal_alert_msg_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, alert_msg));
}

static void clear_authority_list_callback_handler()
{
	if(Java_clear_authority_list_callback_handler_id == 0)
		int_error("Could not find method \"clear_authority_list_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_authority_list_callback_handler_id);
}

static void add_authority_to_list_callback_handler(char *authority_name)
{
	if(Java_add_authority_to_list_callback_handler_id == 0)
		int_error("Could not find method \"add_authority_to_list_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_authority_to_list_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, authority_name));
}

static void add_numerical_user_attribute_to_table_callback_handler(char *attribute_name, char *authority_name, unsigned int attribute_value)
{
	if(Java_add_numerical_user_attribute_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_numerical_user_attribute_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_numerical_user_attribute_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, attribute_name), (jstring)(*Java_env)->NewStringUTF(Java_env, authority_name), (jint)attribute_value);
}

static void add_non_numerical_user_attribute_to_table_callback_handler(char *attribute_name, char *authority_name)
{
	if(Java_add_non_numerical_user_attribute_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_non_numerical_user_attribute_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_non_numerical_user_attribute_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, attribute_name), (jstring)(*Java_env)->NewStringUTF(Java_env, authority_name));
}

static void clear_access_permission_table_callback_handler()
{
	if(Java_clear_access_permission_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_access_permission_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_access_permission_table_callback_handler_id);
}

static void add_access_permission_to_table_callback_handler(char *assigned_username, char *assigned_user_authority_name, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag)
{
	if(Java_add_access_permission_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_access_permission_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_access_permission_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, 
		assigned_username), (jstring)(*Java_env)->NewStringUTF(Java_env, assigned_user_authority_name), (jboolean)upload_permission_flag, (jboolean)
		download_permission_flag, (jboolean)delete_permission_flag);
}

static void clear_attribute_table_callback_handler()
{
	if(Java_clear_attribute_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_attribute_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_attribute_table_callback_handler_id);
}

static void add_attribute_to_table_callback_handler(char *attribute_name, boolean is_numerical_attribute_flag)
{
	if(Java_add_attribute_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_attribute_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_attribute_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, attribute_name), (jboolean)(is_numerical_attribute_flag));
}

static void update_phr_sent_progression_callback_handler(unsigned int percent)
{
	if(Java_update_phr_sent_progression_callback_handler_id == 0)
		int_error("Could not find method \"update_phr_sent_progression_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_update_phr_sent_progression_callback_handler_id, (jint)(percent));
}

static void update_remote_site_phr_id_callback_handler(unsigned int remote_site_phr_id)
{
	if(Java_update_remote_site_phr_id_callback_handler_id == 0)
		int_error("Could not find method \"update_remote_site_phr_id_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_update_remote_site_phr_id_callback_handler_id, (jint)(remote_site_phr_id));
}

static void add_downloading_authorized_phr_list_to_table_callback_handler(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id)
{
	if(Java_add_downloading_authorized_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_downloading_authorized_phr_list_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_downloading_authorized_phr_list_to_table_callback_handler_id, 
		(jstring)(*Java_env)->NewStringUTF(Java_env, data_description), (jstring)(*Java_env)->NewStringUTF(Java_env, file_size), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, phr_conf_level), (jint)phr_id);
}

static void add_deletion_authorized_phr_list_to_table_callback_handler(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id)
{
	if(Java_add_deletion_authorized_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_deletion_authorized_phr_list_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_deletion_authorized_phr_list_to_table_callback_handler_id, 
		(jstring)(*Java_env)->NewStringUTF(Java_env, data_description), (jstring)(*Java_env)->NewStringUTF(Java_env, file_size), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, phr_conf_level), (jint)phr_id);
}

static void update_phr_received_progression_callback_handler(unsigned int percent)
{
	if(Java_update_phr_received_progression_callback_handler_id == 0)
		int_error("Could not find method \"update_phr_received_progression_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_update_phr_received_progression_callback_handler_id, (jint)(percent));
}

static void add_transaction_login_log_to_table_callback_handler(char *date_time, char *ip_address, boolean is_logout_flag)
{
	if(Java_add_transaction_login_log_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_transaction_login_log_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_transaction_login_log_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, date_time), (jstring)(*Java_env)->NewStringUTF(Java_env, ip_address), (jboolean)(is_logout_flag));
}

static void add_transaction_event_log_to_table_callback_handler(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address)
{
	if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_transaction_event_log_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, date_time), (jstring)(*Java_env)->NewStringUTF(Java_env, actor_name), (jstring)(*Java_env)->NewStringUTF(Java_env, 
		actor_authority_name), (jboolean)(is_actor_admin_flag), (jstring)(*Java_env)->NewStringUTF(Java_env, object_description), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, event_description), (jstring)(*Java_env)->NewStringUTF(Java_env, object_owner_name), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, object_owner_authority_name), (jboolean)(is_object_owner_admin_flag), (jstring)(*Java_env)->NewStringUTF(
		Java_env, actor_ip_address));
}

static void clear_emergency_trusted_user_table_callback_handler()
{
	if(Java_clear_emergency_trusted_user_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_emergency_trusted_user_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_emergency_trusted_user_table_callback_handler_id);
}

static void add_emergency_trusted_user_to_table_callback_handler(char *trusted_username, char *trusted_user_authority_name)
{
	if(Java_add_emergency_trusted_user_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_emergency_trusted_user_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_emergency_trusted_user_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, trusted_username), (jstring)(*Java_env)->NewStringUTF(Java_env, trusted_user_authority_name));
}

static void clear_emergency_phr_owner_table_callback_handler()
{
	if(Java_clear_emergency_phr_owner_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_emergency_phr_owner_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_emergency_phr_owner_table_callback_handler_id);
}

static void add_emergency_phr_owner_to_table_callback_handler(char *phr_owner_name, char *phr_owner_authority_name)
{
	if(Java_add_emergency_phr_owner_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_emergency_phr_owner_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_emergency_phr_owner_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, phr_owner_name), (jstring)(*Java_env)->NewStringUTF(Java_env, phr_owner_authority_name));
}

static void clear_restricted_phr_access_request_table_callback_handler()
{
	if(Java_clear_restricted_phr_access_request_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_restricted_phr_access_request_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_restricted_phr_access_request_table_callback_handler_id);
}

static void add_restricted_phr_access_request_to_table_callback_handler(char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id)
{
	if(Java_add_restricted_phr_access_request_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_restricted_phr_access_request_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_restricted_phr_access_request_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, full_requestor_name), (jstring)(*Java_env)->NewStringUTF(Java_env, full_phr_ownername), (jstring)(*Java_env)->NewStringUTF(Java_env, 
		data_description), (jint)approvals, (jint)threshold_value, (jstring)(*Java_env)->NewStringUTF(Java_env, request_status), (jint)phr_id);
}

static void assert_cache_directory_existence()
{
	// We do not consider the cache directory's mode yet. Must be considerd regarding it later.
	if(!directory_exists(CACHE_DIRECTORY_PATH))
	{
		if(!make_directory(CACHE_DIRECTORY_PATH, CACHE_DIRECTORY_PERMISSION_MODE))
			int_error("Creating a cache directory failed");
	}
}

/*
 * Class:     UserMain
 * Method:    init_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_init_1backend(JNIEnv *env, jobject obj)
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
	init_openssl();

	assert_cache_directory_existence();

	phr_encrypting_working_flag  = false;
	phr_uploading_working_flag   = false;
	phr_downloading_working_flag = false;
	phr_decrypting_working_flag  = false;
}

/*
 * Class:     UserMain
 * Method:    store_variables_to_backend
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;
	Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_UserMain_store_1variables_1to_1backend(JNIEnv *env, jobject obj, jstring j_ssl_cert_hash, jstring j_cpabe_priv_key_hash, 
	jstring j_username, jstring j_authority_name, jstring j_passwd, jstring j_user_auth_ip_addr, jstring j_audit_server_ip_addr, jstring j_phr_server_ip_addr, 
	jstring j_emergency_server_ip_addr)
{
	const char *ssl_cert_hash;
	const char *cpabe_priv_key_hash;
	const char *username;
	const char *authority_name;
	const char *passwd;
	const char *user_auth_ip_addr;
	const char *audit_server_ip_addr;
	const char *phr_server_ip_addr;
	const char *emergency_server_ip_addr;

	// Get variables from Java
	ssl_cert_hash            = (*env)->GetStringUTFChars(env, j_ssl_cert_hash, 0);
	cpabe_priv_key_hash      = (*env)->GetStringUTFChars(env, j_cpabe_priv_key_hash, 0);
	username                 = (*env)->GetStringUTFChars(env, j_username, 0);
	authority_name           = (*env)->GetStringUTFChars(env, j_authority_name, 0);
	passwd                   = (*env)->GetStringUTFChars(env, j_passwd, 0);
	user_auth_ip_addr        = (*env)->GetStringUTFChars(env, j_user_auth_ip_addr, 0);
	audit_server_ip_addr     = (*env)->GetStringUTFChars(env, j_audit_server_ip_addr, 0);
	phr_server_ip_addr       = (*env)->GetStringUTFChars(env, j_phr_server_ip_addr, 0);
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);

	strncpy(GLOBAL_ssl_cert_hash, ssl_cert_hash, SHA1_DIGEST_LENGTH);
	strncpy(GLOBAL_cpabe_priv_key_hash, cpabe_priv_key_hash, SHA1_DIGEST_LENGTH);
	strncpy(GLOBAL_username, username, USER_NAME_LENGTH);
	strncpy(GLOBAL_authority_name, authority_name, AUTHORITY_NAME_LENGTH);
	strncpy(GLOBAL_passwd, passwd, PASSWD_LENGTH);
	strncpy(GLOBAL_user_auth_ip_addr, user_auth_ip_addr, IP_ADDRESS_LENGTH);
	strncpy(GLOBAL_audit_server_ip_addr, audit_server_ip_addr, IP_ADDRESS_LENGTH);
	strncpy(GLOBAL_phr_server_ip_addr, phr_server_ip_addr, IP_ADDRESS_LENGTH);
	strncpy(GLOBAL_emergency_server_ip_addr, emergency_server_ip_addr, IP_ADDRESS_LENGTH);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_ssl_cert_hash, ssl_cert_hash);
	(*env)->ReleaseStringUTFChars(env, j_cpabe_priv_key_hash, cpabe_priv_key_hash);
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
	(*env)->ReleaseStringUTFChars(env, j_passwd, passwd);
	(*env)->ReleaseStringUTFChars(env, j_user_auth_ip_addr, user_auth_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_audit_server_ip_addr, audit_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_server_ip_addr, phr_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_emergency_server_ip_addr, emergency_server_ip_addr);
}

/*
 * Class:     UserMain
 * Method:    update_authority_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1authority_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_authority_list_callback_handler_id    = (*env)->GetMethodID(env, cls, "clear_authority_list_callback_handler", "()V");
	Java_add_authority_to_list_callback_handler_id   = (*env)->GetMethodID(env, cls, "add_authority_to_list_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_authority_list_callback_handler_id == 0)
		int_error("Could not find method \"clear_authority_list_callback_handler\"");

	if(Java_add_authority_to_list_callback_handler_id == 0)
		int_error("Could not find method \"add_authority_to_list_callback_handler\"");

	// Update authority list
	update_authority_list_for_user(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_authority_list_callback_handler, add_authority_to_list_callback_handler);
}

/*
 * Class:     UserMain
 * Method:    update_user_attribute_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1user_1attribute_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	Java_add_numerical_user_attribute_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_numerical_user_attribute_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;I)V");

	Java_add_non_numerical_user_attribute_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_non_numerical_user_attribute_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_add_numerical_user_attribute_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_numerical_user_attribute_to_table_callback_handler\"");

	if(Java_add_non_numerical_user_attribute_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_non_numerical_user_attribute_to_table_callback_handler\"");

	// Update user attribute list
	update_user_attribute_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		add_numerical_user_attribute_to_table_callback_handler, add_non_numerical_user_attribute_to_table_callback_handler);
}

/*
 * Class:     ShutdownHook
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_ShutdownHook_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     ShutdownHook
 * Method:    record_transaction_logout_log
 * Signature: (Ljava/lang/String;Z)V
 */
JNIEXPORT void JNICALL Java_ShutdownHook_record_1transaction_1logout_1log(JNIEnv *env, jobject obj, jstring j_username)
{
	const char *username;
	jclass     cls;

	// Get a variable from Java
	username    = (*env)->GetStringUTFChars(env, j_username, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a transcation logout log
	record_transaction_logout_log((char *)username, false, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
}

/*
 * Class:     AccessPermissionManagement
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AccessPermissionManagement_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     AccessPermissionManagement
 * Method:    assign_access_permission_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;ZZZ)Z
 */
JNIEXPORT jboolean JNICALL Java_AccessPermissionManagement_assign_1access_1permission_1main(JNIEnv *env, jobject obj, jstring j_desired_user_authority_name, 
	jstring j_desired_username, jboolean j_upload_permission_flag, jboolean j_download_permission_flag, jboolean j_delete_permission_flag)
{
	const char *desired_user_authority_name;
	const char *desired_username;
	boolean    upload_permission_flag;
	boolean    download_permission_flag;
	boolean    delete_permission_flag;

	jclass     cls;
	boolean    assignment_flag;

	// Get variables from Java
	desired_user_authority_name = (*env)->GetStringUTFChars(env, j_desired_user_authority_name, 0);
	desired_username            = (*env)->GetStringUTFChars(env, j_desired_username, 0);
	upload_permission_flag      = (boolean)j_upload_permission_flag;
	download_permission_flag    = (boolean)j_download_permission_flag;
	delete_permission_flag      = (boolean)j_delete_permission_flag;

	Java_env     = env;
  	Java_object  = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Assign access permissions
	assignment_flag = assign_access_permission((char *)desired_user_authority_name, (char *)desired_username, upload_permission_flag, download_permission_flag, 
		delete_permission_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_desired_user_authority_name, desired_user_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_desired_username, desired_username);

	return (jboolean)assignment_flag;
}

/*
 * Class:     UserMain
 * Method:    update_assigned_access_permission_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1assigned_1access_1permission_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id              = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id        = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_access_permission_table_callback_handler_id  = (*env)->GetMethodID(env, cls, "clear_access_permission_table_callback_handler", "()V");
	Java_add_access_permission_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_access_permission_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;ZZZ)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_access_permission_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_access_permission_table_callback_handler\"");

	if(Java_add_access_permission_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_access_permission_to_table_callback_handler\"");

	// Update an assigned access permission list
	update_assigned_access_permission_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_access_permission_table_callback_handler, add_access_permission_to_table_callback_handler);
}

/*
 * Class:     UserMain
 * Method:    update_attribute_list_main
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1attribute_1list_1main(JNIEnv *env, jobject obj, jstring j_authority_name)
{
	const char *authority_name;
	jclass     cls;

	// Get variable from Java
	authority_name = (*env)->GetStringUTFChars(env, j_authority_name, 0);

	Java_env       = env;
  	Java_object    = obj;

	// Get the method ids for returning output to Java
	cls            = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_attribute_table_callback_handler_id   = (*env)->GetMethodID(env, cls, "clear_attribute_table_callback_handler", "()V");
	Java_add_attribute_to_table_callback_handler_id  = (*env)->GetMethodID(env, cls, "add_attribute_to_table_callback_handler", "(Ljava/lang/String;Z)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_attribute_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_attribute_table_callback_handler\"");

	if(Java_add_attribute_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_attribute_to_table_callback_handler\"");

	// Update attribute list
	update_attribute_list_for_user((char *)authority_name, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_attribute_table_callback_handler, add_attribute_to_table_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
}

/*
 * Class:     UserMain
 * Method:    check_user_existence_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_check_1user_1existence_1main(JNIEnv *env, jobject obj, jstring j_authority_name, jstring j_username)
{
	const char *authority_name;
	const char *username;

	jclass     cls;
	boolean    checking_flag;

	// Get variables from Java
	authority_name = (*env)->GetStringUTFChars(env, j_authority_name, 0);
	username       = (*env)->GetStringUTFChars(env, j_username, 0);

	Java_env       = env;
  	Java_object    = obj;

	// Get the method ids for returning output to Java
	cls            = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Check for the existence of a user
	checking_flag = check_user_existence((char *)authority_name, (char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)checking_flag;
}

/*
 * Class:     UserMain
 * Method:    verify_upload_permission_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_verify_1upload_1permission_1main(JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;

	jclass     cls;
	boolean    upload_permission_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Verify upload permission
	upload_permission_flag = verify_upload_permission((char *)phr_owner_name, (char *)phr_owner_authority_name, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return upload_permission_flag;
}

/*
 * Class:     UserMain
 * Method:    verify_download_permission_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_verify_1download_1permission_1main(JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;

	jclass     cls;
	boolean    download_permission_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Verify download permission
	download_permission_flag = verify_download_permission((char *)phr_owner_name, (char *)phr_owner_authority_name, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return download_permission_flag;
}

/*
 * Class:     UserMain
 * Method:    verify_delete_permission_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_verify_1delete_1permission_1main(JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;

	jclass     cls;
	boolean    delete_permission_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Verify delete permission
	delete_permission_flag = verify_delete_permission((char *)phr_owner_name, (char *)phr_owner_authority_name, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return delete_permission_flag;
}

/*
 * Class:     UserMain
 * Method:    generate_unique_emergency_key_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_generate_1unique_1emergency_1key_1main(JNIEnv *env, 
	jobject obj, jstring j_unique_emergency_key_attribute, jstring j_unique_emergency_key_passwd)
{
	const char *unique_emergency_key_attribute;
	const char *unique_emergency_key_passwd;

	jclass     cls;
	boolean    generating_flag;

	// Get variables from Java
	unique_emergency_key_attribute = (*env)->GetStringUTFChars(env, j_unique_emergency_key_attribute, 0);
	unique_emergency_key_passwd    = (*env)->GetStringUTFChars(env, j_unique_emergency_key_passwd, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Generate the unique emergency key
	generating_flag = generate_unique_emergency_key((char *)unique_emergency_key_attribute, (char *)unique_emergency_key_passwd, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_unique_emergency_key_attribute, unique_emergency_key_attribute);
	(*env)->ReleaseStringUTFChars(env, j_unique_emergency_key_passwd, unique_emergency_key_passwd);

	return generating_flag;
}

/*
 * Class:     UserMain
 * Method:    encrypt_threshold_secret_keys_main
 * Signature: ([Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_encrypt_1threshold_1secret_1keys_1main(JNIEnv *env, jobject obj, jarray j_ea_trusted_user_list)
{
	char         **ea_trusted_user_list;
	unsigned int i, no_trusted_users;

	jstring      j_ea_trusted_username;
	const char   *ea_trusted_username;

	jclass       cls;
	boolean      encrypting_flag;

	no_trusted_users = (*env)->GetArrayLength(env, j_ea_trusted_user_list);

	// Allocate memory
	allocate_2d_string_array(&ea_trusted_user_list, no_trusted_users, USER_NAME_LENGTH + AUTHORITY_NAME_LENGTH + 2);

	// Get variables from Java
	for(i=0; i < no_trusted_users; i++)
	{
		j_ea_trusted_username = (jstring)(*env)->GetObjectArrayElement(env, j_ea_trusted_user_list, i);
		ea_trusted_username  = (*env)->GetStringUTFChars(env, j_ea_trusted_username, 0);
		strcpy(ea_trusted_user_list[i], ea_trusted_username);

		// Free up the Java string argument
		(*env)->ReleaseStringUTFChars(env, j_ea_trusted_username, ea_trusted_username);
	}

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Encrypt the threshold secret keys
	encrypting_flag = encrypt_threshold_secret_keys(no_trusted_users, ea_trusted_user_list, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the heap memory
	deallocate_2d_string_array(&ea_trusted_user_list, no_trusted_users);

	return encrypting_flag;
}

/*
 * Class:     UserMain
 * Method:    upload_unique_emergency_key_params_main
 * Signature: (II[Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_upload_1unique_1emergency_1key_1params_1main(JNIEnv *env, 
	jobject obj, jint j_remote_site_phr_id, jint j_threshold_value, jarray j_ea_trusted_user_list)
{
	char         **ea_trusted_user_list;
	unsigned int i, no_trusted_users;

	unsigned int remote_site_phr_id;
	unsigned int threshold_value;

	jstring      j_ea_trusted_username;
	const char   *ea_trusted_username;

	jclass       cls;
	boolean      uploading_flag;

	remote_site_phr_id = (unsigned int)j_remote_site_phr_id;
	threshold_value    = (unsigned int)j_threshold_value;
	no_trusted_users   = (*env)->GetArrayLength(env, j_ea_trusted_user_list);

	// Allocate memory
	allocate_2d_string_array(&ea_trusted_user_list, no_trusted_users, USER_NAME_LENGTH + AUTHORITY_NAME_LENGTH + 2);

	// Get variables from Java
	for(i=0; i < no_trusted_users; i++)
	{
		j_ea_trusted_username = (jstring)(*env)->GetObjectArrayElement(env, j_ea_trusted_user_list, i);
		ea_trusted_username  = (*env)->GetStringUTFChars(env, j_ea_trusted_username, 0);
		strcpy(ea_trusted_user_list[i], ea_trusted_username);

		// Free up the Java string argument
		(*env)->ReleaseStringUTFChars(env, j_ea_trusted_username, ea_trusted_username);
	}

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Upload the unique emergency key parameters to the Emergency Server
	uploading_flag = upload_unique_emergency_key_params(remote_site_phr_id, threshold_value, no_trusted_users, ea_trusted_user_list, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the heap memory
	deallocate_2d_string_array(&ea_trusted_user_list, no_trusted_users);

	return uploading_flag;
}

/*
 * Class:     UserMain
 * Method:    change_restricted_level_phr_to_excusive_level_phr_main
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_change_1restricted_1level_1phr_1to_1excusive_1level_1phr_1main(JNIEnv *env, jobject obj, jint j_remote_site_phr_id)
{
	unsigned int remote_site_phr_id;

	jclass       cls;
	boolean      changing_flag;

	remote_site_phr_id = (unsigned int)j_remote_site_phr_id;

	Java_env           = env;
  	Java_object        = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Change the confideentiality level of the PHR from the restricted level to the exclusive level
	changing_flag = change_restricted_level_phr_to_excusive_level_phr(remote_site_phr_id, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	return changing_flag;
}

static void set_phr_encrypting_working_flag(boolean flag)
{
	phr_encrypting_working_flag = flag;
}

static boolean get_phr_encrypting_working_flag()
{
	return phr_encrypting_working_flag;
}

/*
 * Class:     UserMain
 * Method:    encrypt_phr_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_encrypt_1phr_1main(JNIEnv *env, jobject obj, jstring j_phr_upload_from_path, jstring j_access_policy)
{
	const char *phr_upload_from_path;
	const char *access_policy;

	jclass     cls;
	boolean    encrypting_flag;

	// Get variables from Java
	phr_upload_from_path = (*env)->GetStringUTFChars(env, j_phr_upload_from_path, 0);
	access_policy        = (*env)->GetStringUTFChars(env, j_access_policy, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Encrypt the PHR
	set_phr_encrypting_working_flag(true);
	encrypting_flag = encrypt_phr((char *)phr_upload_from_path, (char *)access_policy, backend_alert_msg_callback_handler);
	set_phr_encrypting_working_flag(false);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_upload_from_path, phr_upload_from_path);
	(*env)->ReleaseStringUTFChars(env, j_access_policy, access_policy);

	return encrypting_flag;
}

/*
 * Class:     UserMain
 * Method:    cancel_phr_encrypting_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_cancel_1phr_1encrypting_1main(JNIEnv *env, jobject obj)
{
	if(!get_phr_encrypting_working_flag())
		return;

	cancel_phr_encrypting();
}

static void set_phr_uploading_working_flag(boolean flag)
{
	phr_uploading_working_flag = flag;
}

static boolean get_phr_uploading_working_flag()
{
	return phr_uploading_working_flag;
}

/*
 * Class:     UserMain
 * Method:    upload_phr_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_upload_1phr_1main(JNIEnv *env, jobject obj, jstring j_phr_owner_name, 
	jstring j_phr_owner_authority_name, jstring j_data_description, jstring j_confidentiality_level_flag)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *data_description;
	const char *confidentiality_level_flag;

	jclass     cls;
	boolean    uploading_flag;

	// Get variables from Java
	phr_owner_name             = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name   = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	data_description           = (*env)->GetStringUTFChars(env, j_data_description, 0);
	confidentiality_level_flag = (*env)->GetStringUTFChars(env, j_confidentiality_level_flag, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id           = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id     = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_update_phr_sent_progression_callback_handler_id = (*env)->GetMethodID(env, cls, "update_phr_sent_progression_callback_handler", "(I)V");
	Java_update_remote_site_phr_id_callback_handler_id   = (*env)->GetMethodID(env, cls, "update_remote_site_phr_id_callback_handler", "(I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_update_phr_sent_progression_callback_handler_id == 0)
		int_error("Could not find method \"update_phr_sent_progression_callback_handler\"");

	if(Java_update_remote_site_phr_id_callback_handler_id == 0)
		int_error("Could not find method \"update_remote_site_phr_id_callback_handler\"");

	// Upload the PHR
	set_phr_uploading_working_flag(true);

	uploading_flag = upload_phr((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)data_description, (char *)confidentiality_level_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, update_phr_sent_progression_callback_handler, 
		update_remote_site_phr_id_callback_handler);

	set_phr_uploading_working_flag(false);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_data_description, data_description);
	(*env)->ReleaseStringUTFChars(env, j_confidentiality_level_flag, confidentiality_level_flag);

	return uploading_flag;
}

/*
 * Class:     UserMain
 * Method:    cancel_phr_uploading_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_cancel_1phr_1uploading_1main(JNIEnv *env, jobject obj)
{
	if(!get_phr_uploading_working_flag())
		return;

	cancel_phr_uploading();
}

static void set_phr_downloading_working_flag(boolean flag)
{
	phr_downloading_working_flag = flag;
}

static boolean get_phr_downloading_working_flag()
{
	return phr_downloading_working_flag;
}

/*
 * Class:     UserMain
 * Method:    download_phr_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_download_1phr_1main(JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jint j_phr_id)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	int        phr_id;

	jclass     cls;
	boolean    downloading_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_id                   = (unsigned int)j_phr_id;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id               = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id         = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_update_phr_received_progression_callback_handler_id = (*env)->GetMethodID(env, cls, "update_phr_received_progression_callback_handler", "(I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_update_phr_received_progression_callback_handler_id == 0)
		int_error("Could not find method \"update_received_sent_progression_callback_handler\"");

	// Download the PHR
	set_phr_downloading_working_flag(true);

	downloading_flag = download_phr((char *)phr_owner_name, (char *)phr_owner_authority_name, phr_id, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, update_phr_received_progression_callback_handler);

	set_phr_downloading_working_flag(false);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return downloading_flag;
}

/*
 * Class:     UserMain
 * Method:    cancel_phr_downloading_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_cancel_1phr_1downloading_1main(JNIEnv *env, jobject obj)
{
	if(!get_phr_downloading_working_flag())
		return;

	cancel_phr_downloading();
}

static void set_phr_decrypting_working_flag(boolean flag)
{
	phr_decrypting_working_flag = flag;
}

static boolean get_phr_decrypting_working_flag()
{
	return phr_decrypting_working_flag;
}

/*
 * Class:     UserMain
 * Method:    decrypt_phr_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_decrypt_1phr_1main(JNIEnv *env, jobject obj, jstring j_phr_download_to_path)
{
	const char *phr_download_to_path;

	jclass     cls;
	boolean    decrypting_flag;

	// Get variable from Java
	phr_download_to_path = (*env)->GetStringUTFChars(env, j_phr_download_to_path, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Decrypt the PHR
	set_phr_decrypting_working_flag(true);
	decrypting_flag = decrypt_phr((char *)phr_download_to_path, backend_alert_msg_callback_handler);
	set_phr_decrypting_working_flag(false);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_download_to_path, phr_download_to_path);

	return decrypting_flag;
}

/*
 * Class:     UserMain
 * Method:    cancel_phr_decrypting_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_cancel_1phr_1decrypting_1main(JNIEnv *env, jobject obj)
{
	if(!get_phr_decrypting_working_flag())
		return;

	cancel_phr_decrypting();
}

/*
 * Class:     UserMain
 * Method:    delete_phr_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_delete_1phr_1main(JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jint j_phr_id)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	int        phr_id;

	jclass     cls;
	boolean    deletion_flag;

	// Get variables from Java
	phr_owner_name               = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name     = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_id                       = (unsigned int)j_phr_id;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Delete the PHR
	deletion_flag = delete_phr((char *)phr_owner_name, (char *)phr_owner_authority_name, phr_id, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return deletion_flag;
}

/*
 * Class:     UserMain
 * Method:    remove_restricted_level_phr_key_params_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_remove_1restricted_1level_1phr_1key_1params_1main(
	JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jint j_remote_site_phr_id)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	int        remote_site_phr_id;

	jclass     cls;
	boolean    removal_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	remote_site_phr_id       = (unsigned int)j_remote_site_phr_id;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Remove all restricted-level PHR key parameters that linked to the remote_site_phr_id
	removal_flag = remove_restricted_level_phr_key_params((char *)phr_owner_name, (char *)phr_owner_authority_name, 
		remote_site_phr_id, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return removal_flag;
}

/*
 * Class:     UserMain
 * Method:    remove_all_threshold_parameters_in_cache_main
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_UserMain_remove_1all_1threshold_1parameters_1in_1cache_1main(JNIEnv *env, jobject obj, jint j_no_trusted_users)
{
	int no_trusted_users;

	// Get a variable from Java
	no_trusted_users = (unsigned int)j_no_trusted_users;

	// Remove all threshold paramaters
	remove_all_threshold_parameters_in_cache(no_trusted_users);
}

/*
 * Class:     UserMain
 * Method:    load_downloading_authorized_phr_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_load_1downloading_1authorized_1phr_1list_1main(
	JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;

	jclass     cls;
	boolean    loading_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_add_downloading_authorized_phr_list_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_downloading_authorized_phr_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_add_downloading_authorized_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_downloading_authorized_phr_list_to_table_callback_handler\"");

	// Load a downloading authorized PHR list
	loading_flag = load_downloading_authorized_phr_list((char *)phr_owner_name, (char *)phr_owner_authority_name, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, add_downloading_authorized_phr_list_to_table_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return loading_flag;
}

/*
 * Class:     UserMain
 * Method:    load_deletion_authorized_phr_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_load_1deletion_1authorized_1phr_1list_1main(
	JNIEnv *env, jobject obj, jstring j_phr_owner_name, jstring j_phr_owner_authority_name)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;

	jclass     cls;
	boolean    loading_flag;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_add_deletion_authorized_phr_list_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_deletion_authorized_phr_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_add_deletion_authorized_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_deletion_authorized_phr_list_to_table_callback_handler\"");

	// Load a deletion authorized PHR list
	loading_flag = load_deletion_authorized_phr_list((char *)phr_owner_name, (char *)phr_owner_authority_name, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, add_deletion_authorized_phr_list_to_table_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);

	return loading_flag;
}

/*
 * Class:     UserMain
 * Method:    record_phr_encrypting_transaction_log_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
 */
JNIEXPORT void JNICALL Java_UserMain_record_1phr_1encrypting_1transaction_1log_1main(JNIEnv *env, jobject obj, 
	jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jstring j_phr_description, jboolean j_success_flag)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *phr_description;
	boolean    success_flag;

	jclass     cls;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	success_flag             = (boolean)j_success_flag;

	Java_env      = env;
  	Java_object   = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a PHR encrypting transaction log
	record_phr_encrypting_transaction_log((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)phr_description, success_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
}

/*
 * Class:     UserMain
 * Method:    record_phr_uploading_transaction_log_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
 */
JNIEXPORT void JNICALL Java_UserMain_record_1phr_1uploading_1transaction_1log_1main(JNIEnv *env, jobject obj, 
	jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jstring j_phr_description, jboolean j_success_flag)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *phr_description;
	boolean    success_flag;

	jclass     cls;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	success_flag             = (boolean)j_success_flag;

	Java_env      = env;
  	Java_object   = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a PHR uploading transaction log
	record_phr_uploading_transaction_log((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)phr_description, success_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
}

/*
 * Class:     UserMain
 * Method:    record_phr_downloading_transaction_log_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
 */
JNIEXPORT void JNICALL Java_UserMain_record_1phr_1downloading_1transaction_1log_1main(JNIEnv *env, jobject obj, 
	jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jstring j_phr_description, jboolean j_success_flag)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *phr_description;
	boolean    success_flag;

	jclass     cls;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	success_flag             = (boolean)j_success_flag;

	Java_env      = env;
  	Java_object   = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a PHR downloading transaction log
	record_phr_downloading_transaction_log((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)phr_description, success_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
}

/*
 * Class:     UserMain
 * Method:    record_phr_decrypting_transaction_log_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
 */
JNIEXPORT void JNICALL Java_UserMain_record_1phr_1decrypting_1transaction_1log_1main(JNIEnv *env, jobject obj, 
	jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jstring j_phr_description, jboolean j_success_flag)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *phr_description;
	boolean    success_flag;

	jclass     cls;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	success_flag             = (boolean)j_success_flag;

	Java_env      = env;
  	Java_object   = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a PHR decrypting transaction log
	record_phr_decrypting_transaction_log((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)phr_description, success_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
}

/*
 * Class:     UserMain
 * Method:    record_phr_deletion_transaction_log_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
 */
JNIEXPORT void JNICALL Java_UserMain_record_1phr_1deletion_1transaction_1log_1main(JNIEnv *env, jobject obj, 
	jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jstring j_phr_description, jboolean j_success_flag)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *phr_description;
	boolean    success_flag;

	jclass     cls;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	success_flag             = (boolean)j_success_flag;

	Java_env      = env;
  	Java_object   = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a PHR deletion transaction log
	record_phr_deletion_transaction_log((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)phr_description, success_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
}

/*
 * Class:     UserMain
 * Method:    record_failed_uploading_emergency_key_params_transaction_log_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_UserMain_record_1failed_1uploading_1emergency_1key_1params_1transaction_1log_1main(JNIEnv *env, jobject obj, 
	jstring j_phr_owner_name, jstring j_phr_owner_authority_name, jstring j_phr_description)
{
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	const char *phr_description;

	jclass     cls;

	// Get variables from Java
	phr_owner_name           = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Record a failure uploading the emergency key parameters transaction log
	record_failed_uploading_emergency_key_params_transaction_log((char *)phr_owner_name, (char *)phr_owner_authority_name, (char *)phr_description, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
}

/*
 * Class:     UserTransactionAuditing
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserTransactionAuditing_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     UserTransactionAuditing
 * Method:    audit_all_transaction_logs_main
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_UserTransactionAuditing_audit_1all_1transaction_1logs_1main(JNIEnv *env, jobject obj, jboolean j_audit_login_log_flag)
{
	boolean audit_login_log_flag;
	jclass  cls;

	// Get a variable from Java
	audit_login_log_flag = (boolean)j_audit_login_log_flag;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(audit_login_log_flag)  // Login log
	{
		Java_add_transaction_login_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
			"add_transaction_login_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Z)V");

		if(Java_add_transaction_login_log_to_table_callback_handler_id == 0)
			int_error("Could not find method \"add_transaction_login_log_to_table_callback_handler\"");

		// Audit transaction user login log
		audit_all_transaction_user_login_log(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
			add_transaction_login_log_to_table_callback_handler);
	}
	else  // Event log
	{
		Java_add_transaction_event_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
			"add_transaction_event_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;"
			"Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V");

		if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
			int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");

		// Audit transaction user event log
		audit_all_transaction_user_event_log(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
			add_transaction_event_log_to_table_callback_handler);
	}
}

/*
 * Class:     UserTransactionAuditing
 * Method:    audit_some_period_time_transaction_logs_main
 * Signature: (ZLjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_UserTransactionAuditing_audit_1some_1period_1time_1transaction_1logs_1main(
	JNIEnv *env, jobject obj, jboolean j_audit_login_log_flag, jstring j_start_date_time, jstring j_end_date_time)
{
	boolean    audit_login_log_flag;
	const char *start_date_time;
	const char *end_date_time;

	jclass     cls;

	// Get variables from Java
	audit_login_log_flag = (boolean)j_audit_login_log_flag;
	start_date_time      = (*env)->GetStringUTFChars(env, j_start_date_time, 0);
	end_date_time        = (*env)->GetStringUTFChars(env, j_end_date_time, 0);

	Java_env             = env;
  	Java_object          = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(audit_login_log_flag)  // Login log
	{
		Java_add_transaction_login_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
			"add_transaction_login_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Z)V");

		if(Java_add_transaction_login_log_to_table_callback_handler_id == 0)
			int_error("Could not find method \"add_transaction_login_log_to_table_callback_handler\"");

		// Audit transaction user login log
		audit_some_period_time_transaction_user_login_log((char *)start_date_time, (char *)end_date_time, backend_alert_msg_callback_handler, 
			backend_fatal_alert_msg_callback_handler, add_transaction_login_log_to_table_callback_handler);
	}
	else  // Event log
	{
		Java_add_transaction_event_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
			"add_transaction_event_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;"
			"Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V");

		if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
			int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");

		// Audit transaction user event log
		audit_some_period_time_transaction_user_event_log((char *)start_date_time, (char *)end_date_time, backend_alert_msg_callback_handler, 
			backend_fatal_alert_msg_callback_handler, add_transaction_event_log_to_table_callback_handler);
	}

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_start_date_time, start_date_time);
	(*env)->ReleaseStringUTFChars(env, j_end_date_time, end_date_time);
}

/*
 * Class:     AccessPermissionManagement
 * Method:    edit_access_permission_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;ZZZ)Z
 */
JNIEXPORT jboolean JNICALL Java_AccessPermissionManagement_edit_1access_1permission_1main(JNIEnv *env, jobject obj, jstring j_desired_user_authority_name, 
	jstring j_desired_username, jboolean j_upload_permission_flag, jboolean j_download_permission_flag, jboolean j_delete_permission_flag)
{
	const char *desired_user_authority_name;
	const char *desired_username;
	boolean    upload_permission_flag;
	boolean    download_permission_flag;
	boolean    delete_permission_flag;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	desired_user_authority_name = (*env)->GetStringUTFChars(env, j_desired_user_authority_name, 0);
	desired_username            = (*env)->GetStringUTFChars(env, j_desired_username, 0);
	upload_permission_flag      = (boolean)j_upload_permission_flag;
	download_permission_flag    = (boolean)j_download_permission_flag;
	delete_permission_flag      = (boolean)j_delete_permission_flag;

	Java_env     = env;
  	Java_object  = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Edit access permissions
	editing_flag = edit_access_permission((char *)desired_user_authority_name, (char *)desired_username, upload_permission_flag, download_permission_flag, 
		delete_permission_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_desired_user_authority_name, desired_user_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_desired_username, desired_username);

	return (jboolean)editing_flag;
}

/*
 * Class:     UserMain
 * Method:    remove_access_permission_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_remove_1access_1permission_1main(JNIEnv *env, jobject obj, jstring j_desired_user_authority_name, jstring j_desired_username)
{
	const char *desired_user_authority_name;
	const char *desired_username;

	jclass     cls;
	boolean    removal_flag;

	// Get variables from Java
	desired_user_authority_name = (*env)->GetStringUTFChars(env, j_desired_user_authority_name, 0);
	desired_username            = (*env)->GetStringUTFChars(env, j_desired_username, 0);

	Java_env     = env;
  	Java_object  = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Remove access permissions
	removal_flag = remove_access_permission((char *)desired_user_authority_name, (char *)desired_username, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_desired_user_authority_name, desired_user_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_desired_username, desired_username);

	return (jboolean)removal_flag;
}

/*
 * Class:     NewPasswordChanging
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_NewPasswordChanging_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     NewPasswordChanging
 * Method:    change_user_passwd_main
 * Signature: (Ljava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_NewPasswordChanging_change_1user_1passwd_1main(JNIEnv *env, jobject obj, jstring j_new_passwd, jboolean j_send_new_passwd_flag)
{
	const char *new_passwd;
	boolean    send_new_passwd_flag;

	jclass     cls;
	boolean    changing_flag;

	// Get variables from Java
	new_passwd           = (*env)->GetStringUTFChars(env, j_new_passwd, 0);
	send_new_passwd_flag = (boolean)j_send_new_passwd_flag;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Change a user's password
	changing_flag = change_user_passwd((char *)new_passwd, send_new_passwd_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_new_passwd, new_passwd);

	return (jboolean)changing_flag;
}

/*
 * Class:     EmailAddressChanging
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmailAddressChanging_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     EmailAddressChanging
 * Method:    change_user_email_address_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmailAddressChanging_change_1user_1email_1address_1main(JNIEnv *env, jobject obj, jstring j_email_address)
{
	const char *email_address;
	jclass     cls;
	boolean    changing_flag;

	// Get a variable from Java
	email_address = (*env)->GetStringUTFChars(env, j_email_address, 0);

	Java_env      = env;
  	Java_object   = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Change a user's e-mail address
	changing_flag = change_user_email_address((char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)changing_flag;
}

/*
 * Class:     EmergencyTrustedUserAdding
 * Method:    add_emergency_trusted_user_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmergencyTrustedUserAdding_add_1emergency_1trusted_1user_1main(JNIEnv *env, jobject obj, 
	jstring j_desired_trusted_user_authority_name, jstring j_desired_trusted_username)
{
	const char *desired_trusted_user_authority_name;
	const char *desired_trusted_username;

	jclass     cls;
	boolean    adding_flag;

	// Get variables from Java
	desired_trusted_user_authority_name = (*env)->GetStringUTFChars(env, j_desired_trusted_user_authority_name, 0);
	desired_trusted_username            = (*env)->GetStringUTFChars(env, j_desired_trusted_username, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Add emergency trusted user
	adding_flag = add_emergency_trusted_user((char *)desired_trusted_user_authority_name, (char *)desired_trusted_username, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_desired_trusted_user_authority_name, desired_trusted_user_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_desired_trusted_username, desired_trusted_username);

	return (jboolean)adding_flag;
}

/*
 * Class:     UserMain
 * Method:    update_emergency_trusted_user_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1emergency_1trusted_1user_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id                   = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id             = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_emergency_trusted_user_table_callback_handler_id  = (*env)->GetMethodID(env, cls, "clear_emergency_trusted_user_table_callback_handler", "()V");
	Java_add_emergency_trusted_user_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_emergency_trusted_user_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_emergency_trusted_user_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_emergency_trusted_user_table_callback_handler\"");

	if(Java_add_emergency_trusted_user_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_emergency_trusted_user_to_table_callback_handler\"");

	// Update an emergency_trusted_user list
	update_emergency_trusted_user_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_emergency_trusted_user_table_callback_handler, add_emergency_trusted_user_to_table_callback_handler);
}

/*
 * Class:     UserMain
 * Method:    update_emergency_phr_owner_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1emergency_1phr_1owner_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id                = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id          = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_emergency_phr_owner_table_callback_handler_id  = (*env)->GetMethodID(env, cls, "clear_emergency_phr_owner_table_callback_handler", "()V");
	Java_add_emergency_phr_owner_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_emergency_phr_owner_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_emergency_phr_owner_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_emergency_phr_owner_table_callback_handler\"");

	if(Java_add_emergency_phr_owner_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_emergency_phr_owner_to_table_callback_handler\"");

	// Update an emergency_PHR owner list
	update_emergency_phr_owner_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_emergency_phr_owner_table_callback_handler, add_emergency_phr_owner_to_table_callback_handler);
}

/*
 * Class:     UserMain
 * Method:    update_restricted_phr_access_request_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserMain_update_1restricted_1phr_1access_1request_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_restricted_phr_access_request_table_callback_handler_id  = (*env)->GetMethodID(env, cls, 
		"clear_restricted_phr_access_request_table_callback_handler", "()V");

	Java_add_restricted_phr_access_request_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_restricted_phr_access_request_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_restricted_phr_access_request_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_restricted_phr_access_request_table_callback_handler\"");

	if(Java_add_restricted_phr_access_request_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_restricted_phr_access_request_to_table_callback_handler\"");

	// Update a restricted-level PHR access request list
	update_restricted_phr_access_request_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_restricted_phr_access_request_table_callback_handler, add_restricted_phr_access_request_to_table_callback_handler);
}

/*
 * Class:     UserMain
 * Method:    approve_restricted_phr_access_request_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserMain_approve_1restricted_1phr_1access_1request_1main(JNIEnv *env, jobject obj, jstring j_phr_ownername, 
	jstring j_phr_owner_authority_name, jint j_remote_site_phr_id, jstring j_phr_description, jstring j_emergency_staff_name, jstring j_emergency_unit_name)
{
	const char   *phr_ownername;
	const char   *phr_owner_authority_name;
	unsigned int remote_site_phr_id;
	const char   *phr_description;
	const char   *emergency_staff_name;
	const char   *emergency_unit_name;

	jclass       cls;
	boolean      approval_flag;

	// Get variables from Java
	phr_ownername            = (*env)->GetStringUTFChars(env, j_phr_ownername, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	remote_site_phr_id       = (unsigned int)j_remote_site_phr_id;
	phr_description          = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	emergency_staff_name     = (*env)->GetStringUTFChars(env, j_emergency_staff_name, 0);
	emergency_unit_name      = (*env)->GetStringUTFChars(env, j_emergency_unit_name, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Approve the restricted-level PHR access request
	approval_flag = approve_restricted_phr_access_request((char *)phr_ownername, (char *)phr_owner_authority_name, remote_site_phr_id, (char *)phr_description, 
		(char *)emergency_staff_name, (char *)emergency_unit_name, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_ownername, phr_ownername);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_name, emergency_staff_name);
	(*env)->ReleaseStringUTFChars(env, j_emergency_unit_name, emergency_unit_name);

	return approval_flag;
}



