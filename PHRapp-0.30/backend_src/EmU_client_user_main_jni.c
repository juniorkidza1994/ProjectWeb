// For the Java Native Interface calls
#include <jni.h>

#include "common.h"
#include "EmU_client_common.h"

// JNI Variables
static JNIEnv    *Java_env;
static jobject   Java_object;

static jmethodID Java_backend_alert_msg_callback_handler_id;
static jmethodID Java_backend_fatal_alert_msg_callback_handler_id;
static jmethodID Java_clear_phr_authority_info_list_callback_handler_id;
static jmethodID Java_add_phr_authority_info_to_list_callback_handler_id;
static jmethodID Java_clear_secure_phr_to_table_callback_handler_id;
static jmethodID Java_add_secure_phr_list_to_table_callback_handler_id;
static jmethodID Java_clear_restricted_phr_to_table_callback_handler_id;
static jmethodID Java_add_restricted_phr_list_to_table_callback_handler_id;
static jmethodID Java_clear_requested_restricted_phr_tracking_list_to_table_callback_handler_id;
static jmethodID Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id;
static jmethodID Java_set_emergency_phr_ems_side_processing_success_state_callback_handler_id;
static jmethodID Java_update_emergency_phr_received_progression_callback_handler_id;

// Local Variables
static boolean   emergency_phr_downloading_working_flag;
static boolean   emergency_phr_extracting_working_flag;

// Local Function Prototypes
static void backend_alert_msg_callback_handler(char *alert_msg);
static void backend_fatal_alert_msg_callback_handler(char *alert_msg);
static void clear_phr_authority_info_list_callback_handler();
static void add_phr_authority_info_to_list_callback_handler(char *phr_authority_name, char *ip_address);
static void clear_secure_phr_to_table_callback_handler();
static void add_secure_phr_list_to_table_callback_handler(char *data_description, char *file_size, unsigned int phr_id);
static void clear_restricted_phr_to_table_callback_handler();
static void add_restricted_phr_list_to_table_callback_handler(char *data_description, char *file_size, unsigned int approvals, 
	unsigned int threshold_value, char *request_status, unsigned int phr_id);

static void clear_requested_restricted_phr_tracking_list_to_table_callback_handler();
static void add_requested_restricted_phr_tracking_list_to_table_callback_handler(char *full_phr_ownername, char *data_description, 
	char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id, 
	char *emergency_server_ip_addr);

static void set_emergency_phr_ems_side_processing_success_state_callback_handler();
static void update_emergency_phr_received_progression_callback_handler(unsigned int percent);

static void assert_cache_directory_existence();
static void set_emergency_phr_downloading_working_flag(boolean flag);
static boolean get_emergency_phr_downloading_working_flag();
static void set_emergency_phr_extracting_working_flag(boolean flag);
static boolean get_emergency_phr_extracting_working_flag();

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

static void clear_phr_authority_info_list_callback_handler()
{
	if(Java_clear_phr_authority_info_list_callback_handler_id == 0)
		int_error("Could not find method \"clear_phr_authority_info_list_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_phr_authority_info_list_callback_handler_id);
}

static void add_phr_authority_info_to_list_callback_handler(char *phr_authority_name, char *ip_address)
{
	if(Java_add_phr_authority_info_to_list_callback_handler_id == 0)
		int_error("Could not find method \"add_phr_authority_info_to_list_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_phr_authority_info_to_list_callback_handler_id, (jstring)(
		*Java_env)->NewStringUTF(Java_env, phr_authority_name), (jstring)(*Java_env)->NewStringUTF(Java_env, ip_address));
}

static void clear_secure_phr_to_table_callback_handler()
{
	if(Java_clear_secure_phr_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_secure_phr_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_secure_phr_to_table_callback_handler_id);
}

static void add_secure_phr_list_to_table_callback_handler(char *data_description, char *file_size, unsigned int phr_id)
{
	if(Java_add_secure_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_secure_phr_list_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_secure_phr_list_to_table_callback_handler_id, 
		(jstring)(*Java_env)->NewStringUTF(Java_env, data_description), (jstring)(*Java_env)->NewStringUTF(Java_env, file_size), (jint)phr_id);
}

static void clear_restricted_phr_to_table_callback_handler()
{
	if(Java_clear_restricted_phr_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_restricted_phr_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_restricted_phr_to_table_callback_handler_id);
}

static void add_restricted_phr_list_to_table_callback_handler(char *data_description, char *file_size, unsigned int approvals, 
	unsigned int threshold_value, char *request_status, unsigned int phr_id)
{
	if(Java_add_restricted_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_restricted_phr_list_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_restricted_phr_list_to_table_callback_handler_id, 
		(jstring)(*Java_env)->NewStringUTF(Java_env, data_description), (jstring)(*Java_env)->NewStringUTF(Java_env, file_size), 
		(jint)approvals, (jint)threshold_value, (jstring)(*Java_env)->NewStringUTF(Java_env, request_status), (jint)phr_id);
}

static void clear_requested_restricted_phr_tracking_list_to_table_callback_handler()
{
	if(Java_clear_requested_restricted_phr_tracking_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_requested_restricted_phr_tracking_list_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_requested_restricted_phr_tracking_list_to_table_callback_handler_id);
}

static void add_requested_restricted_phr_tracking_list_to_table_callback_handler(char *full_phr_ownername, char *data_description, 
	char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id, 
	char *emergency_server_ip_addr)
{
	if(Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_requested_restricted_phr_tracking_list_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id, 
		(jstring)(*Java_env)->NewStringUTF(Java_env, full_phr_ownername), (jstring)(*Java_env)->NewStringUTF(Java_env, data_description), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, file_size), (jint)approvals, (jint)threshold_value, (jstring)(*Java_env)->NewStringUTF(
		Java_env, request_status), (jint)phr_id, (jstring)(*Java_env)->NewStringUTF(Java_env, emergency_server_ip_addr));
}

static void set_emergency_phr_ems_side_processing_success_state_callback_handler()
{
	if(Java_set_emergency_phr_ems_side_processing_success_state_callback_handler_id == 0)
		int_error("Could not find method \"set_emergency_phr_ems_side_processing_success_state_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_set_emergency_phr_ems_side_processing_success_state_callback_handler_id);
}

static void update_emergency_phr_received_progression_callback_handler(unsigned int percent)
{
	if(Java_update_emergency_phr_received_progression_callback_handler_id == 0)
		int_error("Could not find method \"update_emergency_phr_received_progression_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_update_emergency_phr_received_progression_callback_handler_id, (jint)(percent));
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
 * Class:     EmU_UserMain
 * Method:    init_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1UserMain_init_1backend(JNIEnv *env, jobject obj)
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
	init_openssl();

	assert_cache_directory_existence();

	emergency_phr_downloading_working_flag = false;
	emergency_phr_extracting_working_flag  = false;
}

/*
 * Class:     EmU_UserMain
 * Method:    store_variables_to_backend
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_EmU_1UserMain_store_1variables_1to_1backend(JNIEnv *env, jobject obj, jstring j_ssl_cert_hash, 
	jstring j_username, jstring j_authority_name, jstring j_passwd, jstring j_emergency_staff_auth_ip_addr)
{
	const char *ssl_cert_hash;
	const char *username;
	const char *authority_name;
	const char *passwd;
	const char *emergency_staff_auth_ip_addr;

	// Get variables from Java
	ssl_cert_hash                = (*env)->GetStringUTFChars(env, j_ssl_cert_hash, 0);
	username                     = (*env)->GetStringUTFChars(env, j_username, 0);
	authority_name               = (*env)->GetStringUTFChars(env, j_authority_name, 0);
	passwd                       = (*env)->GetStringUTFChars(env, j_passwd, 0);
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);

	strncpy(GLOBAL_ssl_cert_hash, ssl_cert_hash, SHA1_DIGEST_LENGTH);
	strncpy(GLOBAL_username, username, USER_NAME_LENGTH);
	strncpy(GLOBAL_authority_name, authority_name, AUTHORITY_NAME_LENGTH);
	strncpy(GLOBAL_passwd, passwd, PASSWD_LENGTH);
	strncpy(GLOBAL_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr, IP_ADDRESS_LENGTH);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_ssl_cert_hash, ssl_cert_hash);
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
	(*env)->ReleaseStringUTFChars(env, j_passwd, passwd);
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);
}

/*
 * Class:     EmU_ShutdownHook
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1ShutdownHook_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
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

	// Change an emergency unit user's password
	changing_flag = change_emu_user_passwd((char *)new_passwd, send_new_passwd_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

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

	// Change an emergency unit user's e-mail address
	changing_flag = change_emu_user_email_address((char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)changing_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    update_phr_authority_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1UserMain_update_1phr_1authority_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id              = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id        = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_phr_authority_info_list_callback_handler_id  = (*env)->GetMethodID(env, cls, "clear_phr_authority_info_list_callback_handler", "()V");
	Java_add_phr_authority_info_to_list_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_phr_authority_info_to_list_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_phr_authority_info_list_callback_handler_id == 0)
		int_error("Could not find method \"clear_phr_authority_info_list_callback_handler\"");

	if(Java_add_phr_authority_info_to_list_callback_handler_id == 0)
		int_error("Could not find method \"add_phr_authority_info_to_list_callback_handler\"");

	// Update PHR authority list
	update_phr_authority_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_phr_authority_info_list_callback_handler, add_phr_authority_info_to_list_callback_handler);
}

/*
 * Class:     EmU_UserMain
 * Method:    check_phr_owner_existence_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_check_1phr_1owner_1existence_1main(JNIEnv *env, jobject obj, 
	jstring j_emergency_server_ip_addr, jstring j_phr_owner_authority_name, jstring j_phr_ownername)
{
	const char *emergency_server_ip_addr;
	const char *phr_owner_authority_name;
	const char *phr_ownername;

	jclass     cls;
	boolean    checking_flag;

	// Get variables from Java
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_ownername            = (*env)->GetStringUTFChars(env, j_phr_ownername, 0);

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

	// Check for the existence of a PHR owner
	checking_flag = check_phr_owner_existence((char *)emergency_server_ip_addr, (char *)phr_owner_authority_name, 
		(char *)phr_ownername, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_server_ip_addr, emergency_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_ownername, phr_ownername);

	return (jboolean)checking_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    load_emergency_phr_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_load_1emergency_1phr_1list_1main(JNIEnv *env, jobject obj, 
	jstring j_emergency_server_ip_addr, jstring j_phr_owner_authority_name, jstring j_phr_ownername)
{
	const char *emergency_server_ip_addr;
	const char *phr_owner_authority_name;
	const char *phr_ownername;

	jclass     cls;
	boolean    loading_flag;

	// Get variables from Java
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_ownername            = (*env)->GetStringUTFChars(env, j_phr_ownername, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id            = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id      = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_secure_phr_to_table_callback_handler_id    = (*env)->GetMethodID(env, cls, "clear_secure_phr_to_table_callback_handler", "()V");
	Java_add_secure_phr_list_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_secure_phr_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;I)V");

	Java_clear_restricted_phr_to_table_callback_handler_id    = (*env)->GetMethodID(env, cls, "clear_restricted_phr_to_table_callback_handler", "()V");
	Java_add_restricted_phr_list_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_restricted_phr_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_secure_phr_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_secure_phr_to_table_callback_handler\"");

	if(Java_add_secure_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_secure_phr_list_to_table_callback_handler\"");

	if(Java_clear_restricted_phr_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_restricted_phr_to_table_callback_handler\"");

	if(Java_add_restricted_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_restricted_phr_list_to_table_callback_handler\"");

	// Load both the secure-level and restricted-level PHRs of the target PHR owner
	loading_flag = load_emergency_phr_list((char *)emergency_server_ip_addr, (char *)phr_owner_authority_name, (char *)phr_ownername, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, clear_secure_phr_to_table_callback_handler, 
		add_secure_phr_list_to_table_callback_handler, clear_restricted_phr_to_table_callback_handler,  add_restricted_phr_list_to_table_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_server_ip_addr, emergency_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_ownername, phr_ownername);

	return (jboolean)loading_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    load_requested_restricted_phr_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_load_1requested_1restricted_1phr_1list_1main(JNIEnv *env, 
	jobject obj, jstring j_phr_authority_name, jstring j_emergency_server_ip_addr)
{
	const char *phr_authority_name;
	const char *emergency_server_ip_addr;

	jclass     cls;
	boolean    loading_flag;

	// Get variables from Java
	phr_authority_name       = (*env)->GetStringUTFChars(env, j_phr_authority_name, 0);
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id   = (*env)->GetMethodID(env, cls, 
		"add_requested_restricted_phr_tracking_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
		"IILjava/lang/String;ILjava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_requested_restricted_phr_tracking_list_to_table_callback_handler\"");

	// Load the requested restricted-level PHRs of PHR owners who are in the target PHR authority
	loading_flag = load_requested_restricted_phr_list((char *)phr_authority_name, (char *)emergency_server_ip_addr, backend_alert_msg_callback_handler, 			backend_fatal_alert_msg_callback_handler, add_requested_restricted_phr_tracking_list_to_table_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_authority_name, phr_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_emergency_server_ip_addr, emergency_server_ip_addr);

	return (jboolean)loading_flag;
}

static void set_emergency_phr_downloading_working_flag(boolean flag)
{
	emergency_phr_downloading_working_flag = flag;
}

static boolean get_emergency_phr_downloading_working_flag()
{
	return emergency_phr_downloading_working_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    download_emergency_phr_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_download_1emergency_1phr_1main(JNIEnv *env, jobject obj, jstring j_target_emergency_server_ip_addr, jstring j_phr_owner_name, 
	jstring j_phr_owner_authority_name, jint j_phr_id, jstring j_phr_description, jboolean j_is_restricted_level_phr_flag)
{
	const char *target_emergency_server_ip_addr;
	const char *phr_owner_name;
	const char *phr_owner_authority_name;
	int        phr_id;
	const char *phr_description;
	boolean    is_restricted_level_phr_flag;

	jclass     cls;
	boolean    downloading_flag;

	// Get variables from Java
	target_emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_target_emergency_server_ip_addr, 0);
	phr_owner_name                  = (*env)->GetStringUTFChars(env, j_phr_owner_name, 0);
	phr_owner_authority_name        = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_id                          = (unsigned int)j_phr_id;
	phr_description                 = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	is_restricted_level_phr_flag    = (boolean)j_is_restricted_level_phr_flag;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	Java_set_emergency_phr_ems_side_processing_success_state_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"set_emergency_phr_ems_side_processing_success_state_callback_handler", "()V");

	Java_update_emergency_phr_received_progression_callback_handler_id           = (*env)->GetMethodID(env, cls, 
		"update_emergency_phr_received_progression_callback_handler", "(I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_set_emergency_phr_ems_side_processing_success_state_callback_handler_id == 0)
		int_error("Could not find method \"set_emergency_phr_ems_side_processing_success_state_callback_handler\"");

	if(Java_update_emergency_phr_received_progression_callback_handler_id == 0)
		int_error("Could not find method \"update_emergency_phr_received_progression_callback_handler\"");

	// Download the emergency PHR
	set_emergency_phr_downloading_working_flag(true);

	downloading_flag = download_emergency_phr((char *)target_emergency_server_ip_addr, (char *)phr_owner_name, (char *)phr_owner_authority_name, 
		phr_id, (char *)phr_description, is_restricted_level_phr_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		set_emergency_phr_ems_side_processing_success_state_callback_handler, update_emergency_phr_received_progression_callback_handler);

	set_emergency_phr_downloading_working_flag(false);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_target_emergency_server_ip_addr, target_emergency_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_name, phr_owner_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);

	return downloading_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    cancel_emergency_phr_downloading_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1UserMain_cancel_1emergency_1phr_1downloading_1main(JNIEnv *env, jobject obj)
{
	if(!get_emergency_phr_downloading_working_flag())
		return;

	cancel_emergency_phr_downloading();
}

static void set_emergency_phr_extracting_working_flag(boolean flag)
{
	emergency_phr_extracting_working_flag = flag;
}

static boolean get_emergency_phr_extracting_working_flag()
{
	return emergency_phr_extracting_working_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    extract_emergency_phr_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_extract_1emergency_1phr_1main(JNIEnv *env, jobject obj, jstring j_phr_download_to_path)
{
	const char *phr_download_to_path;

	jclass     cls;
	boolean    extracting_flag;

	// Get variable from Java
	phr_download_to_path = (*env)->GetStringUTFChars(env, j_phr_download_to_path, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Extract the emergency PHR
	set_emergency_phr_extracting_working_flag(true);
	extracting_flag = extract_emergency_phr((char *)phr_download_to_path, backend_alert_msg_callback_handler);
	set_emergency_phr_extracting_working_flag(false);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_download_to_path, phr_download_to_path);

	return extracting_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    cancel_emergency_phr_extracting_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1UserMain_cancel_1emergency_1phr_1extracting_1main(JNIEnv *env, jobject obj)
{
	if(!get_emergency_phr_extracting_working_flag())
		return;

	cancel_emergency_phr_extracting();
}

/*
 * Class:     EmU_UserMain
 * Method:    request_restricted_level_phr_accessing_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_request_1restricted_1level_1phr_1accessing_1main(JNIEnv *env, jobject obj, jstring j_target_emergency_server_ip_addr, 
	jstring j_phr_owner_authority_name, jstring j_phr_ownername, jint j_phr_id, jstring j_phr_description, jstring j_emergency_staff_email_address)
{
	const char *target_emergency_server_ip_addr;
	const char *phr_owner_authority_name;
	const char *phr_ownername;
	int        phr_id;
	const char *phr_description;
	const char *emergency_staff_email_address;

	jclass     cls;
	boolean    requesting_flag;

	// Get variables from Java
	target_emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_target_emergency_server_ip_addr, 0);
	phr_owner_authority_name        = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_ownername                   = (*env)->GetStringUTFChars(env, j_phr_ownername, 0);
	phr_id                          = (unsigned int)j_phr_id;
	phr_description                 = (*env)->GetStringUTFChars(env, j_phr_description, 0);
	emergency_staff_email_address   = (*env)->GetStringUTFChars(env, j_emergency_staff_email_address, 0);

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

	// Request the restricted-level PHR accessing
	requesting_flag = request_restricted_level_phr_accessing((char *)target_emergency_server_ip_addr, (char *)phr_owner_authority_name, (char *)phr_ownername, phr_id, 
		(char *)phr_description, (char *)emergency_staff_email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_target_emergency_server_ip_addr, target_emergency_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_ownername, phr_ownername);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_email_address, emergency_staff_email_address);

	return requesting_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    cancel_restricted_level_phr_access_request_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_cancel_1restricted_1level_1phr_1access_1request_1main(JNIEnv *env, jobject obj, jstring j_target_emergency_server_ip_addr, 
	jstring j_phr_owner_authority_name, jstring j_phr_ownername, jint j_phr_id, jstring j_phr_description)
{
	const char *target_emergency_server_ip_addr;
	const char *phr_owner_authority_name;
	const char *phr_ownername;
	int        phr_id;
	const char *phr_description;

	jclass     cls;
	boolean    cancelling_flag;

	// Get variables from Java
	target_emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_target_emergency_server_ip_addr, 0);
	phr_owner_authority_name        = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_ownername                   = (*env)->GetStringUTFChars(env, j_phr_ownername, 0);
	phr_id                          = (unsigned int)j_phr_id;
	phr_description                 = (*env)->GetStringUTFChars(env, j_phr_description, 0);

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

	// Cancel a request on the restricted-level PHR accessing
	cancelling_flag = cancel_restricted_level_phr_access_request((char *)target_emergency_server_ip_addr, (char *)phr_owner_authority_name, (char *)phr_ownername, 
		phr_id, (char *)phr_description, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_target_emergency_server_ip_addr, target_emergency_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_ownername, phr_ownername);
	(*env)->ReleaseStringUTFChars(env, j_phr_description, phr_description);

	return cancelling_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    update_restricted_phr_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_update_1restricted_1phr_1list_1main(JNIEnv *env, jobject obj, 
	jstring j_emergency_server_ip_addr, jstring j_phr_owner_authority_name, jstring j_phr_ownername)
{
	const char *emergency_server_ip_addr;
	const char *phr_owner_authority_name;
	const char *phr_ownername;

	jclass     cls;
	boolean    updating_flag;

	// Get variables from Java
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);
	phr_owner_authority_name = (*env)->GetStringUTFChars(env, j_phr_owner_authority_name, 0);
	phr_ownername            = (*env)->GetStringUTFChars(env, j_phr_ownername, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id                = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id          = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_restricted_phr_to_table_callback_handler_id    = (*env)->GetMethodID(env, cls, "clear_restricted_phr_to_table_callback_handler", "()V");
	Java_add_restricted_phr_list_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_restricted_phr_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;I)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_restricted_phr_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_restricted_phr_to_table_callback_handler\"");

	if(Java_add_restricted_phr_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_restricted_phr_list_to_table_callback_handler\"");

	// Updeate the restricted-level PHRs of the target PHR owner
	updating_flag = update_restricted_phr_list((char *)emergency_server_ip_addr, (char *)phr_owner_authority_name, (char *)phr_ownername, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, clear_restricted_phr_to_table_callback_handler, 
		add_restricted_phr_list_to_table_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_server_ip_addr, emergency_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_owner_authority_name, phr_owner_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_phr_ownername, phr_ownername);

	return (jboolean)updating_flag;
}

/*
 * Class:     EmU_UserMain
 * Method:    update_requested_restricted_phr_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserMain_update_1requested_1restricted_1phr_1list_1main(JNIEnv *env, 
	jobject obj, jstring j_phr_authority_name, jstring j_emergency_server_ip_addr)
{
	const char *phr_authority_name;
	const char *emergency_server_ip_addr;

	jclass     cls;
	boolean    updating_flag;

	// Get variables from Java
	phr_authority_name       = (*env)->GetStringUTFChars(env, j_phr_authority_name, 0);
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_requested_restricted_phr_tracking_list_to_table_callback_handler_id = (*env)->GetMethodID(
		env, cls, "clear_requested_restricted_phr_tracking_list_to_table_callback_handler", "()V");

	Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id   = (*env)->GetMethodID(env, cls, 
		"add_requested_restricted_phr_tracking_list_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
		"IILjava/lang/String;ILjava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_requested_restricted_phr_tracking_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_requested_restricted_phr_tracking_list_to_table_callback_handler\"");

	if(Java_add_requested_restricted_phr_tracking_list_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_requested_restricted_phr_tracking_list_to_table_callback_handler\"");

	// Update the requested restricted-level PHRs of PHR owners who are in the target PHR authority
	updating_flag = update_requested_restricted_phr_list((char *)phr_authority_name, (char *)emergency_server_ip_addr, backend_alert_msg_callback_handler, 			backend_fatal_alert_msg_callback_handler, clear_requested_restricted_phr_tracking_list_to_table_callback_handler, 
		add_requested_restricted_phr_tracking_list_to_table_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_authority_name, phr_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_emergency_server_ip_addr, emergency_server_ip_addr);

	return (jboolean)updating_flag;
}



