// For the Java Native Interface calls
#include <jni.h>

#include "common.h"
#include "client_common.h"

// JNI Variables
static JNIEnv    *Java_env;
static jobject   Java_object;

static jmethodID Java_backend_alert_msg_callback_handler_id;
static jmethodID Java_backend_fatal_alert_msg_callback_handler_id;
static jmethodID Java_clear_attribute_table_callback_handler_id;
static jmethodID Java_add_attribute_to_table_callback_handler_id;
static jmethodID Java_get_user_attribute_by_index_callback_handler_id;
static jmethodID Java_clear_user_tree_table_callback_handler_id;
static jmethodID Java_add_user_to_tree_table_callback_handler_id;
static jmethodID Java_attach_numerical_user_attribute_to_tree_table_callback_handler_id;
static jmethodID Java_attach_non_numerical_user_attribute_to_tree_table_callback_handler_id;
static jmethodID Java_repaint_user_tree_table_callback_handler_id;
static jmethodID Java_clear_admin_table_callback_handler_id;
static jmethodID Java_add_admin_to_table_callback_handler_id;
static jmethodID Java_clear_authority_table_callback_handler_id;
static jmethodID Java_add_authority_to_table_callback_handler_id;
static jmethodID Java_add_transaction_admin_login_log_to_table_callback_handler_id;
static jmethodID Java_add_transaction_system_login_log_to_table_callback_handler_id;
static jmethodID Java_add_transaction_event_log_to_table_callback_handler_id;

// Local Function Prototypes
static void backend_alert_msg_callback_handler(char *alert_msg);
static void backend_fatal_alert_msg_callback_handler(char *alert_msg);
static void clear_attribute_table_callback_handler();
static void add_attribute_to_table_callback_handler(char *attribute_name, boolean is_numerical_attribute_flag);

static void get_user_attribute_by_index_callback_handler(unsigned int index, char *user_attribute_buffer_ret);
static void clear_user_tree_table_callback_handler();
static void add_user_to_tree_table_callback_handler(char *username, char *email_address);
static void attach_numerical_user_attribute_to_tree_table_callback_handler(char *username, char *attribute_name, char *authority_name, unsigned int attribute_value);
static void attach_non_numerical_user_attribute_to_tree_table_callback_handler(char *username, char *attribute_name, char *authority_name);
static void repaint_user_tree_table_callback_handler();
static void clear_admin_table_callback_handler();
static void add_admin_to_table_callback_handler(char *username, char *email_address);
static void clear_authority_table_callback_handler();
static void add_authority_to_table_callback_handler(char *authority_name, char *ip_address, boolean authority_join_flag);
static void add_transaction_admin_login_log_to_table_callback_handler(char *date_time, char *ip_address, boolean is_logout_flag);
static void add_transaction_system_login_log_to_table_callback_handler(char *date_time, char *username, 
	char *user_authority_name, boolean is_admin_flag, char *ip_address, boolean is_logout_flag);

static void add_transaction_event_log_to_table_callback_handler(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address);

static void assert_cache_directory_existence();

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

static void get_user_attribute_by_index_callback_handler(unsigned int index, char *user_attribute_buffer_ret)
{
	if(Java_get_user_attribute_by_index_callback_handler_id == 0)
		int_error("Could not find method \"get_user_attribute_by_index_callback_handler\"");

	jstring    j_user_attribute_buffer;
	const char *tmp_user_attribute_buffer;

	// Get user attribute from Java
	j_user_attribute_buffer = (jstring)(*Java_env)->CallObjectMethod(Java_env, Java_object, Java_get_user_attribute_by_index_callback_handler_id, (jint)index);

	if(!j_user_attribute_buffer)
		int_error("\"j_user_attribute_buffer\" is NULL");

	tmp_user_attribute_buffer = (*Java_env)->GetStringUTFChars(Java_env, j_user_attribute_buffer, 0);
	strcpy(user_attribute_buffer_ret, tmp_user_attribute_buffer);

	// Free up the Java string argument
	(*Java_env)->ReleaseStringUTFChars(Java_env, j_user_attribute_buffer, tmp_user_attribute_buffer);
}

static void clear_user_tree_table_callback_handler()
{
	if(Java_clear_user_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_user_tree_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_user_tree_table_callback_handler_id);
}

static void add_user_to_tree_table_callback_handler(char *username, char *email_address)
{
	if(Java_add_user_to_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"add_user_to_tree_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_user_to_tree_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, username), (jstring)(*Java_env)->NewStringUTF(Java_env, email_address));
}

static void attach_numerical_user_attribute_to_tree_table_callback_handler(char *username, char *attribute_name, char *authority_name, unsigned int attribute_value)
{
	if(Java_attach_numerical_user_attribute_to_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"attach_numerical_user_attribute_to_tree_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_attach_numerical_user_attribute_to_tree_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, username), (jstring)(*Java_env)->NewStringUTF(Java_env, attribute_name), (jstring)(*Java_env)->NewStringUTF(Java_env, authority_name), 
		(jint)attribute_value);
}

static void attach_non_numerical_user_attribute_to_tree_table_callback_handler(char *username, char *attribute_name, char *authority_name)
{
	if(Java_attach_numerical_user_attribute_to_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"attach_numerical_user_attribute_to_tree_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_attach_non_numerical_user_attribute_to_tree_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, username), (jstring)(*Java_env)->NewStringUTF(Java_env, attribute_name), (jstring)(*Java_env)->NewStringUTF(Java_env, authority_name));
}

static void repaint_user_tree_table_callback_handler()
{
	if(Java_repaint_user_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"repaint_user_tree_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_repaint_user_tree_table_callback_handler_id);
}

static void clear_admin_table_callback_handler()
{
	if(Java_clear_admin_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_admin_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_admin_table_callback_handler_id);
}

static void add_admin_to_table_callback_handler(char *username, char *email_address)
{
	if(Java_add_admin_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_admin_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_admin_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, username), (jstring)(*Java_env)->NewStringUTF(Java_env, email_address));
}

static void clear_authority_table_callback_handler()
{
	if(Java_clear_authority_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_authority_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_authority_table_callback_handler_id);
}

static void add_authority_to_table_callback_handler(char *authority_name, char *ip_address, boolean authority_join_flag)
{
	if(Java_add_authority_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_authority_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_authority_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, authority_name), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, ip_address), (jboolean)authority_join_flag);
}

static void add_transaction_admin_login_log_to_table_callback_handler(char *date_time, char *ip_address, boolean is_logout_flag)
{
	if(Java_add_transaction_admin_login_log_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_transaction_admin_login_log_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_transaction_admin_login_log_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, date_time), (jstring)(*Java_env)->NewStringUTF(Java_env, ip_address), (jboolean)(is_logout_flag));
}

static void add_transaction_system_login_log_to_table_callback_handler(char *date_time, char *username, 
	char *user_authority_name, boolean is_admin_flag, char *ip_address, boolean is_logout_flag)
{
	if(Java_add_transaction_system_login_log_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_transaction_system_login_log_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_transaction_system_login_log_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, date_time), (jstring)(*Java_env)->NewStringUTF(Java_env, username), (jstring)(*Java_env)->NewStringUTF(Java_env, user_authority_name), 
		(jboolean)(is_admin_flag), (jstring)(*Java_env)->NewStringUTF(Java_env, ip_address), (jboolean)(is_logout_flag));
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
 * Class:     AdminMain
 * Method:    init_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminMain_init_1backend(JNIEnv *env, jobject obj)
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
	init_openssl();

	assert_cache_directory_existence();
}

/*
 * Class:     AdminMain
 * Method:    store_variables_to_backend
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_AdminMain_store_1variables_1to_1backend(JNIEnv *env, jobject obj, jstring j_ssl_cert_hash, 
	jstring j_username, jstring j_authority_name, jstring j_passwd, jstring j_user_auth_ip_addr, jstring j_audit_server_ip_addr)
{
	const char *ssl_cert_hash;
	const char *username;
	const char *authority_name;
	const char *passwd;
	const char *user_auth_ip_addr;
	const char *audit_server_ip_addr;

	// Get variables from Java
	ssl_cert_hash        = (*env)->GetStringUTFChars(env, j_ssl_cert_hash, 0);
	username             = (*env)->GetStringUTFChars(env, j_username, 0);
	authority_name       = (*env)->GetStringUTFChars(env, j_authority_name, 0);
	passwd               = (*env)->GetStringUTFChars(env, j_passwd, 0);
	user_auth_ip_addr    = (*env)->GetStringUTFChars(env, j_user_auth_ip_addr, 0);
	audit_server_ip_addr = (*env)->GetStringUTFChars(env, j_audit_server_ip_addr, 0);

	strncpy(GLOBAL_ssl_cert_hash, ssl_cert_hash, SHA1_DIGEST_LENGTH);
	strncpy(GLOBAL_username, username, USER_NAME_LENGTH);
	strncpy(GLOBAL_authority_name, authority_name, AUTHORITY_NAME_LENGTH);
	strncpy(GLOBAL_passwd, passwd, PASSWD_LENGTH);
	strncpy(GLOBAL_user_auth_ip_addr, user_auth_ip_addr, IP_ADDRESS_LENGTH);
	strncpy(GLOBAL_audit_server_ip_addr, audit_server_ip_addr, IP_ADDRESS_LENGTH);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_ssl_cert_hash, ssl_cert_hash);
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
	(*env)->ReleaseStringUTFChars(env, j_passwd, passwd);
	(*env)->ReleaseStringUTFChars(env, j_user_auth_ip_addr, user_auth_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_audit_server_ip_addr, audit_server_ip_addr);
}

/*
 * Class:     AttributeRegistration
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AttributeRegistration_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     AttributeRegistration
 * Method:    register_attribute_main
 * Signature: (Ljava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_AttributeRegistration_register_1attribute_1main(JNIEnv *env, jobject obj, jstring j_attribute_name, jboolean j_is_numerical_attribute_flag)
{
	const char *attribute_name;
	boolean    is_numerical_attribute_flag;

	jclass     cls;
	boolean    registration_flag;

	// Get variables from Java
	attribute_name              = (*env)->GetStringUTFChars(env, j_attribute_name, 0);
	is_numerical_attribute_flag = (boolean)j_is_numerical_attribute_flag;

	Java_env                    = env;
  	Java_object                 = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Register attribute
	registration_flag = register_attribute((char *)attribute_name, is_numerical_attribute_flag, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_attribute_name, attribute_name);

	return (jboolean)registration_flag;
}

/*
 * Class:     AdminMain
 * Method:    update_attribute_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminMain_update_1attribute_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

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
	update_attribute_list_for_admin(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_attribute_table_callback_handler, add_attribute_to_table_callback_handler);
}

/*
 * Class:     UserManagement
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_UserManagement_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     UserManagement
 * Method:    register_user_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserManagement_register_1user_1main(JNIEnv *env, jobject obj, jstring j_username, jstring j_email_address)
{
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    registration_flag;

	// Get variables from Java
	username      = (*env)->GetStringUTFChars(env, j_username, 0);
	email_address = (*env)->GetStringUTFChars(env, j_email_address, 0);

	Java_env     = env;
  	Java_object  = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id           = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id     = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_get_user_attribute_by_index_callback_handler_id = (*env)->GetMethodID(env, cls, "get_user_attribute_by_index_callback_handler", "(I)Ljava/lang/String;");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_get_user_attribute_by_index_callback_handler_id == 0)
		int_error("Could not find method \"get_user_attribute_by_index_callback_handler\"");

	// Register user
	registration_flag = register_user((char *)username, (char *)email_address, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, get_user_attribute_by_index_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)registration_flag;
}

/*
 * Class:     AdminMain
 * Method:    update_user_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminMain_update_1user_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_user_tree_table_callback_handler_id   = (*env)->GetMethodID(env, cls, "clear_user_tree_table_callback_handler", "()V");
	Java_add_user_to_tree_table_callback_handler_id  = (*env)->GetMethodID(env, cls, "add_user_to_tree_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	Java_attach_numerical_user_attribute_to_tree_table_callback_handler_id     = (*env)->GetMethodID(env, cls, 
		"attach_numerical_user_attribute_to_tree_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

	Java_attach_non_numerical_user_attribute_to_tree_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"attach_non_numerical_user_attribute_to_tree_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

	Java_repaint_user_tree_table_callback_handler_id = (*env)->GetMethodID(env, cls, "repaint_user_tree_table_callback_handler", "()V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_user_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_user_tree_table_callback_handler\"");

	if(Java_add_user_to_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"add_user_to_tree_table_callback_handler\"");

	if(Java_attach_numerical_user_attribute_to_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"attach_numerical_user_attribute_to_tree_table_callback_handler\"");
	
	if(Java_attach_non_numerical_user_attribute_to_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"attach_non_numerical_user_attribute_to_tree_table_callback_handler\"");

	if(Java_repaint_user_tree_table_callback_handler_id == 0)
		int_error("Could not find method \"repaint_user_tree_table_callback_handler\"");

	// Update user list
	update_user_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, clear_user_tree_table_callback_handler, 
		add_user_to_tree_table_callback_handler, attach_numerical_user_attribute_to_tree_table_callback_handler, 
		attach_non_numerical_user_attribute_to_tree_table_callback_handler, repaint_user_tree_table_callback_handler);
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
	record_transaction_logout_log((char *)username, true, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
}

/*
 * Class:     AdminMain
 * Method:    update_admin_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminMain_update_1admin_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_admin_table_callback_handler_id       = (*env)->GetMethodID(env, cls, "clear_admin_table_callback_handler", "()V");
	Java_add_admin_to_table_callback_handler_id      = (*env)->GetMethodID(env, cls, "add_admin_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_admin_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_admin_table_callback_handler\"");

	if(Java_add_admin_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_admin_to_table_callback_handler\"");

	// Update admin list
	update_admin_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_admin_table_callback_handler, add_admin_to_table_callback_handler);
}

/*
 * Class:     AdminTransactionAuditing
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminTransactionAuditing_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     AdminTransactionAuditing
 * Method:    audit_all_transaction_logs_main
 * Signature: (ZZ)V
 */
JNIEXPORT void JNICALL Java_AdminTransactionAuditing_audit_1all_1transaction_1logs_1main(
	JNIEnv *env, jobject obj, jboolean j_audit_admin_log_flag, jboolean j_audit_login_log_flag)
{
	boolean audit_admin_log_flag;
	boolean audit_login_log_flag;
	jclass  cls;

	// Get variables from Java
	audit_admin_log_flag = (boolean)j_audit_admin_log_flag;
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

	if(audit_admin_log_flag)
	{
		if(audit_login_log_flag)  // Admin login log
		{
			Java_add_transaction_admin_login_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_admin_login_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Z)V");

			if(Java_add_transaction_admin_login_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_admin_login_log_to_table_callback_handler\"");

			// Audit transaction admin login log
			audit_all_transaction_admin_login_log(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
				add_transaction_admin_login_log_to_table_callback_handler);			
		}
		else // Admin event log
		{
			Java_add_transaction_event_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_event_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;"
				"Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V");

			if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");

			// Audit transaction admin event log
			audit_all_transaction_admin_event_log(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
				add_transaction_event_log_to_table_callback_handler);
		}
	}
	else
	{
		if(audit_login_log_flag)  // System login log
		{
			Java_add_transaction_system_login_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_system_login_log_to_table_callback_handler", 
				"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Z)V");

			if(Java_add_transaction_system_login_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_system_login_log_to_table_callback_handler\"");

			// Audit transaction system login log
			audit_all_transaction_system_login_log(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
				add_transaction_system_login_log_to_table_callback_handler);
		}
		else // System event log
		{
			Java_add_transaction_event_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_event_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;"
				"Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V");

			if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");
			
			// Audit transaction system event log
			audit_all_transaction_system_event_log(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
				add_transaction_event_log_to_table_callback_handler);
		}
	}
}

/*
 * Class:     AdminTransactionAuditing
 * Method:    audit_some_period_time_transaction_logs_main
 * Signature: (ZZLjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_AdminTransactionAuditing_audit_1some_1period_1time_1transaction_1logs_1main(
	JNIEnv *env, jobject obj, jboolean j_audit_admin_log_flag, jboolean j_audit_login_log_flag, jstring j_start_date_time, jstring j_end_date_time)
{
	boolean    audit_admin_log_flag;
	boolean    audit_login_log_flag;
	const char *start_date_time;
	const char *end_date_time;

	jclass     cls;

	// Get variables from Java
	audit_admin_log_flag = (boolean)j_audit_admin_log_flag;
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

	if(audit_admin_log_flag)
	{
		if(audit_login_log_flag)  // Admin login log
		{
			Java_add_transaction_admin_login_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_admin_login_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Z)V");

			if(Java_add_transaction_admin_login_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_admin_login_log_to_table_callback_handler\"");

			// Audit transaction admin login log
			audit_some_period_time_transaction_admin_login_log((char *)start_date_time, (char *)end_date_time, backend_alert_msg_callback_handler, 
				backend_fatal_alert_msg_callback_handler, add_transaction_admin_login_log_to_table_callback_handler);			
		}
		else // Admin event log
		{
			Java_add_transaction_event_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_event_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;"
				"Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V");

			if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");

			// Audit transaction admin event log
			audit_some_period_time_transaction_admin_event_log((char *)start_date_time, (char *)end_date_time, backend_alert_msg_callback_handler, 
				backend_fatal_alert_msg_callback_handler, add_transaction_event_log_to_table_callback_handler);
		}
	}
	else
	{
		if(audit_login_log_flag)  // System login log
		{
			Java_add_transaction_system_login_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_system_login_log_to_table_callback_handler", 
				"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Z)V");

			if(Java_add_transaction_system_login_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_system_login_log_to_table_callback_handler\"");

			// Audit transaction system login log
			audit_some_period_time_transaction_system_login_log((char *)start_date_time, (char *)end_date_time, backend_alert_msg_callback_handler, 
				backend_fatal_alert_msg_callback_handler, add_transaction_system_login_log_to_table_callback_handler);
		}
		else // System event log
		{
			Java_add_transaction_event_log_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
				"add_transaction_event_log_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;"
				"Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;)V");

			if(Java_add_transaction_event_log_to_table_callback_handler_id == 0)
				int_error("Could not find method \"add_transaction_event_log_to_table_callback_handler\"");
			
			// Audit transaction system event log
			audit_some_period_time_transaction_system_event_log((char *)start_date_time, (char *)end_date_time, backend_alert_msg_callback_handler, 
				backend_fatal_alert_msg_callback_handler, add_transaction_event_log_to_table_callback_handler);
		}
	}

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_start_date_time, start_date_time);
	(*env)->ReleaseStringUTFChars(env, j_end_date_time, end_date_time);
}

/*
 * Class:     UserManagement
 * Method:    edit_user_email_address_and_attribute_list_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserManagement_edit_1user_1email_1address_1and_1attribute_1list_1main(JNIEnv *env, jobject obj, jstring j_username, jstring j_email_address)
{
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	username      = (*env)->GetStringUTFChars(env, j_username, 0);
	email_address = (*env)->GetStringUTFChars(env, j_email_address, 0);

	Java_env     = env;
  	Java_object  = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id           = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id     = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_get_user_attribute_by_index_callback_handler_id = (*env)->GetMethodID(env, cls, "get_user_attribute_by_index_callback_handler", "(I)Ljava/lang/String;");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_get_user_attribute_by_index_callback_handler_id == 0)
		int_error("Could not find method \"get_user_attribute_by_index_callback_handler\"");

	// Edit user's e-mail address and attribute list
	editing_flag = edit_user_email_address_and_attribute_list((char *)username, (char *)email_address, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, get_user_attribute_by_index_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)editing_flag;
}

/*
 * Class:     UserManagement
 * Method:    edit_user_email_address_only_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserManagement_edit_1user_1email_1address_1only_1main(JNIEnv *env, jobject obj, jstring j_username, jstring j_email_address)
{
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	username      = (*env)->GetStringUTFChars(env, j_username, 0);
	email_address = (*env)->GetStringUTFChars(env, j_email_address, 0);

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

	// Edit user's e-mail address
	editing_flag = edit_user_email_address_only((char *)username, (char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)editing_flag;
}

/*
 * Class:     UserManagement
 * Method:    edit_user_attribute_list_only_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_UserManagement_edit_1user_1attribute_1list_1only_1main(JNIEnv *env, jobject obj, jstring j_username)
{
	const char *username;
	jclass     cls;
	boolean    editing_flag;

	// Get a variable from Java
	username    = (*env)->GetStringUTFChars(env, j_username, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id           = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id     = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_get_user_attribute_by_index_callback_handler_id = (*env)->GetMethodID(env, cls, "get_user_attribute_by_index_callback_handler", "(I)Ljava/lang/String;");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_get_user_attribute_by_index_callback_handler_id == 0)
		int_error("Could not find method \"get_user_attribute_by_index_callback_handler\"");

	// Edit user's attribute list
	editing_flag = edit_user_attribute_list_only((char *)username, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, get_user_attribute_by_index_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)editing_flag;
}

/*
 * Class:     NumericalAttributeValueEditing
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_NumericalAttributeValueEditing_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     NumericalAttributeValueEditing
 * Method:    edit_user_attribute_value_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_NumericalAttributeValueEditing_edit_1user_1attribute_1value_1main(JNIEnv *env, jobject obj, 
	jstring j_username, jstring j_attribute_name, jstring j_attribute_authority_name, jstring j_attribute_value)
{
	const char *username;
	const char *attribute_name;
	const char *attribute_authority_name;
	const char *attribute_value;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	username                 = (*env)->GetStringUTFChars(env, j_username, 0);
	attribute_name           = (*env)->GetStringUTFChars(env, j_attribute_name, 0);
	attribute_authority_name = (*env)->GetStringUTFChars(env, j_attribute_authority_name, 0);
	attribute_value          = (*env)->GetStringUTFChars(env, j_attribute_value, 0);

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

	// Edit user's attribute value
	editing_flag = edit_user_attribute_value((char *)username, (char *)attribute_name, (char *)attribute_authority_name, (char *)attribute_value, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_attribute_name, attribute_name);
	(*env)->ReleaseStringUTFChars(env, j_attribute_authority_name, attribute_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_attribute_value, attribute_value);

	return (jboolean)editing_flag;
}

/*
 * Class:     AdminMain
 * Method:    remove_attribute_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_remove_1attribute_1main(JNIEnv *env, jobject obj, jstring j_attribute_name)
{
	const char *attribute_name;
	jclass     cls;
	boolean    removal_flag;

	// Get a variable from Java
	attribute_name = (*env)->GetStringUTFChars(env, j_attribute_name, 0);

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

	// Remove an attribute
	removal_flag = remove_attribute((char *)attribute_name, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_attribute_name, attribute_name);

	return (jboolean)removal_flag;
}

/*
 * Class:     AdminMain
 * Method:    reset_user_passwd_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_reset_1user_1passwd_1main(JNIEnv *env, jobject obj, jstring j_username)
{
	const char *username;
	jclass     cls;
	boolean    resetting_flag;

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

	// Reset user password
	resetting_flag = reset_user_passwd((char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)resetting_flag;
}

/*
 * Class:     AdminMain
 * Method:    remove_user_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_remove_1user_1main(JNIEnv *env, jobject obj, jstring j_username)
{
	const char *username;
	jclass     cls;
	boolean    removal_flag;

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

	// Remove a user
	removal_flag = remove_user((char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)removal_flag;
}

/*
 * Class:     AdminMain
 * Method:    remove_user_attribute_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_remove_1user_1attribute_1main(JNIEnv *env, jobject obj, 
	jstring j_username, jstring j_attribute_name, jstring j_attribute_authority_name)
{
	const char *username;
	const char *attribute_name;
	const char *attribute_authority_name;

	jclass     cls;
	boolean    removal_flag;

	// Get variables from Java
	username                 = (*env)->GetStringUTFChars(env, j_username, 0);
	attribute_name           = (*env)->GetStringUTFChars(env, j_attribute_name, 0);
	attribute_authority_name = (*env)->GetStringUTFChars(env, j_attribute_authority_name, 0);

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

	// Remove a user attribute
	removal_flag = remove_user_attribute((char *)username, (char *)attribute_name, (char *)attribute_authority_name, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_attribute_name, attribute_name);
	(*env)->ReleaseStringUTFChars(env, j_attribute_authority_name, attribute_authority_name);

	return (jboolean)removal_flag;
}

/*
 * Class:     AdminManagement
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminManagement_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     AdminManagement
 * Method:    register_admin_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminManagement_register_1admin_1main(JNIEnv *env, jobject obj, jstring j_username, jstring j_email_address)
{
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    registration_flag;

	// Get variables from Java
	username      = (*env)->GetStringUTFChars(env, j_username, 0);
	email_address = (*env)->GetStringUTFChars(env, j_email_address, 0);

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

	// Register admin
	registration_flag = register_admin((char *)username, (char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)registration_flag;
}

/*
 * Class:     AdminManagement
 * Method:    edit_admin_email_address_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminManagement_edit_1admin_1email_1address_1main(JNIEnv *env, jobject obj, jstring j_username, jstring j_email_address)
{
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	username      = (*env)->GetStringUTFChars(env, j_username, 0);
	email_address = (*env)->GetStringUTFChars(env, j_email_address, 0);

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

	// Edit admin's e-mail address
	editing_flag = edit_admin_email_address((char *)username, (char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)editing_flag;
}

/*
 * Class:     AdminMain
 * Method:    reset_admin_passwd_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_reset_1admin_1passwd_1main(JNIEnv *env, jobject obj, jstring j_username)
{
	const char *username;
	jclass     cls;
	boolean    resetting_flag;

	// Get a variable from Java
	username     = (*env)->GetStringUTFChars(env, j_username, 0);

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

	// Reset admin password
	resetting_flag = reset_admin_passwd((char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)resetting_flag;
}

/*
 * Class:     AdminMain
 * Method:    remove_admin_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_remove_1admin_1main(JNIEnv *env, jobject obj, jstring j_username)
{
	const char *username;
	jclass     cls;
	boolean    removal_flag;

	// Get a variable from Java
	username     = (*env)->GetStringUTFChars(env, j_username, 0);

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

	// Remove admin
	removal_flag = remove_admin((char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

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
 * Method:    change_admin_passwd_main
 * Signature: (Ljava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_NewPasswordChanging_change_1admin_1passwd_1main(JNIEnv *env, jobject obj, jstring j_new_passwd, jboolean j_send_new_passwd_flag)
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

	// Change an admin's password
	changing_flag = change_admin_passwd((char *)new_passwd, send_new_passwd_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

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
 * Method:    change_admin_email_address_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmailAddressChanging_change_1admin_1email_1address_1main(JNIEnv *env, jobject obj, jstring j_email_address)
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

	// Change an admin's e-mail address
	changing_flag = change_admin_email_address((char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)changing_flag;
}

/*
 * Class:     AuthorityManagement
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AuthorityManagement_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     AuthorityManagement
 * Method:    register_authority_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AuthorityManagement_register_1authority_1main(JNIEnv *env, jobject obj, jstring j_authority_name, jstring j_ip_address)
{
	const char *authority_name;
	const char *ip_address;

	jclass     cls;
	boolean    registration_flag;

	// Get variables from Java
	authority_name = (*env)->GetStringUTFChars(env, j_authority_name, 0);
	ip_address     = (*env)->GetStringUTFChars(env, j_ip_address, 0);

	Java_env       = env;
  	Java_object    = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Register an authority
	registration_flag = register_authority((char *)authority_name, (char *)ip_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
	(*env)->ReleaseStringUTFChars(env, j_ip_address, ip_address);

	return (jboolean)registration_flag;
}

/*
 * Class:     AuthorityManagement
 * Method:    edit_authority_ip_address_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AuthorityManagement_edit_1authority_1ip_1address_1main(JNIEnv *env, jobject obj, jstring j_authority_name, jstring j_ip_address)
{
	const char *authority_name;
	const char *ip_address;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	authority_name = (*env)->GetStringUTFChars(env, j_authority_name, 0);
	ip_address     = (*env)->GetStringUTFChars(env, j_ip_address, 0);

	Java_env       = env;
  	Java_object    = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Edit authority's IP address
	editing_flag = edit_authority_ip_address((char *)authority_name, (char *)ip_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);
	(*env)->ReleaseStringUTFChars(env, j_ip_address, ip_address);

	return (jboolean)editing_flag;
}

/*
 * Class:     AdminMain
 * Method:    update_authority_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_AdminMain_update_1authority_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_authority_table_callback_handler_id   = (*env)->GetMethodID(env, cls, "clear_authority_table_callback_handler", "()V");
	Java_add_authority_to_table_callback_handler_id  = (*env)->GetMethodID(env, cls, 
		"add_authority_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;Z)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_authority_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_authority_table_callback_handler\"");

	if(Java_add_authority_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_authority_to_table_callback_handler\"");

	// Update authority list
	update_authority_list_for_admin(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_authority_table_callback_handler, add_authority_to_table_callback_handler);
}

/*
 * Class:     AdminMain
 * Method:    remove_authority_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_AdminMain_remove_1authority_1main(JNIEnv *env, jobject obj, jstring j_authority_name)
{
	const char *authority_name;
	jclass     cls;
	boolean    removal_flag;

	// Get a variable from Java
	authority_name = (*env)->GetStringUTFChars(env, j_authority_name, 0);

	Java_env       = env;
  	Java_object    = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	// Remove authority
	removal_flag = remove_authority((char *)authority_name, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_authority_name, authority_name);

	return (jboolean)removal_flag;
}

/*
 * Class:     ServerAddressesConfigurationChanging
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_ServerAddressesConfigurationChanging_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     ServerAddressesConfigurationChanging
 * Method:    change_server_addresses_configuration
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_ServerAddressesConfigurationChanging_change_1server_1addresses_1configuration(
	JNIEnv *env, jobject obj, jstring j_audit_server_ip_addr, jstring j_phr_server_ip_addr, jstring j_emergency_server_ip_addr)
{
	const char *audit_server_ip_addr;
	const char *phr_server_ip_addr;
	const char *emergency_server_ip_addr;

	jclass     cls;
	boolean    changing_flag;

	// Get variables from Java
	audit_server_ip_addr     = (*env)->GetStringUTFChars(env, j_audit_server_ip_addr, 0);
	phr_server_ip_addr       = (*env)->GetStringUTFChars(env, j_phr_server_ip_addr, 0);
	emergency_server_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_server_ip_addr, 0);

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

	// Update global variables
	strcpy(GLOBAL_audit_server_ip_addr, audit_server_ip_addr);
	strcpy(GLOBAL_phr_server_ip_addr, phr_server_ip_addr);
	strcpy(GLOBAL_emergency_server_ip_addr, emergency_server_ip_addr);

	// Change server addresses configuration at both the user authority and emergency server
	changing_flag = change_server_addresses_configuration((char *)audit_server_ip_addr, (char *)phr_server_ip_addr, (char *)emergency_server_ip_addr, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_audit_server_ip_addr, audit_server_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_phr_server_ip_addr, phr_server_ip_addr);

	return (jboolean)changing_flag;
}

/*
 * Class:     MailServerConfigurationChanging
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_MailServerConfigurationChanging_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     MailServerConfigurationChanging
 * Method:    change_mail_server_configuration
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_MailServerConfigurationChanging_change_1mail_1server_1configuration(JNIEnv *env, jobject obj, 
	jstring j_mail_server_url, jstring j_authority_email_address, jstring j_authority_email_passwd)
{
	const char *mail_server_url;
	const char *authority_email_address;
	const char *authority_email_passwd;

	jclass     cls;
	boolean    changing_flag;

	// Get variables from Java
	mail_server_url         = (*env)->GetStringUTFChars(env, j_mail_server_url, 0);
	authority_email_address = (*env)->GetStringUTFChars(env, j_authority_email_address, 0);
	authority_email_passwd  = (*env)->GetStringUTFChars(env, j_authority_email_passwd, 0);

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

	// Change mail server configuration at both the user authority and emergency server
	changing_flag = change_mail_server_configuration((char *)mail_server_url, (char *)authority_email_address, (char *)authority_email_passwd, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_mail_server_url, mail_server_url);
	(*env)->ReleaseStringUTFChars(env, j_authority_email_address, authority_email_address);
	(*env)->ReleaseStringUTFChars(env, j_authority_email_passwd, authority_email_passwd);

	return (jboolean)changing_flag;
}



