// For the Java Native Interface calls
#include <jni.h>

#include "common.h"
#include "EmU_client_common.h"

// JNI Variables
static JNIEnv    *Java_env;
static jobject   Java_object;

static jmethodID Java_backend_alert_msg_callback_handler_id;
static jmethodID Java_backend_fatal_alert_msg_callback_handler_id;
static jmethodID Java_clear_user_table_callback_handler_id;
static jmethodID Java_add_user_to_table_callback_handler_id;
static jmethodID Java_clear_admin_table_callback_handler_id;
static jmethodID Java_add_admin_to_table_callback_handler_id;
static jmethodID Java_clear_phr_authority_table_callback_handler_id;
static jmethodID Java_add_phr_authority_to_table_callback_handler_id;

// Local Function Prototypes
static void backend_alert_msg_callback_handler(char *alert_msg);
static void backend_fatal_alert_msg_callback_handler(char *alert_msg);
static void clear_user_table_callback_handler();
static void add_user_to_table_callback_handler(char *username, char *email_address);
static void clear_admin_table_callback_handler();
static void add_admin_to_table_callback_handler(char *username, char *email_address);
static void clear_phr_authority_table_callback_handler();
static void add_phr_authority_to_table_callback_handler(char *phr_authority_name, char *ip_address);

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

static void clear_user_table_callback_handler()
{
	if(Java_clear_user_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_user_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_user_table_callback_handler_id);
}

static void add_user_to_table_callback_handler(char *username, char *email_address)
{
	if(Java_add_user_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_user_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_user_to_table_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, username), (jstring)(*Java_env)->NewStringUTF(Java_env, email_address));
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

static void clear_phr_authority_table_callback_handler()
{
	if(Java_clear_phr_authority_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_phr_authority_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_clear_phr_authority_table_callback_handler_id);
}

static void add_phr_authority_to_table_callback_handler(char *phr_authority_name, char *ip_address)
{
	if(Java_add_phr_authority_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_phr_authority_to_table_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_add_phr_authority_to_table_callback_handler_id, (jstring)(
		*Java_env)->NewStringUTF(Java_env, phr_authority_name), (jstring)(*Java_env)->NewStringUTF(Java_env, ip_address));
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
 * Class:     EmU_AdminMain
 * Method:    init_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1AdminMain_init_1backend(JNIEnv *env, jobject obj)
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
	init_openssl();

	assert_cache_directory_existence();
}

/*
 * Class:     EmU_AdminMain
 * Method:    store_variables_to_backend
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_EmU_1AdminMain_store_1variables_1to_1backend(JNIEnv *env, jobject obj, jstring j_ssl_cert_hash, 
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

	// Change an emergency unit admin's password
	changing_flag = change_emu_admin_passwd((char *)new_passwd, send_new_passwd_flag, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

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

	// Change an emergency unit admin's e-mail address
	changing_flag = change_emu_admin_email_address((char *)email_address, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

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

	// Change emergency unit's mail server configuration at emergency staff authority
	changing_flag = change_emu_mail_server_configuration((char *)mail_server_url, (char *)authority_email_address, (char *)authority_email_passwd, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_mail_server_url, mail_server_url);
	(*env)->ReleaseStringUTFChars(env, j_authority_email_address, authority_email_address);
	(*env)->ReleaseStringUTFChars(env, j_authority_email_passwd, authority_email_passwd);

	return (jboolean)changing_flag;
}

/*
 * Class:     EmU_AdminMain
 * Method:    update_user_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1AdminMain_update_1user_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_user_table_callback_handler_id        = (*env)->GetMethodID(env, cls, "clear_user_table_callback_handler", "()V");
	Java_add_user_to_table_callback_handler_id       = (*env)->GetMethodID(env, cls, "add_user_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_user_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_user_table_callback_handler\"");

	if(Java_add_user_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_user_to_table_callback_handler\"");

	// Update the emergency unit's user list
	update_emu_user_list(false, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_user_table_callback_handler, add_user_to_table_callback_handler);
}

/*
 * Class:     EmU_AdminMain
 * Method:    update_admin_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1AdminMain_update_1admin_1list_1main(JNIEnv *env, jobject obj)
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

	// Update the emergency unit's admin list
	update_emu_user_list(true, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_admin_table_callback_handler, add_admin_to_table_callback_handler);
}

/*
 * Class:     EmU_AdminMain
 * Method:    update_phr_authority_list_main
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1AdminMain_update_1phr_1authority_1list_1main(JNIEnv *env, jobject obj)
{
	jclass cls;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls         = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id          = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id    = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_clear_phr_authority_table_callback_handler_id  = (*env)->GetMethodID(env, cls, "clear_phr_authority_table_callback_handler", "()V");
	Java_add_phr_authority_to_table_callback_handler_id = (*env)->GetMethodID(env, cls, 
		"add_phr_authority_to_table_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_clear_phr_authority_table_callback_handler_id == 0)
		int_error("Could not find method \"clear_phr_authority_table_callback_handler\"");

	if(Java_add_phr_authority_to_table_callback_handler_id == 0)
		int_error("Could not find method \"add_phr_authority_to_table_callback_handler\"");

	// Update PHR authority list
	update_phr_authority_list(backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler, 
		clear_phr_authority_table_callback_handler, add_phr_authority_to_table_callback_handler);
}

/*
 * Class:     EmU_UserAndAdminManagement
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1UserAndAdminManagement_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     EmU_UserAndAdminManagement
 * Method:    register_user_main
 * Signature: (ZLjava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserAndAdminManagement_register_1user_1main(
	JNIEnv *env, jobject obj, jboolean j_is_admin_flag, jstring j_username, jstring j_email_address)
{
	boolean    is_admin_flag;
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    registration_flag;

	// Get variables from Java
	is_admin_flag = (boolean)j_is_admin_flag;
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

	// Register a emergency unit's user/admin
	registration_flag = register_emu_user(is_admin_flag, (char *)username, (char *)email_address, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)registration_flag;
}

/*
 * Class:     EmU_UserAndAdminManagement
 * Method:    edit_user_email_address_main
 * Signature: (ZLjava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1UserAndAdminManagement_edit_1user_1email_1address_1main(
	JNIEnv *env, jobject obj, jboolean j_is_admin_flag, jstring j_username, jstring j_email_address)
{
	boolean    is_admin_flag;
	const char *username;
	const char *email_address;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	is_admin_flag = (boolean)j_is_admin_flag;
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

	// Edit the emergency unit's user/admin e-mail address
	editing_flag = edit_emu_user_email_address(is_admin_flag, (char *)username, (char *)email_address, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_email_address, email_address);

	return (jboolean)editing_flag;
}

/*
 * Class:     EmU_AdminMain
 * Method:    reset_user_passwd_main
 * Signature: (ZLjava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1AdminMain_reset_1user_1passwd_1main(JNIEnv *env, jobject obj, jboolean j_is_admin_flag, jstring j_username)
{
	boolean    is_admin_flag;
	const char *username;
	jclass     cls;
	boolean    resetting_flag;

	// Get variables from Java
	is_admin_flag = (boolean)j_is_admin_flag;
	username      = (*env)->GetStringUTFChars(env, j_username, 0);

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

	// Reset the emergency unit's user/admin password
	resetting_flag = reset_emu_user_passwd(is_admin_flag, (char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)resetting_flag;
}

/*
 * Class:     EmU_AdminMain
 * Method:    remove_user_main
 * Signature: (ZLjava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1AdminMain_remove_1user_1main(JNIEnv *env, jobject obj, jboolean j_is_admin_flag, jstring j_username)
{
	boolean    is_admin_flag;
	const char *username;
	jclass     cls;
	boolean    removal_flag;

	// Get variables from Java
	is_admin_flag = (boolean)j_is_admin_flag;
	username      = (*env)->GetStringUTFChars(env, j_username, 0);

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

	// Remove the emergency unit's user/admin
	removal_flag = remove_emu_user(is_admin_flag, (char *)username, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return (jboolean)removal_flag;
}

/*
 * Class:     EmU_PHRAuthorityManagement
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1PHRAuthorityManagement_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     EmU_PHRAuthorityManagement
 * Method:    register_phr_authority_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1PHRAuthorityManagement_register_1phr_1authority_1main(JNIEnv *env, jobject obj, jstring j_phr_authority_name, jstring j_ip_address)
{
	const char *phr_authority_name;
	const char *ip_address;

	jclass     cls;
	boolean    registration_flag;

	// Get variables from Java
	phr_authority_name = (*env)->GetStringUTFChars(env, j_phr_authority_name, 0);
	ip_address         = (*env)->GetStringUTFChars(env, j_ip_address, 0);

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

	// Register a PHR authority
	registration_flag = register_phr_authority((char *)phr_authority_name, (char *)ip_address, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_authority_name, phr_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_ip_address, ip_address);

	return (jboolean)registration_flag;
}

/*
 * Class:     EmU_PHRAuthorityManagement
 * Method:    edit_phr_authority_ip_address_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1PHRAuthorityManagement_edit_1phr_1authority_1ip_1address_1main(
	JNIEnv *env, jobject obj, jstring j_phr_authority_name, jstring j_ip_address)
{
	const char *phr_authority_name;
	const char *ip_address;

	jclass     cls;
	boolean    editing_flag;

	// Get variables from Java
	phr_authority_name = (*env)->GetStringUTFChars(env, j_phr_authority_name, 0);
	ip_address         = (*env)->GetStringUTFChars(env, j_ip_address, 0);

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

	// Edit PHR authority's IP address
	editing_flag = edit_phr_authority_ip_address((char *)phr_authority_name, (char *)ip_address, 
		backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_phr_authority_name, phr_authority_name);
	(*env)->ReleaseStringUTFChars(env, j_ip_address, ip_address);

	return (jboolean)editing_flag;
}

/*
 * Class:     EmU_AdminMain
 * Method:    remove_phr_authority_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1AdminMain_remove_1phr_1authority_1main(JNIEnv *env, jobject obj, jstring j_phr_authority_name)
{
	const char *phr_authority_name;
	jclass     cls;
	boolean    removal_flag;

	// Get a variable from Java
	phr_authority_name = (*env)->GetStringUTFChars(env, j_phr_authority_name, 0);

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

	// Remove a PHR authority
	removal_flag = remove_phr_authority((char *)phr_authority_name, backend_alert_msg_callback_handler, backend_fatal_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_phr_authority_name, phr_authority_name);

	return (jboolean)removal_flag;
}



