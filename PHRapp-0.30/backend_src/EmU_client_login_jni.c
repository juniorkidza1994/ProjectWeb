// For the Java Native Interface calls
#include <jni.h>

#include "common.h"
#include "EmU_client_common.h"

// JNI Variables
static JNIEnv    *Java_env;
static jobject   Java_object;

static jmethodID Java_backend_alert_msg_callback_handler_id;
static jmethodID Java_backend_fatal_alert_msg_callback_handler_id;

static jmethodID Java_basic_info_ret_callback_handler_id;
static jmethodID Java_mail_server_configuration_ret_callback_handler_id;
static jmethodID Java_ssl_cert_hash_ret_callback_handler_id;

// Local Function Prototypes
static void backend_alert_msg_callback_handler(char *alert_msg);
static void backend_fatal_alert_msg_callback_handler(char *alert_msg);
static void basic_info_ret_callback_handler(char *email_address, char *authority_name);
static void ssl_cert_hash_ret_callback_handler(char *ssl_cert_hash);

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

static void basic_info_ret_callback_handler(char *email_address, char *authority_name)
{
	if(Java_basic_info_ret_callback_handler_id == 0)
		int_error("Could not find method \"basic_info_ret_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_basic_info_ret_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, email_address), 
		(jstring)(*Java_env)->NewStringUTF(Java_env, authority_name));
}

static void mail_server_configuration_ret_callback_handler(char *mail_server_url, char *authority_email_address, char *authority_email_passwd)
{
	if(Java_mail_server_configuration_ret_callback_handler_id == 0)
		int_error("Could not find method \"mail_server_configuration_ret_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_mail_server_configuration_ret_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(
		Java_env, mail_server_url), (jstring)(*Java_env)->NewStringUTF(Java_env, authority_email_address), (jstring)(*Java_env)->NewStringUTF(
		Java_env, authority_email_passwd));
}

static void ssl_cert_hash_ret_callback_handler(char *ssl_cert_hash)
{
	if(Java_ssl_cert_hash_ret_callback_handler_id == 0)
		int_error("Could not find method \"ssl_cert_hash_ret_callback_handler\"");

	(*Java_env)->CallVoidMethod(Java_env, Java_object, Java_ssl_cert_hash_ret_callback_handler_id, (jstring)(*Java_env)->NewStringUTF(Java_env, ssl_cert_hash));
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
 * Class:     EmU_Login
 * Method:    init_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1Login_init_1backend(JNIEnv *env, jobject obj)
{
	set_using_safety_threads_for_openssl(true);
	seed_prng();
	init_openssl();

	assert_cache_directory_existence();
}

/*
 * Class:     EmU_Login
 * Method:    uninit_backend
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_EmU_1Login_uninit_1backend(JNIEnv *env, jobject obj)
{
	recursive_remove(CACHE_DIRECTORY_PATH);
	uninit_openssl();
}

/*
 * Class:     EmU_Login
 * Method:    user_login_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1Login_user_1login_1main(JNIEnv *env, jobject obj, jstring j_emergency_staff_auth_ip_addr, jstring j_username, jstring j_passwd)
{
	const char *emergency_staff_auth_ip_addr;
	const char *username;
	const char *passwd;
	jclass     cls;
	boolean    authentication_flag;

	// Get Emergency Staff Authority's IP address, username and password from Java
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);
	username          	     = (*env)->GetStringUTFChars(env, j_username, 0);
	passwd            	     = (*env)->GetStringUTFChars(env, j_passwd, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_basic_info_ret_callback_handler_id          = (*env)->GetMethodID(env, cls, "basic_info_ret_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");
	Java_ssl_cert_hash_ret_callback_handler_id       = (*env)->GetMethodID(env, cls, "ssl_cert_hash_ret_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_basic_info_ret_callback_handler_id == 0)
		int_error("Could not find method \"basic_info_ret_callback_handler\"");

	if(Java_ssl_cert_hash_ret_callback_handler_id == 0)
		int_error("Could not find method \"ssl_cert_hash_ret_callback_handler\"");

	// Authenticate the user
	authentication_flag = authenticate_user((char *)emergency_staff_auth_ip_addr, (char *)username, (char *)passwd, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, basic_info_ret_callback_handler, ssl_cert_hash_ret_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_passwd, passwd);

	return authentication_flag;
}

/*
 * Class:     EmU_Login
 * Method:    admin_login_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1Login_admin_1login_1main(JNIEnv *env, jobject obj, jstring j_emergency_staff_auth_ip_addr, jstring j_username, jstring j_passwd)
{
	const char *emergency_staff_auth_ip_addr;
	const char *username;
	const char *passwd;

	jclass     cls;
	boolean    authentication_flag;

	// Get variables from Java
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);
	username          	     = (*env)->GetStringUTFChars(env, j_username, 0);
	passwd            	     = (*env)->GetStringUTFChars(env, j_passwd, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id             = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_backend_fatal_alert_msg_callback_handler_id       = (*env)->GetMethodID(env, cls, "backend_fatal_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	Java_basic_info_ret_callback_handler_id                = (*env)->GetMethodID(env, cls, "basic_info_ret_callback_handler", "(Ljava/lang/String;Ljava/lang/String;)V");

	Java_mail_server_configuration_ret_callback_handler_id = (*env)->GetMethodID(env, cls, "mail_server_configuration_ret_callback_handler", 
		"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

	Java_ssl_cert_hash_ret_callback_handler_id             = (*env)->GetMethodID(env, cls, "ssl_cert_hash_ret_callback_handler", "(Ljava/lang/String;)V");

	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	if(Java_backend_fatal_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_fatal_alert_msg_callback_handler\"");

	if(Java_basic_info_ret_callback_handler_id == 0)
		int_error("Could not find method \"basic_info_ret_callback_handler\"");

	if(Java_mail_server_configuration_ret_callback_handler_id == 0)
		int_error("Could not find method \"mail_server_configuration_ret_callback_handler\"");

	if(Java_ssl_cert_hash_ret_callback_handler_id == 0)
		int_error("Could not find method \"ssl_cert_hash_ret_callback_handler\"");

	// Authenticate the admin
	authentication_flag = authenticate_admin((char *)emergency_staff_auth_ip_addr, (char *)username, (char *)passwd, backend_alert_msg_callback_handler, 
		backend_fatal_alert_msg_callback_handler, basic_info_ret_callback_handler, mail_server_configuration_ret_callback_handler, ssl_cert_hash_ret_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_passwd, passwd);

	return authentication_flag;
}

/*
 * Class:     EmU_Login
 * Method:    load_emergency_staff_authority_pub_key_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1Login_load_1emergency_1staff_1authority_1pub_1key_1main(JNIEnv *env, jobject obj, jstring j_emergency_staff_auth_ip_addr)
{
	const char *emergency_staff_auth_ip_addr;
	jclass     cls;
	boolean    loading_flag;

	// Get a variable from Java
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Load an emergency staff authority's public key
	loading_flag = load_emergency_staff_authority_pub_key((char *)emergency_staff_auth_ip_addr, backend_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);

	return loading_flag;
}

/*
 * Class:     EmU_ForgetPassword
 * Method:    load_emergency_staff_authority_pub_key_main
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1ForgetPassword_load_1emergency_1staff_1authority_1pub_1key_1main(JNIEnv *env, jobject obj, jstring j_emergency_staff_auth_ip_addr)
{
	const char *emergency_staff_auth_ip_addr;
	jclass     cls;
	boolean    loading_flag;

	// Get a variable from Java
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Load a emergency staff authority's public key
	loading_flag = load_emergency_staff_authority_pub_key((char *)emergency_staff_auth_ip_addr, backend_alert_msg_callback_handler);

	// Free up the Java string argument
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);

	return loading_flag;
}

/*
 * Class:     EmU_ForgetPassword
 * Method:    request_passwd_resetting_code_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1ForgetPassword_request_1passwd_1resetting_1code_1main(JNIEnv *env, 
	jobject obj, jstring j_emergency_staff_auth_ip_addr, jstring j_username, jboolean j_is_admin_flag)
{
	const char *emergency_staff_auth_ip_addr;
	const char *username;
	boolean    is_admin_flag;

	jclass     cls;
	boolean    requesting_flag;

	// Get variables from Java
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);
	username                     = (*env)->GetStringUTFChars(env, j_username, 0);
	is_admin_flag                = (boolean)j_is_admin_flag;

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Request for password resetting code
	requesting_flag = request_emu_passwd_resetting_code((char *)emergency_staff_auth_ip_addr, (char *)username, is_admin_flag, backend_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_username, username);

	return requesting_flag;
}

/*
 * Class:     EmU_ForgetPassword
 * Method:    reset_passwd_main
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_EmU_1ForgetPassword_reset_1passwd_1main(JNIEnv *env, jobject obj, 
	jstring j_emergency_staff_auth_ip_addr, jstring j_username, jboolean j_is_admin_flag, jstring j_resetting_code)
{
	const char *emergency_staff_auth_ip_addr;
	const char *username;
	boolean    is_admin_flag;
	const char *resetting_code;

	jclass     cls;
	boolean    resetting_flag;

	// Get variables from Java
	emergency_staff_auth_ip_addr = (*env)->GetStringUTFChars(env, j_emergency_staff_auth_ip_addr, 0);
	username                     = (*env)->GetStringUTFChars(env, j_username, 0);
	is_admin_flag                = (boolean)j_is_admin_flag;
	resetting_code               = (*env)->GetStringUTFChars(env, j_resetting_code, 0);

	Java_env    = env;
  	Java_object = obj;

	// Get the method ids for returning output to Java
	cls = (*env)->GetObjectClass(env, obj);

	Java_backend_alert_msg_callback_handler_id = (*env)->GetMethodID(env, cls, "backend_alert_msg_callback_handler", "(Ljava/lang/String;)V");
	if(Java_backend_alert_msg_callback_handler_id == 0)
		int_error("Could not find method \"backend_alert_msg_callback_handler\"");

	// Reset password
	resetting_flag = reset_emu_passwd((char *)emergency_staff_auth_ip_addr, (char *)username, is_admin_flag, (char *)resetting_code, backend_alert_msg_callback_handler);

	// Free up the Java string arguments
	(*env)->ReleaseStringUTFChars(env, j_emergency_staff_auth_ip_addr, emergency_staff_auth_ip_addr);
	(*env)->ReleaseStringUTFChars(env, j_username, username);
	(*env)->ReleaseStringUTFChars(env, j_resetting_code, resetting_code);

	return resetting_flag;
}



