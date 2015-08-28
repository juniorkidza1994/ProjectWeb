import java.lang.*;

// Declare constant variables for using in every classes
public interface ConstantVars
{
	public final int    TEXTFIELD_LENGTH                = 50;

	public final String ROOT_NODE_TYPE                  = "Root node";
	public final String USER_TYPE                       = "User";
	public final String ATTRIBUTE_TYPE                  = "Attribute";

	public final int    LOWER_BOUND_AUDITING_YEAR       = 2013;
	public final int    UPPER_BOUND_AUDITING_YEAR       = 2063;

	public final int    MAX_CONCURRENT_TRANSACTION_LOGS = 10;

	public enum TransactionLogType
	{
	 	USER_LOGIN_LOG, USER_EVENT_LOG, ADMIN_LOGIN_LOG, ADMIN_EVENT_LOG, SYSTEM_LOGIN_LOG, SYSTEM_EVENT_LOG;
	}

	public final int    ENFORCING_RELOGIN_TIME          = 1800;     // second unit

	public final int    PASSWD_LENGTH_LOWER_BOUND       = 8;
	public final int    PASSWD_LENGTH_UPPER_BOUND       = 50;

	public final int    PASSWD_RESETTING_CODE_LENGTH    = 8;

	// PHR confidentiality levels
	public final String PHR_SECURE_LEVEL_FLAG           = "0";
	public final String PHR_RESTRICTED_LEVEL_FLAG	    = "1";
	public final String PHR_EXCLUSIVE_LEVEL_FLAG	    = "2";      // By default

	public final String CACHE_DIRECTORY_NAME            = "Client_cache";
	public final String PTHRESHOLD_PREFIX_NAME          = "pthreshold";
	public final String SERIALIZABLE_OBJ_EXTENSION      = ".ser";

	public final String ENC_THRESHOLD_MSG               = "enc_threshold_msg";

	public final String RESTRICTED_PHR_NO_REQUEST       = "No request";
	public final String RESTRICTED_PHR_REQUEST_PENDING  = "Request pending";
	public final String RESTRICTED_PHR_REQUEST_APPROVED = "Request approved";
}



