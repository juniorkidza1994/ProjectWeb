import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.lang.*;
import java.util.regex.*;
import javax.swing.border.*;

import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.*;

public class Login extends JFrame  implements ConstantVars
{
	private static final long serialVersionUID = -1113582265865921787L;

	// Declaration of the Native C functions
	private native void init_backend();
	private native void uninit_backend();
	private native boolean load_user_authority_pub_key_main(String user_auth_ip_addr);
	private native boolean user_login_main(String user_auth_ip_addr, String username, String passwd);
	private native boolean admin_login_main(String user_auth_ip_addr, String username, String passwd);

	// Variables
//	private JPanel         main_panel                  = new JPanel();
	private ReentrantLock  working_lock                = new ReentrantLock();

//	private JTextField     user_auth_ip_addr_textfield = new JTextField(TEXTFIELD_LENGTH);
//	private JTextField     username_textfield          = new JTextField(TEXTFIELD_LENGTH);
//	private JPasswordField passwd_textfield            = new JPasswordField(TEXTFIELD_LENGTH);

//	private JRadioButton[] user_type_radio_buttons     = new JRadioButton[2];
//  private ButtonGroup    user_type_group             = new ButtonGroup();
    private final String   login_as_user               = new String("User");
    private final String   login_as_admin              = new String("Admin");

//	private JButton        login_button                = new JButton("Login");
//	private JButton        forget_passwd_button        = new JButton("Forget a password?");

	// Return from backend
	private String         email_address;
	private String         authority_name;
	private String         audit_server_ip_addr;
	private String         phr_server_ip_addr;
	private String         emergency_server_ip_addr;
	private String         mail_server_url;
	private String         authority_email_address;
	private String         authority_email_passwd;
	private String         ssl_cert_hash;
	private String         cpabe_priv_key_hash;

	private Object 		   main_class;
	private String		   m_result_msg;

	public Login()
	{
		super("PHR system: Login Authentication");
		
		// Load JNI backend library
		System.loadLibrary("PHRapp_Login_JNI");

//		working_lock.lock();

		// Call to C function
		init_backend();
		main_class = null;
		m_result_msg = "";
	//	init_ui();
	//	login_main("127.0.0.1","admin","bright23","Admin");

//		working_lock.unlock();
	}

	public boolean login(String user_auth_ip_addr, String username, String passwd, String user_type)
	{
				boolean result = false;

				System.out.println("USER IP : " + user_auth_ip_addr);
				System.out.println("username : " + username);
				System.out.println("passwd : " + passwd);
				System.out.println("user_type : " + user_type);


				// Validate User Authority's IP address, username and password
				if(!validate_inputs(user_auth_ip_addr, username, passwd))
				{
					return result;
				}

				// Check for existence of a user authority's public key if it does not exist then load it
				if(!load_user_authority_pub_key_main(user_auth_ip_addr))  // Call to backend (C function)
				{
					System.out.println("SAD");
					return result;
				}

				if(user_type.equals(login_as_user))
				{  
					// Call to backend (C function)
					if(user_login_main(user_auth_ip_addr, username, passwd))
					{

						System.out.println("LOGIN SUCCESSFULL !!!!!");
						m_result_msg = "LOGIN SUCCESSFULL !!!!!";

						System.out.println("Create User Class !!!!!");

						long startTime = System.currentTimeMillis();
							
						// Call UserMain object
						UserMain user_main = new UserMain(username, passwd, email_address, authority_name, user_auth_ip_addr, 
							audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr, ssl_cert_hash, cpabe_priv_key_hash);

				//		user_main.setVisible(true);
						
						main_class = user_main;
						
						result = true;

						long stopTime = System.currentTimeMillis();

						long elapsedTime = stopTime - startTime;

						System.out.println("TIME LOGIN : " + elapsedTime);
					}
					else
					{
						main_class = null;
						result = false;
						System.out.println("Can't login User");
					}
				}
				else if(user_type.equals(login_as_admin))
				{  
					// Call to backend (C function)
					if(admin_login_main(user_auth_ip_addr, username, passwd))
					{

						System.out.println("LOGIN SUCCESSFULL !!!!!");
						m_result_msg = "LOGIN SUCCESSFULL !!!!!";

						System.out.println("Create Admin Class !!!!!");
						
						long startTime = System.currentTimeMillis();

						// Call AdminMain object
						AdminMain admin_main = new AdminMain(username, passwd, email_address, authority_name, user_auth_ip_addr, 
							audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr, mail_server_url, 
							authority_email_address, authority_email_passwd, ssl_cert_hash);
						
						long stopTime = System.currentTimeMillis();
						
						long elapsedTime = stopTime - startTime;

						System.out.println("TIME LOGIN : " + elapsedTime);
						
						main_class = admin_main;
						
						result = true;
					}
					else
					{
						main_class = null;
						System.out.println("Can't login Admin");
						result = false;
		//				user_auth_ip_addr_textfield.requestFocus();
					}
				}

				return result;
	}

	public Object getMainClass(){
		return main_class;
	}

	public String getResultMsg(){
		return m_result_msg;
	}

	private ForgetPassword forget_password_dialog;

	public Object getForgetPasswordClass(){
		if(forget_password_dialog == null)
			forget_password_dialog = new ForgetPassword();
		return forget_password_dialog;
	}

	private boolean validate_inputs(String user_auth_ip_addr, String username, String passwd)
	{
		Pattern p;
		Matcher m;

		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(user_auth_ip_addr);
		if(m.matches() == false)
		{
//			JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			m_result_msg = "Please input correct format for the IP address";
			return false;
		}

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username);
		if(m.matches() == false)
		{
//			JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			m_result_msg = "Please input correct format for the username";
			return false;
		}
		
		// Validate passwd
		if(!(passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
//			JOptionPane.showMessageDialog(this, "Please input the password's length between " + 
//				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");
			m_result_msg = "Please input the password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters";

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(passwd);
		if(m.matches() == false)
		{
//			JOptionPane.showMessageDialog(this, "Please input correct format for the password");
			m_result_msg = "Please input correct format for the password";
			return false;
		}

		return true;
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
//		JOptionPane.showMessageDialog(main_panel, alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Call to C function
		uninit_backend();

		// Notify alert message to user and then terminate the application
//		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}

	private synchronized void basic_info_ret_callback_handler(String email_address, String authority_name, 
		String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr)
	{
		this.email_address            = email_address;
		this.authority_name           = authority_name;
		this.audit_server_ip_addr     = audit_server_ip_addr;
		this.phr_server_ip_addr       = phr_server_ip_addr;
		this.emergency_server_ip_addr = emergency_server_ip_addr;
	}

	// This method is called only if the user is an admin
	private synchronized void mail_server_configuration_ret_callback_handler(String mail_server_url, String authority_email_address, String authority_email_passwd)
	{
		this.mail_server_url         = mail_server_url;
		this.authority_email_address = authority_email_address;
		this.authority_email_passwd  = authority_email_passwd;
	}

	private synchronized void ssl_cert_hash_ret_callback_handler(String ssl_cert_hash)
	{
		this.ssl_cert_hash = ssl_cert_hash;
	}
	
	// This method is called only if the user is nornal user
	private synchronized void cpabe_priv_key_hash_ret_callback_handler(String cpabe_priv_key_hash)
	{
		this.cpabe_priv_key_hash = cpabe_priv_key_hash;
	}

	// Main method
	public static void main(String[] args)
	{
//		System.out.println("TEST");
//		Login login_gui = new Login();
//		System.out.println("CREATE new class");
		
//		login_gui.login_main("127.0.0.1","admin","bright23","Admin");
		
//		System.out.println("END PROGRAM");
		
		/*SwingUtilities.invokeLater(new Runnable()
		{
            		public void run()
			{
				Login login_gui = new Login();
	//			login_gui.setVisible(true);
            		}
        	});*/
	}
}