import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import java.util.regex.*;
import javax.swing.border.*;

import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.*;

import org.jdesktop.swingx.*;
import org.jdesktop.swingx.treetable.*;

import org.apache.commons.lang3.*;

class NewPasswordChanging extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1433582265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean change_admin_passwd_main(String new_passwd, boolean send_new_passwd_flag);
	private native boolean change_user_passwd_main(String new_passwd, boolean send_new_passwd_flag);

	// Variables
	private JPanel         main_panel                    = new JPanel();
	private JPasswordField current_passwd_textfield      = new JPasswordField(TEXTFIELD_LENGTH);
	private JPasswordField new_passwd_textfield          = new JPasswordField(TEXTFIELD_LENGTH);
	private JPasswordField confirm_new_passwd_textfield  = new JPasswordField(TEXTFIELD_LENGTH);

	private JCheckBox      send_new_passwd_flag_checkbox = new JCheckBox("Send the new password to an e-mail address?", true);

	private JButton        change_button		     = new JButton("Change");
	private JButton        cancel_button                 = new JButton("Cancel");

	private boolean        is_admin_flag;
	private String         current_passwd_cmp;

	private String  	   new_passwd;
	private	String  	   confirm_new_passwd;
	private	String  	   current_passwd;
	private boolean 	   result_flag;

	// Return variable
	private boolean        m_result_flag;	

	public NewPasswordChanging(Component parent, boolean is_admin_flag, String current_passwd_cmp)
	{

		m_result_flag             = false;
		result_flag 			= false;
		this.is_admin_flag      = is_admin_flag;
		this.current_passwd_cmp = current_passwd_cmp;

	}

	private boolean validate_input()
	{
		Pattern p;
		Matcher m;

		// Validate current passwd
		if(!(current_passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && current_passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			JOptionPane.showMessageDialog(this, "Please input the current password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(current_passwd);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the current password");
			return false;
		}

		// Validate new passwd
		if(!(new_passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && new_passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			JOptionPane.showMessageDialog(this, "Please input the new password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(new_passwd);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the new password");
			return false;
		}

		// Validate confirm new passwd
		if(!(confirm_new_passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && confirm_new_passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			JOptionPane.showMessageDialog(this, "Please input the confirm new password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(confirm_new_passwd);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the confirm new password");
			return false;
		}

		// Do a new password and a confirm new password match?
		if(!new_passwd.equals(confirm_new_passwd))
		{
			JOptionPane.showMessageDialog(this, "The new password and confirm new password do not match");
			return false;
		}

		// Do an current password match a compared current password?
		if(!current_passwd.equals(current_passwd_cmp))
		{
			JOptionPane.showMessageDialog(this, "Invalid the current password");
			return false;
		}

		// Check update
		if(current_passwd.equals(new_passwd))
		{
			JOptionPane.showMessageDialog(this, "No any update");
			return false;
		}

		return true;
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		JOptionPane.showMessageDialog(main_panel, alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Call to C function
		uninit_backend();

		// Notify alert message to user and then terminate the application
		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}

	// WEB FUNCION
	public boolean get_result()
	{
		return result_flag;
	}

	public String get_new_passwd()
	{
		return new String(new_passwd_textfield.getPassword());
	}

	public void change_passwd(String  current_passwd,  String new_passwd, String  confirm_new_passwd, Boolean send_new_passwd_flag)
	{
		this.current_passwd = current_passwd;
		this.new_passwd = new_passwd;
		this.confirm_new_passwd = confirm_new_passwd;

		System.out.println("FROM CLASS");
		System.out.println("CURRENT PASSWORD : " + this.current_passwd);
		System.out.println("NEW PASSWORD : " + this.new_passwd);
		System.out.println("CONFIRM PASSWORD : " + this.confirm_new_passwd);

		if(validate_input())
		{

			// Call to C function
			if(is_admin_flag && change_admin_passwd_main(new_passwd, send_new_passwd_flag.booleanValue()))
			{
				m_result_flag = true;
				result_flag   = true;
			}
			else if(!is_admin_flag && change_user_passwd_main(new_passwd, send_new_passwd_flag.booleanValue()))
			{
				System.out.println("CHANGE PASS SUCCESS!!");
				m_result_flag = true;
				result_flag   = true;
			}
		}
	}

	public boolean getResulFlag()
	{
		return m_result_flag;
	}
}



