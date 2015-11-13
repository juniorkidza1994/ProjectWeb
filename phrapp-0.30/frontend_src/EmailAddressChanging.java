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

class EmailAddressChanging extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1433582265865921454L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean change_admin_email_address_main(String email_address);
	private native boolean change_user_email_address_main(String email_address);

	// Variables
	private JPanel         main_panel              = new JPanel();
	private JTextField     email_address_textfield = new JTextField(TEXTFIELD_LENGTH);
	private JPasswordField passwd_textfield        = new JPasswordField(TEXTFIELD_LENGTH);

	private JButton        change_button	       = new JButton("Change");
	private JButton        cancel_button           = new JButton("Cancel");

	private boolean        is_admin_flag;
	private String         current_email_address;
	private String		   new_email_address;
	private String         current_passwd;
	private String		   confirm_passwd;

	// Return variable
	private boolean        result_flag;

	public EmailAddressChanging(Component parent, boolean is_admin_flag, String current_email_address, String current_passwd)
	{
		result_flag                = false;
		this.is_admin_flag         = is_admin_flag;
		this.current_email_address = current_email_address;
		this.current_passwd        = current_passwd;

		// init_ui(parent);
		// init_email_address_textfield(current_email_address);
		// setup_actions();
	}


	public EmailAddressChanging( boolean is_admin_flag, String current_email_address, String current_passwd)
	{
		result_flag                = false;
		this.is_admin_flag         = is_admin_flag;
		this.current_email_address = current_email_address;
		this.current_passwd        = current_passwd;
	}

	public String getCurrentEmail(){
		return current_email_address;
	}

	public final void change_email(String new_email_address, String confirm_passwd)
	{
		this.confirm_passwd = confirm_passwd;
		this.new_email_address = new_email_address;
		if(validate_input())
			{
							// Call to C function
			if(is_admin_flag && change_admin_email_address_main(new_email_address))
			{
				result_flag = true;
			}
			else if(!is_admin_flag && change_user_email_address_main(new_email_address))
			{
				System.out.println("CHANGE EMAIL SUCCESSFULL");
				result_flag = true;
			}
		}
	}

	private boolean validate_input()
	{
		Pattern p;
		Matcher m;
		// Validate e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(new_email_address);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the e-mail address");
			return false;
		}

		// Validate passwd
		if(!(confirm_passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && confirm_passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			JOptionPane.showMessageDialog(this, "Please input the password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(confirm_passwd);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the password");
			return false;
		}

		// Do a password match with a current password?
		if(!confirm_passwd.equals(current_passwd))
		{
			JOptionPane.showMessageDialog(this, "Invalid the password");
			return false;
		}

		// Check update
		if(new_email_address.equals(current_email_address))
		{
			JOptionPane.showMessageDialog(this, "No any update");
			return false;
		}

		return true;
	}

	public boolean get_result()
	{
		return result_flag;
	}

	public String get_email_address()
	{
		return email_address_textfield.getText();
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
}



