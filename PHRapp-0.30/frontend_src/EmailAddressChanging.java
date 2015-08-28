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
	private String         current_passwd;

	// Return variable
	private boolean        result_flag;

	public EmailAddressChanging(Component parent, boolean is_admin_flag, String current_email_address, String current_passwd)
	{
		result_flag                = false;
		this.is_admin_flag         = is_admin_flag;
		this.current_email_address = current_email_address;
		this.current_passwd        = current_passwd;

		init_ui(parent);
		init_email_address_textfield(current_email_address);
		setup_actions();
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel email_address_label = new JLabel("E-mail address: ", JLabel.RIGHT);
		JLabel passwd_label        = new JLabel((is_admin_flag) ? "Admin's password: " : "User's passwd: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(email_address_label);
		upper_inner_panel.add(email_address_textfield);
		upper_inner_panel.add(passwd_label);
		upper_inner_panel.add(passwd_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 80));
		upper_outer_panel.setMaximumSize(new Dimension(400, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Buttons
		change_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(400, 30));
		buttons_panel.setMaximumSize(new Dimension(400, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(change_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(upper_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		setTitle("E-mail Address Changing");
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private final void setup_actions()
	{
		// Change button
		change_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						change_button.setEnabled(false);
						cancel_button.setEnabled(false);

						if(validate_input())
						{
							String email_address = email_address_textfield.getText();

							// Call to C function
							if(is_admin_flag && change_admin_email_address_main(email_address))
							{
								result_flag = true;
								dispose();
							}
							else if(!is_admin_flag && change_user_email_address_main(email_address))
							{
								result_flag = true;
								dispose();
							}
						}

						change_button.setEnabled(true);
						cancel_button.setEnabled(true);
		    			}
				});
			}
		});

		// Cancel button
		cancel_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						change_button.setEnabled(false);
						cancel_button.setEnabled(false);
		        			dispose();
					}
				});
		    	}
		});
	}

	private void init_email_address_textfield(String email_address)
	{
		email_address_textfield.setText(email_address);
	}

	private boolean validate_input()
	{
		Pattern p;
		Matcher m;
		String  email_address = email_address_textfield.getText();
		String  passwd        = new String(passwd_textfield.getPassword());

		// Validate e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(email_address);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the e-mail address");
			return false;
		}

		// Validate passwd
		if(!(passwd.length() >= PASSWD_LENGTH_LOWER_BOUND && passwd.length() <= PASSWD_LENGTH_UPPER_BOUND))
		{
			JOptionPane.showMessageDialog(this, "Please input the password's length between " + 
				PASSWD_LENGTH_LOWER_BOUND + " and " + PASSWD_LENGTH_UPPER_BOUND + " characters");

			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(passwd);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the password");
			return false;
		}

		// Do a password match with a current password?
		if(!passwd.equals(current_passwd))
		{
			JOptionPane.showMessageDialog(this, "Invalid the password");
			return false;
		}

		// Check update
		if(email_address.equals(current_email_address))
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



