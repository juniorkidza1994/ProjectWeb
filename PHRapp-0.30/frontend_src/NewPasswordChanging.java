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

	// Return variable
	private boolean        result_flag;	

	public NewPasswordChanging(Component parent, boolean is_admin_flag, String current_passwd_cmp)
	{
		result_flag             = false;
		this.is_admin_flag      = is_admin_flag;
		this.current_passwd_cmp = current_passwd_cmp;

		init_ui(parent);
		setup_actions();
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel current_passwd_label     = new JLabel("Current password: ", JLabel.RIGHT);
		JLabel new_passwd_label         = new JLabel("New password: ", JLabel.RIGHT);
		JLabel confirm_new_passwd_label = new JLabel("Confirm new password: ", JLabel.RIGHT);

		JPanel passwordfields_inner_panel = new JPanel(new SpringLayout());
		passwordfields_inner_panel.add(current_passwd_label);
		passwordfields_inner_panel.add(current_passwd_textfield);
		passwordfields_inner_panel.add(new_passwd_label);
		passwordfields_inner_panel.add(new_passwd_textfield);
		passwordfields_inner_panel.add(confirm_new_passwd_label);
		passwordfields_inner_panel.add(confirm_new_passwd_textfield);

		SpringUtilities.makeCompactGrid(passwordfields_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel passwordfields_outer_panel = new JPanel();
		passwordfields_outer_panel.setLayout(new BoxLayout(passwordfields_outer_panel, BoxLayout.X_AXIS));
		passwordfields_outer_panel.setPreferredSize(new Dimension(440, 115));
		passwordfields_outer_panel.setMaximumSize(new Dimension(440, 115));
		passwordfields_outer_panel.setAlignmentX(0.0f);
		passwordfields_outer_panel.add(passwordfields_inner_panel);

		// Send new password flag checkbox
        	send_new_passwd_flag_checkbox.setFocusable(false);
		send_new_passwd_flag_checkbox.setAlignmentX(0.0f);

		JPanel send_new_passwd_flag_checkbox_inner_panel = new JPanel();
		send_new_passwd_flag_checkbox_inner_panel.setLayout(new BoxLayout(send_new_passwd_flag_checkbox_inner_panel, BoxLayout.X_AXIS));
		send_new_passwd_flag_checkbox_inner_panel.setPreferredSize(new Dimension(350, 30));
		send_new_passwd_flag_checkbox_inner_panel.setMaximumSize(new Dimension(350, 30));
		send_new_passwd_flag_checkbox_inner_panel.setAlignmentX(0.5f);
		send_new_passwd_flag_checkbox_inner_panel.add(send_new_passwd_flag_checkbox);

		JPanel send_new_passwd_flag_checkbox_outer_panel = new JPanel();
		send_new_passwd_flag_checkbox_outer_panel.setPreferredSize(new Dimension(440, 30));
		send_new_passwd_flag_checkbox_outer_panel.setMaximumSize(new Dimension(440, 30));
		send_new_passwd_flag_checkbox_outer_panel.setAlignmentX(0.0f);
		send_new_passwd_flag_checkbox_outer_panel.add(send_new_passwd_flag_checkbox_inner_panel);

		// Buttons
		change_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(440, 30));
		buttons_panel.setMaximumSize(new Dimension(440, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(change_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(passwordfields_outer_panel);
		main_panel.add(send_new_passwd_flag_checkbox_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		setTitle("New Password Changing");
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
							String  new_passwd           = new String(new_passwd_textfield.getPassword());
							boolean send_new_passwd_flag = send_new_passwd_flag_checkbox.isSelected();

							// Call to C function
							if(is_admin_flag && change_admin_passwd_main(new_passwd, send_new_passwd_flag))
							{
								result_flag = true;
								dispose();
							}
							else if(!is_admin_flag && change_user_passwd_main(new_passwd, send_new_passwd_flag))
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

	private boolean validate_input()
	{
		Pattern p;
		Matcher m;
		String  new_passwd         = new String(new_passwd_textfield.getPassword());
		String  confirm_new_passwd = new String(confirm_new_passwd_textfield.getPassword());
		String  current_passwd     = new String(current_passwd_textfield.getPassword());

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

	public boolean get_result()
	{
		return result_flag;
	}

	public String get_new_passwd()
	{
		return new String(new_passwd_textfield.getPassword());
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



