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

class EmU_ForgetPassword extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1233582265863921754L;

	// Declaration of the Native C functions
	private native boolean load_emergency_staff_authority_pub_key_main(String emergency_staff_auth_ip_addr);
	private native boolean request_passwd_resetting_code_main(String emergency_staff_auth_ip_addr, String username, boolean is_admin_flag);
	private native boolean reset_passwd_main(String emergency_staff_auth_ip_addr, String username, boolean is_admin_flag, String resetting_code);

	// Variables
	private JPanel         main_panel                                               = new JPanel();

	private JButton        request_passwd_resetting_code_main_button                = new JButton("Request a password resetting code");
	private JButton        reset_passwd_main_button                                 = new JButton("Reset a password");

	private Component      parent;

	// Passwd resetting code requesting
	private JTextField     emergency_staff_auth_ip_addr_textfield_code_requesting;
	private JTextField     username_textfield_code_requesting;

	private JRadioButton[] user_type_radio_buttons_code_requesting;
       	private ButtonGroup    user_type_group_code_requesting;
        private final String   user_type_code_requesting                                = new String("User");
        private final String   admin_type_code_requesting                               = new String("Admin");

	private JButton        request_code_button                                      = new JButton("Request a resetting code");
	private JButton        code_requesting_back_button                              = new JButton("Back to main");

	private ActionListener request_code_button_actionlistener;
	private ActionListener code_requesting_back_button_actionlistener;

	// Passwd resetting
	private JTextField     emergency_staff_auth_ip_addr_textfield_passwd_resetting;
	private JTextField     username_textfield_passwd_resetting;
	private JPasswordField resetting_code_textfield_passwd_resetting;

	private JRadioButton[] user_type_radio_buttons_passwd_resetting;
       	private ButtonGroup    user_type_group_passwd_resetting;
        private final String   user_type_passwd_resetting                               = new String("User");
        private final String   admin_type_passwd_resetting                              = new String("Admin");

	private JButton        reset_passwd_button                                      = new JButton("Reset a password");
	private JButton        passwd_resetting_back_button                             = new JButton("Back to main");

	private ActionListener reset_passwd_button_actionlistener;
	private ActionListener passwd_resetting_back_button_actionlistener;

	public EmU_ForgetPassword(Component parent)
	{
		this.parent = parent;

		// Load JNI backend library
		System.loadLibrary("PHRapp_EmU_Login_JNI");
			
		init_ui_main();
		setup_actions_for_main();
		init_actions_for_passwd_resetting_code_requesting();
		init_actions_for_passwd_resetting();
	}

	private final void init_ui_main()
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel notice_msg_label = new JLabel("<html><center>To reset a password, you must request for a password <br>resetting code " + 
			"which will be sent to the user's e-mail address. <br><br>You can reset a password by entering a valid resetting code.</center></html>");

		notice_msg_label.setAlignmentX(0.5f);

		JPanel notice_msg_label_panel = new JPanel();
		notice_msg_label_panel.setPreferredSize(new Dimension(450, 65));
		notice_msg_label_panel.setMaximumSize(new Dimension(450, 65));
		notice_msg_label_panel.setAlignmentX(0.0f);
		notice_msg_label_panel.add(notice_msg_label);

		// Request passwd resetting code main button
		request_passwd_resetting_code_main_button.setAlignmentX(0.5f);

		JPanel request_passwd_resetting_code_main_button_panel = new JPanel();
		request_passwd_resetting_code_main_button_panel.setPreferredSize(new Dimension(450, 30));
		request_passwd_resetting_code_main_button_panel.setMaximumSize(new Dimension(450, 30));
		request_passwd_resetting_code_main_button_panel.setAlignmentX(0.0f);
		request_passwd_resetting_code_main_button_panel.add(request_passwd_resetting_code_main_button);

		// Reset passwd main button
		reset_passwd_main_button.setAlignmentX(0.5f);

		JPanel reset_passwd_main_button_panel = new JPanel();
		reset_passwd_main_button_panel.setPreferredSize(new Dimension(450, 30));
		reset_passwd_main_button_panel.setMaximumSize(new Dimension(450, 30));
		reset_passwd_main_button_panel.setAlignmentX(0.0f);
		reset_passwd_main_button_panel.add(reset_passwd_main_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(20, 20, 20, 20)));

		main_panel.add(notice_msg_label_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		main_panel.add(request_passwd_resetting_code_main_button_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(reset_passwd_main_button_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);

		add(main_panel);

		setTitle("Password Resetting");
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private final void setup_actions_for_main()
	{
		// Request passwd resetting code main button
		request_passwd_resetting_code_main_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						request_passwd_resetting_code_main_button.setEnabled(false);

						init_ui_for_passwd_resetting_code_requesting();
						setup_actions_for_passwd_resetting_code_requesting();

						request_passwd_resetting_code_main_button.setEnabled(true);
		    			}
				});
			}
		});

		// Reset passwd main button
		reset_passwd_main_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						reset_passwd_main_button.setEnabled(false);

						init_ui_for_passwd_resetting();
						setup_actions_for_passwd_resetting();

						reset_passwd_main_button.setEnabled(true);
		    			}
				});
			}
		});
	}

	private final void init_ui_for_passwd_resetting_code_requesting()
	{
		JLabel emergency_staff_auth_ip_addr_label              = new JLabel("IP address: ", JLabel.RIGHT);
		JLabel username_label                                  = new JLabel("Username: ", JLabel.RIGHT);

		emergency_staff_auth_ip_addr_textfield_code_requesting = new JTextField(TEXTFIELD_LENGTH);
		username_textfield_code_requesting                     = new JTextField(TEXTFIELD_LENGTH);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(emergency_staff_auth_ip_addr_label);
		upper_inner_panel.add(emergency_staff_auth_ip_addr_textfield_code_requesting);
		upper_inner_panel.add(username_label);
		upper_inner_panel.add(username_textfield_code_requesting);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(300, 80));
		upper_outer_panel.setMaximumSize(new Dimension(300, 80));
		upper_outer_panel.setAlignmentX(0.5f);
		upper_outer_panel.add(upper_inner_panel);

		// User type
		user_type_radio_buttons_code_requesting = new JRadioButton[2];
        	user_type_radio_buttons_code_requesting[0] = new JRadioButton(user_type_code_requesting);
        	user_type_radio_buttons_code_requesting[0].setActionCommand(user_type_code_requesting);

        	user_type_radio_buttons_code_requesting[1] = new JRadioButton(admin_type_code_requesting);
        	user_type_radio_buttons_code_requesting[1].setActionCommand(admin_type_code_requesting);

		user_type_radio_buttons_code_requesting[0].setSelected(true);
		user_type_group_code_requesting = new ButtonGroup();
            	user_type_group_code_requesting.add(user_type_radio_buttons_code_requesting[0]);
		user_type_group_code_requesting.add(user_type_radio_buttons_code_requesting[1]);

		// User type panel
		JPanel user_type_inner_panel = new JPanel();
		user_type_inner_panel.setLayout(new BoxLayout(user_type_inner_panel, BoxLayout.Y_AXIS));
		user_type_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		user_type_inner_panel.setPreferredSize(new Dimension(120, 70));
		user_type_inner_panel.setMaximumSize(new Dimension(120, 70));
		user_type_inner_panel.setAlignmentX(0.0f);
		user_type_inner_panel.add(user_type_radio_buttons_code_requesting[0]);
		user_type_inner_panel.add(user_type_radio_buttons_code_requesting[1]);

		JPanel user_type_outer_panel = new JPanel(new GridLayout(0, 1));
		user_type_outer_panel.setLayout(new BoxLayout(user_type_outer_panel, BoxLayout.Y_AXIS));
    		user_type_outer_panel.setBorder(BorderFactory.createTitledBorder("User type:"));
		user_type_outer_panel.setAlignmentX(0.5f);
		user_type_outer_panel.add(user_type_inner_panel);

		// Buttons
		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(350, 30));
		buttons_panel.setMaximumSize(new Dimension(350, 30));
		buttons_panel.setAlignmentX(0.5f);
		buttons_panel.add(request_code_button);
		buttons_panel.add(code_requesting_back_button);

		// Main panel
		main_panel.removeAll();
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 20, 20, 20)));
		main_panel.add(upper_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(user_type_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);
		main_panel.revalidate();
		main_panel.repaint();

		// Set focus
		emergency_staff_auth_ip_addr_textfield_code_requesting.requestFocus(true);

		setTitle("Password Resetting Code Requesting");
		pack();
		setLocationRelativeTo(parent);
	}

	private final void uninit_ui_for_passwd_resetting_code_requesting()
	{
		main_panel.removeAll();
		main_panel.revalidate();
		main_panel.repaint();
	}

	private void init_actions_for_passwd_resetting_code_requesting()
	{
		// Request code button
		request_code_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						request_code_button.setEnabled(false);

						if(validate_passwd_resetting_code_requesting_input())
						{
							String emergency_staff_auth_ip_addr = emergency_staff_auth_ip_addr_textfield_code_requesting.getText();
							String username                     = username_textfield_code_requesting.getText();
							String user_type                    = user_type_group_code_requesting.getSelection().getActionCommand();

							// Check for existence of an emergency staff authority's public key if it does not exist then load it
							if(!load_emergency_staff_authority_pub_key_main(emergency_staff_auth_ip_addr))  // Call to backend (C function)
							{
								request_code_button.setEnabled(true);
								return;
							}

							if(user_type.equals(user_type_code_requesting))
							{
								// Call to backend (C function)
								if(request_passwd_resetting_code_main(emergency_staff_auth_ip_addr, username, false))
								{
									uninit_ui_for_passwd_resetting_code_requesting();
									release_actions_for_passwd_resetting_code_requesting();

									init_ui_for_passwd_resetting();
									setup_actions_for_passwd_resetting();
									pre_init_passwd_resetting_input(emergency_staff_auth_ip_addr, username, false);

									JOptionPane.showMessageDialog(main_panel, "The password resetting code is sent to the user's " + 
										"e-mail address.\nYou can reset a password by entering a valid resetting code.");
								}
							}
							else if(user_type.equals(admin_type_code_requesting))
							{
								// Call to backend (C function)
								if(request_passwd_resetting_code_main(emergency_staff_auth_ip_addr, username, true))
								{
									uninit_ui_for_passwd_resetting_code_requesting();
									release_actions_for_passwd_resetting_code_requesting();

									init_ui_for_passwd_resetting();
									setup_actions_for_passwd_resetting();
									pre_init_passwd_resetting_input(emergency_staff_auth_ip_addr, username, true);

									JOptionPane.showMessageDialog(main_panel, "The password resetting code is sent to the user's " + 
										"e-mail address.\nYou can reset a password by entering a valid resetting code.");
								}
							}
						}

						request_code_button.setEnabled(true);
		    			}
				});
			}
		};

		// Code requesting back button
		code_requesting_back_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						code_requesting_back_button.setEnabled(false);

						uninit_ui_for_passwd_resetting_code_requesting();
						release_actions_for_passwd_resetting_code_requesting();
						init_ui_main();

						code_requesting_back_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private final void setup_actions_for_passwd_resetting_code_requesting()
	{
		// Request code button
		request_code_button.addActionListener(request_code_button_actionlistener);

		// Code requesting back button
		code_requesting_back_button.addActionListener(code_requesting_back_button_actionlistener);
	}

	private final void release_actions_for_passwd_resetting_code_requesting()
	{
		// Request code button
		request_code_button.removeActionListener(request_code_button_actionlistener);

		// Code requesting back button
		code_requesting_back_button.removeActionListener(code_requesting_back_button_actionlistener);
	}

	private boolean validate_passwd_resetting_code_requesting_input()
	{
		Pattern p;
		Matcher m;

		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(emergency_staff_auth_ip_addr_textfield_code_requesting.getText());
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			return false;
		}

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username_textfield_code_requesting.getText());
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			return false;
		}
		
		return true;	
	}

	private void pre_init_passwd_resetting_input(String assigned_emergency_staff_auth_ip_addr, String assigned_username, boolean is_admin_flag)
	{
		emergency_staff_auth_ip_addr_textfield_passwd_resetting.setText(assigned_emergency_staff_auth_ip_addr);
		emergency_staff_auth_ip_addr_textfield_passwd_resetting.setEnabled(false);

		username_textfield_passwd_resetting.setText(assigned_username);
		username_textfield_passwd_resetting.setEnabled(false);

		// Set focus
		resetting_code_textfield_passwd_resetting.requestFocus(true);

		if(is_admin_flag)
		{
			user_type_radio_buttons_passwd_resetting[0].setSelected(false);
			user_type_radio_buttons_passwd_resetting[1].setSelected(true);
		}
		else
		{
			user_type_radio_buttons_passwd_resetting[0].setSelected(true);
			user_type_radio_buttons_passwd_resetting[1].setSelected(false);
		}

		user_type_radio_buttons_passwd_resetting[0].setEnabled(false);
		user_type_radio_buttons_passwd_resetting[1].setEnabled(false);
	}

	private final void init_ui_for_passwd_resetting()
	{
		JLabel emergency_staff_auth_ip_addr_label               = new JLabel("IP address: ", JLabel.RIGHT);
		JLabel username_label                                   = new JLabel("Username: ", JLabel.RIGHT);
		JLabel resetting_code_label                             = new JLabel("Resetting code: ", JLabel.RIGHT);

		emergency_staff_auth_ip_addr_textfield_passwd_resetting = new JTextField(TEXTFIELD_LENGTH);
		username_textfield_passwd_resetting                     = new JTextField(TEXTFIELD_LENGTH);
		resetting_code_textfield_passwd_resetting               = new JPasswordField(TEXTFIELD_LENGTH);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(emergency_staff_auth_ip_addr_label);
		upper_inner_panel.add(emergency_staff_auth_ip_addr_textfield_passwd_resetting);
		upper_inner_panel.add(username_label);
		upper_inner_panel.add(username_textfield_passwd_resetting);
		upper_inner_panel.add(resetting_code_label);
		upper_inner_panel.add(resetting_code_textfield_passwd_resetting);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(332, 120));
		upper_outer_panel.setMaximumSize(new Dimension(332, 120));
		upper_outer_panel.setAlignmentX(0.5f);
		upper_outer_panel.add(upper_inner_panel);

		// User type
		user_type_radio_buttons_passwd_resetting = new JRadioButton[2];
        	user_type_radio_buttons_passwd_resetting[0] = new JRadioButton(user_type_passwd_resetting);
        	user_type_radio_buttons_passwd_resetting[0].setActionCommand(user_type_passwd_resetting);

        	user_type_radio_buttons_passwd_resetting[1] = new JRadioButton(admin_type_passwd_resetting);
        	user_type_radio_buttons_passwd_resetting[1].setActionCommand(admin_type_passwd_resetting);

		user_type_radio_buttons_passwd_resetting[0].setSelected(true);
		user_type_group_passwd_resetting = new ButtonGroup();
            	user_type_group_passwd_resetting.add(user_type_radio_buttons_passwd_resetting[0]);
		user_type_group_passwd_resetting.add(user_type_radio_buttons_passwd_resetting[1]);

		// User type panel
		JPanel user_type_inner_panel = new JPanel();
		user_type_inner_panel.setLayout(new BoxLayout(user_type_inner_panel, BoxLayout.Y_AXIS));
		user_type_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		user_type_inner_panel.setPreferredSize(new Dimension(120, 70));
		user_type_inner_panel.setMaximumSize(new Dimension(120, 70));
		user_type_inner_panel.setAlignmentX(0.0f);
		user_type_inner_panel.add(user_type_radio_buttons_passwd_resetting[0]);
		user_type_inner_panel.add(user_type_radio_buttons_passwd_resetting[1]);

		JPanel user_type_outer_panel = new JPanel(new GridLayout(0, 1));
		user_type_outer_panel.setLayout(new BoxLayout(user_type_outer_panel, BoxLayout.Y_AXIS));
    		user_type_outer_panel.setBorder(BorderFactory.createTitledBorder("User type:"));
		user_type_outer_panel.setAlignmentX(0.5f);
		user_type_outer_panel.add(user_type_inner_panel);

		// Buttons
		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(350, 30));
		buttons_panel.setMaximumSize(new Dimension(350, 30));
		buttons_panel.setAlignmentX(0.5f);
		buttons_panel.add(reset_passwd_button);
		buttons_panel.add(passwd_resetting_back_button);

		// Main panel
		main_panel.removeAll();
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 20, 20, 20)));
		main_panel.add(upper_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(user_type_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);
		main_panel.revalidate();
		main_panel.repaint();

		// Set focus
		emergency_staff_auth_ip_addr_textfield_passwd_resetting.requestFocus(true);

		setTitle("Password Resetting");
		pack();
		setLocationRelativeTo(parent);
	}

	private final void uninit_ui_for_passwd_resetting()
	{
		main_panel.removeAll();
		main_panel.revalidate();
		main_panel.repaint();
	}

	private void init_actions_for_passwd_resetting()
	{
		// Reset passwd button
		reset_passwd_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						reset_passwd_button.setEnabled(false);

						if(validate_passwd_resetting_input())
						{
							String emergency_staff_auth_ip_addr = emergency_staff_auth_ip_addr_textfield_passwd_resetting.getText();
							String username                     = username_textfield_passwd_resetting.getText();
							String resetting_code               = new String(resetting_code_textfield_passwd_resetting.getPassword());
							String user_type                    = user_type_group_passwd_resetting.getSelection().getActionCommand();

							// Check for existence of an emergency staff authority's public key if it does not exist then load it
							if(!load_emergency_staff_authority_pub_key_main(emergency_staff_auth_ip_addr))  // Call to backend (C function)
							{
								reset_passwd_button.setEnabled(true);
								return;
							}

							if(user_type.equals(user_type_passwd_resetting))
							{
								// Call to backend (C function)
								if(reset_passwd_main(emergency_staff_auth_ip_addr, username, false, resetting_code))
								{
									JOptionPane.showMessageDialog(main_panel, "The password is sent to your e-mail address already");
									dispose();
								}
							}
							else if(user_type.equals(admin_type_passwd_resetting))
							{
								// Call to backend (C function)
								if(reset_passwd_main(emergency_staff_auth_ip_addr, username, true, resetting_code))
								{
									JOptionPane.showMessageDialog(main_panel, "The password is sent to your e-mail address already");
									dispose();
								}
							}
						}

						reset_passwd_button.setEnabled(true);
		    			}
				});
			}
		};

		// Passwd resetting back button
		passwd_resetting_back_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						passwd_resetting_back_button.setEnabled(false);

						uninit_ui_for_passwd_resetting();
						release_actions_for_passwd_resetting();
						init_ui_main();

						passwd_resetting_back_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private final void setup_actions_for_passwd_resetting()
	{
		// Reset passwd button
		reset_passwd_button.addActionListener(reset_passwd_button_actionlistener);

		// Passwd resetting back button
		passwd_resetting_back_button.addActionListener(passwd_resetting_back_button_actionlistener);
	}

	private final void release_actions_for_passwd_resetting()
	{
		// Reset passwd button
		reset_passwd_button.removeActionListener(reset_passwd_button_actionlistener);

		// Passwd resetting back button
		passwd_resetting_back_button.removeActionListener(passwd_resetting_back_button_actionlistener);
	}

	private boolean validate_passwd_resetting_input()
	{
		Pattern p;
		Matcher m;

		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(emergency_staff_auth_ip_addr_textfield_passwd_resetting.getText());
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			return false;
		}

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username_textfield_passwd_resetting.getText());
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			return false;
		}

		// Validate resetting code
		String resetting_code = new String(resetting_code_textfield_passwd_resetting.getPassword());

		if(resetting_code.length() != PASSWD_RESETTING_CODE_LENGTH)
		{
			JOptionPane.showMessageDialog(this, "The resetting code's length is " + PASSWD_RESETTING_CODE_LENGTH + " characters");
			return false;
		}

		p = Pattern.compile("^[^-]*[a-zA-Z0-9\\_&$%#@*+-/]+");
		m = p.matcher(resetting_code);
		if(m.matches() == false)
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the resetting code");
			return false;
		}

		return true;	
	}

	// Callback method (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		JOptionPane.showMessageDialog(main_panel, alert_msg);
	}
}



