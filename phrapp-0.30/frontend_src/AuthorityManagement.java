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

class AuthorityManagement extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1313582265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean register_authority_main(String authority_name, String ip_address);
	private native boolean edit_authority_ip_address_main(String authority_name, String ip_address);

	// Variables
	private JPanel     main_panel                 = new JPanel();

	private JTextField authority_name_textfield   = new JTextField(TEXTFIELD_LENGTH);
	private JTextField ip_address_textfield       = new JTextField(TEXTFIELD_LENGTH);

	private JButton    submit_button;
	private JButton    cancel_button              = new JButton("Cancel");

	private boolean    is_registration_mode_flag;     // Registration or editing mode

	// This for editing mode only
	private String     current_ip_address;

	// Return variable
	private boolean    result_flag;
	private String	   result_msg;

	// WEB
	private String		m_authority_name;
	private String 	    m_ip_address;

	public AuthorityManagement(Component parent)       // Registration mode
	{
		result_flag               = false;
		is_registration_mode_flag = true;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent);
		setup_actions();
	}

	// WEB
	public AuthorityManagement()       // Registration mode
	{
		result_flag               = false;
		is_registration_mode_flag = true;
		result_msg 				  = "";
		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
	}


	public AuthorityManagement(Component parent, String authority_name, String current_ip_address)       // Editing mode
	{
		result_flag                = false;
		is_registration_mode_flag  = false;
		this.current_ip_address    = current_ip_address;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent);
		init_textfields(authority_name, current_ip_address);
		setup_actions();
	}

	// WEB 

	public AuthorityManagement(String authority_name, String current_ip_address)       // Editing mode
	{
		result_flag                = false;
		is_registration_mode_flag  = false;
		this.current_ip_address    = current_ip_address;
		m_authority_name		   = authority_name;
		result_msg 				   = "";

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		JLabel ip_address_label     = new JLabel("IP address: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(authority_name_label);
		upper_inner_panel.add(authority_name_textfield);
		upper_inner_panel.add(ip_address_label);
		upper_inner_panel.add(ip_address_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 80));
		upper_outer_panel.setMaximumSize(new Dimension(400, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Buttons
		submit_button = (is_registration_mode_flag) ? new JButton("Register") : new JButton("Edit");
		submit_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(400, 30));
		buttons_panel.setMaximumSize(new Dimension(400, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(submit_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(upper_outer_panel);
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		if(is_registration_mode_flag)
			setTitle("Authority Registration");
		else
			setTitle("Authority Editing");

		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private final void setup_actions()
	{
		// Submit button
		submit_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						submit_button.setEnabled(false);
						cancel_button.setEnabled(false);

						String authority_name = authority_name_textfield.getText();
						String ip_address     = ip_address_textfield.getText();

						if(is_registration_mode_flag && validate_input_registration_mode())
						{
							// Call to C function
							if(register_authority_main(authority_name, ip_address))
							{
								result_flag = true;
		        					dispose();
							}
						}
						else if(!is_registration_mode_flag && validate_input_editing_mode())
						{
							// Call to C function
							if(edit_authority_ip_address_main(authority_name, ip_address))
							{
								result_flag = true;
		        					dispose();
							}
						}

						submit_button.setEnabled(true);
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
						submit_button.setEnabled(false);
						cancel_button.setEnabled(false);
		        			dispose();
					}
				});
		    	}
		});
	}

	// WEB
	public void authorityManagement(String authority_name, String ip_address){

		m_authority_name = authority_name;
		m_ip_address	 = ip_address;

		System.out.println(m_ip_address);

		if(is_registration_mode_flag && validate_input_registration_mode())
		{
							// Call to C function
			if(register_authority_main(authority_name, ip_address))
			{
				result_flag = true;
				result_msg = "Register Authority Success";
			}
		}
		else if(!is_registration_mode_flag && validate_input_editing_mode())
		{
			// Call to C function
			if(edit_authority_ip_address_main(authority_name, ip_address))
			{
				result_flag = true;
		        result_msg = "Edit Authority Success";
			}
		}
	}

	private void init_textfields(String authority_name, String ip_address)
	{
		authority_name_textfield.setText(authority_name);
		authority_name_textfield.setEnabled(false);

		ip_address_textfield.setText(ip_address);
	}

	private boolean validate_input_registration_mode()
	{
		Pattern p;
		Matcher m;

		// Validate authority name
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		// m = p.matcher(new String(authority_name_textfield.getText()));
		m = p.matcher(m_authority_name);
		if(!m.matches())
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the authority name");
			result_msg = "Please input correct format for the authority name";
			return false;
		}

		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		// m = p.matcher(new String(ip_address_textfield.getText()));
		m = p.matcher(m_ip_address);
		if(!m.matches())
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			result_msg = "Please input correct format for the IP address";
			return false;
		}

		return true;
	}

	private boolean validate_input_editing_mode()
	{
		Pattern p;
		Matcher m;
		String  ip_address = m_ip_address;
		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(ip_address);
		if(!m.matches())
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			result_msg = "Please input correct format for the IP address";
			return false;
		}

		// Check update
		if(ip_address.equals(current_ip_address))
		{
			// JOptionPane.showMessageDialog(this, "No any update");
			result_msg = "No any update";
			return false;
		}

		return true;
	}

	public boolean get_result()
	{
		return result_flag;
	}

	// WEB

	public boolean getResultFlag()
	{
		return result_flag;
	}

	public String getResultMsg()
	{
		return result_msg;
	}

	public String getAuthorityName()
	{
		return m_authority_name;
	}

	public String getCurrentIP()
	{
		return current_ip_address;
	}


	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		// JOptionPane.showMessageDialog(main_panel, alert_msg);
		if(alert_msg.equals("Sending an e-mail failed (SSL connect error)"))
			result_flag = true;
		result_msg = alert_msg;
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



