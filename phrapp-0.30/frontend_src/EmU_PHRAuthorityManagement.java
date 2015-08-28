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

class EmU_PHRAuthorityManagement extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1513582265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean register_phr_authority_main(String phr_authority_name, String ip_address);
	private native boolean edit_phr_authority_ip_address_main(String phr_authority_name, String ip_address);

	// Variables
	private JPanel     main_panel                   = new JPanel();

	private JTextField phr_authority_name_textfield = new JTextField(TEXTFIELD_LENGTH);
	private JTextField ip_address_textfield         = new JTextField(TEXTFIELD_LENGTH);

	private JButton    submit_button;
	private JButton    cancel_button                = new JButton("Cancel");

	private boolean    is_registration_mode_flag;     // Registration or editing mode

	// This for editing mode only
	private String     current_ip_address;

	// Return variable
	private boolean    result_flag;

	public EmU_PHRAuthorityManagement(Component parent)       // Registration mode
	{
		result_flag               = false;
		is_registration_mode_flag = true;

		// Load JNI backend library
		System.loadLibrary("PHRapp_EmU_Admin_JNI");
			
		init_ui(parent);
		setup_actions();
	}

	public EmU_PHRAuthorityManagement(Component parent, String phr_authority_name, String current_ip_address)       // Editing mode
	{
		result_flag                = false;
		is_registration_mode_flag  = false;
		this.current_ip_address    = current_ip_address;

		// Load JNI backend library
		System.loadLibrary("PHRapp_EmU_Admin_JNI");
			
		init_ui(parent);
		init_textfields(phr_authority_name, current_ip_address);
		setup_actions();
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel phr_authority_name_label = new JLabel("PHR authority name: ", JLabel.RIGHT);
		JLabel ip_address_label         = new JLabel("IP address: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(phr_authority_name_label);
		upper_inner_panel.add(phr_authority_name_textfield);
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
			setTitle("PHR Authority Registration");
		else
			setTitle("PHR Authority Editing");

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

						String phr_authority_name = phr_authority_name_textfield.getText();
						String ip_address         = ip_address_textfield.getText();

						if(is_registration_mode_flag && validate_input_registration_mode())
						{
							// Call to C function
							if(register_phr_authority_main(phr_authority_name, ip_address))
							{
								result_flag = true;
		        					dispose();
							}
						}
						else if(!is_registration_mode_flag && validate_input_editing_mode())
						{
							// Call to C function
							if(edit_phr_authority_ip_address_main(phr_authority_name, ip_address))
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

	private void init_textfields(String phr_authority_name, String ip_address)
	{
		phr_authority_name_textfield.setText(phr_authority_name);
		phr_authority_name_textfield.setEnabled(false);

		ip_address_textfield.setText(ip_address);
	}

	private boolean validate_input_registration_mode()
	{
		Pattern p;
		Matcher m;

		// Validate authority name
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(new String(phr_authority_name_textfield.getText()));
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the PHR authority name");
			return false;
		}

		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(new String(ip_address_textfield.getText()));
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			return false;
		}

		return true;
	}

	private boolean validate_input_editing_mode()
	{
		Pattern p;
		Matcher m;
		String  ip_address = ip_address_textfield.getText();

		// Validate IP address
		p = Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");

		m = p.matcher(new String(ip_address_textfield.getText()));
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the IP address");
			return false;
		}

		// Check update
		if(ip_address.equals(current_ip_address))
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



