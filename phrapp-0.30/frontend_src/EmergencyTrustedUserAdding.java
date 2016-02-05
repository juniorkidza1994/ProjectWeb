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

class EmergencyTrustedUserAdding extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1113582265865901754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean add_emergency_trusted_user_main(String desired_trusted_user_authority_name, String desired_trusted_username);

	// Variables
	private JPanel            main_panel                   = new JPanel();

	private JComboBox         authority_name_combobox      = new JComboBox();
	private JTextField        username_textfield           = new JTextField(TEXTFIELD_LENGTH);

	private JButton           add_button                   = new JButton("Add");
	private JButton           cancel_button                = new JButton("Cancel");

	private String            phr_owner_authority_name;
	private String            phr_owner_name;
	private ArrayList<String> authority_name_list;

	// Return variable
	private boolean           result_flag;
	private String			  m_result_msg;

	public EmergencyTrustedUserAdding(Component parent, String phr_owner_authority_name, String phr_owner_name, ArrayList<String> authority_name_list)
	{
		result_flag                   = false;
		this.phr_owner_authority_name = phr_owner_authority_name;
		this.phr_owner_name           = phr_owner_name;
		this.authority_name_list      = authority_name_list;

		// Load JNI backend library
		System.loadLibrary("PHRapp_User_JNI");
			
		init_ui(parent);
		init_authority_name_combobox(authority_name_list);
		setup_actions();
	}

	// USE IN WEB

	public EmergencyTrustedUserAdding(String phr_owner_authority_name, String phr_owner_name, ArrayList<String> authority_name_list)
	{
		result_flag                   = false;
		this.phr_owner_authority_name = phr_owner_authority_name;
		this.phr_owner_name           = phr_owner_name;
		this.authority_name_list      = authority_name_list;

		// Load JNI backend library
		System.loadLibrary("PHRapp_User_JNI");
	}

	public void addUser(Integer  index, String  username ){


		System.out.println("ADD TURSTED USERS FUNCTION IN JAVA");

		if(validate_input_web_mode(index.intValue(), username)){
			String  authority_name = authority_name_list.get(index);
			// Call to C function
			if(add_emergency_trusted_user_main(authority_name, username))
			{
				result_flag = true;
				m_result_msg = "Add trusted user success !!";
			}
			else {
				result_flag = false;		
			}
		}
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		// Authority name
		JLabel authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);

		authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		authority_name_combobox.setMaximumSize(new Dimension(60, 25));

		// Username
		JLabel username_label = new JLabel("Username: ", JLabel.RIGHT);

		JPanel user_inner_panel = new JPanel(new SpringLayout());
		user_inner_panel.add(authority_name_label);
		user_inner_panel.add(authority_name_combobox);
		user_inner_panel.add(username_label);
		user_inner_panel.add(username_textfield);

		SpringUtilities.makeCompactGrid(user_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel user_outer_panel = new JPanel();
		user_outer_panel.setLayout(new BoxLayout(user_outer_panel, BoxLayout.X_AXIS));
		user_outer_panel.setPreferredSize(new Dimension(400, 80));
		user_outer_panel.setMaximumSize(new Dimension(400, 80));
		user_outer_panel.setAlignmentX(0.0f);
		user_outer_panel.add(user_inner_panel);

		// Buttons
		add_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(400, 30));
		buttons_panel.setMaximumSize(new Dimension(400, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(add_button);
		buttons_panel.add(cancel_button);		

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(user_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);		

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		setTitle("Emergency Trusted User Adding");

		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private final void setup_actions()
	{
		// Add button
		add_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						add_button.setEnabled(false);
						cancel_button.setEnabled(false);

						if(validate_input_mode())
						{
							int     index          = authority_name_combobox.getSelectedIndex();
							String  authority_name = authority_name_list.get(index);
							String  username       = username_textfield.getText();

							// Call to C function
							if(add_emergency_trusted_user_main(authority_name, username))
							{
								result_flag = true;
		        					dispose();
							}
						}

						add_button.setEnabled(true);
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
						add_button.setEnabled(false);
						cancel_button.setEnabled(false);
		        			dispose();
					}
				});
		    	}
		});
	}

	private void init_authority_name_combobox(ArrayList<String> authority_name_list)
	{
		int list_size = authority_name_list.size();
		for(int i=0; i < list_size; i++)
			authority_name_combobox.addItem(authority_name_list.get(i));

		authority_name_combobox.setSelectedIndex(-1);
	}

	private void init_username_textfield(String assigned_username)
	{
		username_textfield.setText(assigned_username);
		username_textfield.setEnabled(false);
	}

	private boolean validate_input_mode()
	{
		Pattern p;
		Matcher m;
		int     index;
		String  authority_name;
		String  username;

		// Validate authority name
		index = authority_name_combobox.getSelectedIndex();
		if(index == -1)
		{
			JOptionPane.showMessageDialog(this, "Please select the authority name");
			return false;
		}

		authority_name = authority_name_list.get(index);
		username = username_textfield.getText();

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			return false;
		}

		if(authority_name.equals(phr_owner_authority_name) && username.equals(phr_owner_name))
		{
			JOptionPane.showMessageDialog(this, "Trusted user must be another user");
			return false;
		}

		return true;
	}

	private boolean validate_input_web_mode(int index, String username)
	{
		Pattern p;
		Matcher m;
		String  authority_name;

		if(index == -1)
		{
			// JOptionPane.showMessageDialog(this, "Please select the authority name");
			m_result_msg = "Please select the authority name";
			return false;
		}

		authority_name = authority_name_list.get(index);

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username);
		if(!m.matches())
		{
			// JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			m_result_msg = "Please input correct format for the username";
			return false;
		}

		if(authority_name.equals(phr_owner_authority_name) && username.equals(phr_owner_name))
		{
			
			// JOptionPane.showMessageDialog(this, "Trusted user must be another user");
			m_result_msg = "Trusted user must be another user";
			return false;
		}

		return true;
	}

	public boolean get_result()
	{
		return result_flag;
	}

	public boolean getResultFlag()
	{
		return result_flag;
	}

	public String getResultMsg()
	{
		return m_result_msg;
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		//JOptionPane.showMessageDialog(main_panel, alert_msg);
		m_result_msg = alert_msg;
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Call to C function
		uninit_backend();

		// Notify alert message to user and then terminate the application
		//JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}
}



