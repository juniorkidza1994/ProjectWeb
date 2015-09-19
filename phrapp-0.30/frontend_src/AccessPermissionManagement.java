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

class AccessPermissionManagement extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1113582265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean assign_access_permission_main(String desired_user_authority_name, String desired_username, 
		boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag);
	private native boolean edit_access_permission_main(String desired_user_authority_name, String desired_username, 
		boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag);

	// Variables
	private JPanel            main_panel                   = new JPanel();

	private JComboBox         authority_name_combobox      = new JComboBox();
	private JTextField        username_textfield           = new JTextField(TEXTFIELD_LENGTH);
	private JCheckBox         upload_permission_checkbox   = new JCheckBox("Upload data", false);
	private JCheckBox         download_permission_checkbox = new JCheckBox("Download data", false);
	private JCheckBox         delete_permission_checkbox   = new JCheckBox("Delete data", false);

	private JButton           submit_button;
	private JButton           cancel_button                = new JButton("Cancel");

	private String            phr_owner_authority_name;
	private String            phr_owner_name;
	private ArrayList<String> authority_name_list;

	private boolean           is_assigning_mode_flag;     // Assigning or editing mode

	// These for editing mode only
	private String            assigned_user_authority_name;
	private String            assigned_username;
	private boolean           current_upload_permission_flag;
	private boolean           current_download_permission_flag;
	private boolean           current_delete_permission_flag;

	// Return variable
	private boolean           result_flag;

	public AccessPermissionManagement(Component parent, String phr_owner_authority_name, String phr_owner_name, ArrayList<String> authority_name_list)  // Assigning mode
	{
		is_assigning_mode_flag        = true;
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

	public AccessPermissionManagement(Component parent, String assigned_user_authority_name, String assigned_username, boolean current_upload_permission_flag, 
		boolean current_download_permission_flag, boolean current_delete_permission_flag)  // Editing mode
	{
		is_assigning_mode_flag                = false;
		result_flag                           = false;
		this.assigned_user_authority_name     = assigned_user_authority_name;
		this.assigned_username                = assigned_username;
		this.current_upload_permission_flag   = current_upload_permission_flag;
		this.current_download_permission_flag = current_download_permission_flag;
		this.current_delete_permission_flag   = current_delete_permission_flag;

		// Load JNI backend library
		System.loadLibrary("PHRapp_User_JNI");
			
		init_ui(parent);
		init_authority_name_combobox(assigned_user_authority_name);
		init_username_textfield(assigned_username);
		init_permission_checkboxes(current_upload_permission_flag, current_download_permission_flag, current_delete_permission_flag);
		setup_actions();
	}

	public AccessPermissionManagement(String phr_owner_authority_name, String phr_owner_name, ArrayList<String> authority_name_list)  // Assigning mode
	{
		is_assigning_mode_flag        = true;
		result_flag                   = false;
		this.phr_owner_authority_name = phr_owner_authority_name;
		this.phr_owner_name           = phr_owner_name;
		this.authority_name_list      = authority_name_list;

		// Load JNI backend library
		System.loadLibrary("PHRapp_User_JNI");

	}

	public AccessPermissionManagement(String assigned_user_authority_name, String assigned_username, boolean current_upload_permission_flag, 
		boolean current_download_permission_flag, boolean current_delete_permission_flag)  // Editing mode
	{
		is_assigning_mode_flag                = false;
		result_flag                           = false;
		this.assigned_user_authority_name     = assigned_user_authority_name;
		this.assigned_username                = assigned_username;
		this.current_upload_permission_flag   = current_upload_permission_flag;
		this.current_download_permission_flag = current_download_permission_flag;
		this.current_delete_permission_flag   = current_delete_permission_flag;

		// Load JNI backend library
		System.loadLibrary("PHRapp_User_JNI");
			
		System.out.println("CREATE CLASS ACCESS PERMISSION");	
	}

	public String getAuthorityName(){

		return assigned_user_authority_name;
	}

	public String getUsername(){

		return assigned_username;
	}

	public boolean getUploadFlag(){
		return current_upload_permission_flag;
	}

	public boolean getDownloadFlag(){
		return current_download_permission_flag;
	}

	public boolean getDeleteFlag(){
		return current_delete_permission_flag;
	}

	public boolean assignAccessPermission(String authority_name, String username, Boolean up, Boolean down, Boolean del){

		boolean upload_permission_flag = up.booleanValue();
		boolean download_permission_flag = down.booleanValue();
		boolean delete_permission_flag = del.booleanValue();
								// Call to C function
		if(assign_access_permission_main(authority_name, username, 
		upload_permission_flag, download_permission_flag, delete_permission_flag))
		{
			System.out.println("ASSIGN SUCCESS");
			return true;
		        				
		}
		System.out.println("ASSIGN FAILL");

		return false;
	}

	public boolean editAccessPermission(String up, String down, String del){

		boolean upload_permission_flag = Boolean.parseBoolean(up);
		boolean download_permission_flag = Boolean.parseBoolean(down);
		boolean delete_permission_flag = Boolean.parseBoolean(del);
								// Call to C function
		if(edit_access_permission_main(assigned_user_authority_name, assigned_username, 
		upload_permission_flag, download_permission_flag, delete_permission_flag))
		{
			return true;

		}

		return false;
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

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(authority_name_label);
		upper_inner_panel.add(authority_name_combobox);
		upper_inner_panel.add(username_label);
		upper_inner_panel.add(username_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 80));
		upper_outer_panel.setMaximumSize(new Dimension(400, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Access permissions checkbox
		upload_permission_checkbox.setFocusable(false);
		download_permission_checkbox.setFocusable(false);
		delete_permission_checkbox.setFocusable(false);

		// Access permissions panel
		JPanel access_permissions_box_inner_panel = new JPanel();
		access_permissions_box_inner_panel.setLayout(new BoxLayout(access_permissions_box_inner_panel, BoxLayout.Y_AXIS));
		access_permissions_box_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		access_permissions_box_inner_panel.setAlignmentX(0.5f);
		access_permissions_box_inner_panel.add(upload_permission_checkbox);
		access_permissions_box_inner_panel.add(download_permission_checkbox);
		access_permissions_box_inner_panel.add(delete_permission_checkbox);

		JPanel access_permissions_box_outer_panel = new JPanel(new GridLayout(0, 1));
		access_permissions_box_outer_panel.setLayout(new BoxLayout(access_permissions_box_outer_panel, BoxLayout.Y_AXIS));
    		access_permissions_box_outer_panel.setBorder(BorderFactory.createTitledBorder("Access Permissions"));
		access_permissions_box_outer_panel.setPreferredSize(new Dimension(230, 120));
		access_permissions_box_outer_panel.setMaximumSize(new Dimension(230, 120));
		access_permissions_box_outer_panel.setAlignmentX(0.0f);
		access_permissions_box_outer_panel.add(access_permissions_box_inner_panel);

		JPanel access_permissions_outer_panel = new JPanel();
		access_permissions_outer_panel.setPreferredSize(new Dimension(400, 130));
		access_permissions_outer_panel.setMaximumSize(new Dimension(400, 130));
		access_permissions_outer_panel.setAlignmentX(0.0f);
		access_permissions_outer_panel.add(access_permissions_box_outer_panel);

		// Buttons
		submit_button = (is_assigning_mode_flag) ? new JButton("Assign") : new JButton("Edit");
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
		main_panel.add(access_permissions_outer_panel);	
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);		

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		if(is_assigning_mode_flag)
			setTitle("Access Permission Assignment");
		else
			setTitle("Access Permission Editing");

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

						if(is_assigning_mode_flag && validate_input_assigning_mode())   // Assigning mode
						{
							int     index                    = authority_name_combobox.getSelectedIndex();
							String  authority_name           = authority_name_list.get(index);
							String  username                 = username_textfield.getText();
							boolean upload_permission_flag   = upload_permission_checkbox.isSelected();
							boolean download_permission_flag = download_permission_checkbox.isSelected();
							boolean delete_permission_flag   = delete_permission_checkbox.isSelected();

							// Call to C function
							if(assign_access_permission_main(authority_name, username, 
								upload_permission_flag, download_permission_flag, delete_permission_flag))
							{
								result_flag = true;
		        					dispose();
							}
						}
						else if(!is_assigning_mode_flag && validate_input_editing_mode())   // Editing mode
						{
							boolean upload_permission_flag   = upload_permission_checkbox.isSelected();
							boolean download_permission_flag = download_permission_checkbox.isSelected();
							boolean delete_permission_flag   = delete_permission_checkbox.isSelected();

							// Call to C function
							if(edit_access_permission_main(assigned_user_authority_name, assigned_username, 
								upload_permission_flag, download_permission_flag, delete_permission_flag))
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

	private void init_authority_name_combobox(ArrayList<String> authority_name_list)   // Assigning mode
	{
		int list_size = authority_name_list.size();
		for(int i=0; i < list_size; i++)
			authority_name_combobox.addItem(authority_name_list.get(i));

		authority_name_combobox.setSelectedIndex(-1);
	}

	private void init_authority_name_combobox(String assigned_user_authority_name)     // Editing mode
	{
		authority_name_combobox.addItem(assigned_user_authority_name);
		authority_name_combobox.setSelectedIndex(0);
		authority_name_combobox.setEnabled(false);
	}

	private void init_username_textfield(String assigned_username)
	{
		username_textfield.setText(assigned_username);
		username_textfield.setEnabled(false);
	}

	private void init_permission_checkboxes(boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag)
	{
		upload_permission_checkbox.setSelected(upload_permission_flag);
		download_permission_checkbox.setSelected(download_permission_flag);	
		delete_permission_checkbox.setSelected(delete_permission_flag);	
	}

	private boolean validate_input_assigning_mode()
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
			JOptionPane.showMessageDialog(this, "You have access permissions to your own data already");
			return false;
		}
 
		// Validate access permissions
		if(!upload_permission_checkbox.isSelected() && !download_permission_checkbox.isSelected() && !delete_permission_checkbox.isSelected())
		{
			JOptionPane.showMessageDialog(this, "Please select at least 1 access permission");
			return false;
		}

		return true;
	}

	private boolean validate_input_editing_mode()
	{
		// Validate access permissions
		if(!upload_permission_checkbox.isSelected() && !download_permission_checkbox.isSelected() && !delete_permission_checkbox.isSelected())
		{
			JOptionPane.showMessageDialog(this, "Please select at least 1 access permission");
			return false;
		}

		// Check update
		if(upload_permission_checkbox.isSelected() == current_upload_permission_flag && 
			download_permission_checkbox.isSelected() == current_download_permission_flag && 
			delete_permission_checkbox.isSelected() == current_delete_permission_flag)
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



