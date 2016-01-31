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

class UserManagement extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1513587265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean register_user_main(String username, String email_address);
	private native boolean edit_user_email_address_and_attribute_list_main(String username, String email_address);
	private native boolean edit_user_email_address_only_main(String username, String email_address);
	private native boolean edit_user_attribute_list_only_main(String username);

	// Variables
	private DefaultTableModel external_attribute_table_model;   // Reference to external object

	private JPanel            main_panel                      = new JPanel();
	private JTextField	  username_textfield              = new JTextField(TEXTFIELD_LENGTH);
	private JTextField	  email_address_textfield         = new JTextField(TEXTFIELD_LENGTH);

	private DefaultTableModel attribute_table_model;
	private JTable            attribute_table;

	private JButton           submit_button;
	private JButton           cancel_button                   = new JButton("Cancel");

	private boolean           is_registering_mode_flag;   // Registering or editing mode

	// These for editing mode only
	String        current_email_address;
	UserTreeTable external_user_tree_table;
	int           selected_row;

	boolean       is_email_address_edited_flag;
	boolean       is_attribute_list_edited_flag;

	// Return variable
	private boolean           result_flag;

	// WEB
	private String 			  result;

	public UserManagement(Component parent, DefaultTableModel external_attribute_table_model)  // Registering mode
	{
		is_registering_mode_flag            = true;
		result_flag                         = false;
		this.external_attribute_table_model = external_attribute_table_model;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent);
		init_attribute_table_registering_mode();
		setup_actions();
	}

	public UserManagement(DefaultTableModel external_attribute_table_model)  // Registering Web mode
	{
		is_registering_mode_flag            = true;
		result_flag                         = false;
		this.external_attribute_table_model = external_attribute_table_model;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_attribute_table();
		init_attribute_table_registering_mode();
	}


	public UserManagement(Component parent, DefaultTableModel external_attribute_table_model, UserTreeTable external_user_tree_table, int selected_row)  // Editing mode
	{
		is_registering_mode_flag            = false;
		result_flag                         = false;
		is_email_address_edited_flag        = false;
		is_attribute_list_edited_flag       = false;
		this.external_attribute_table_model = external_attribute_table_model;
		this.external_user_tree_table       = external_user_tree_table;
		this.selected_row                   = selected_row;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent);
		init_username_textfield(get_username_from_user_tree_table());

		current_email_address = get_email_address_from_user_tree_table();
		init_email_address_textfield(current_email_address);

		init_attribute_table_editing_mode();
		setup_actions();
	}

	public UserManagement(DefaultTableModel external_attribute_table_model, UserTreeTable external_user_tree_table, int selected_row)  // Editing web mode
	{
		is_registering_mode_flag            = false;
		result_flag                         = false;
		is_email_address_edited_flag        = false;
		is_attribute_list_edited_flag       = false;
		this.external_attribute_table_model = external_attribute_table_model;
		this.external_user_tree_table       = external_user_tree_table;
		this.selected_row                   = selected_row;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");

		current_email_address = get_email_address_from_user_tree_table();

		init_attribute_table();
		init_attribute_table_editing_mode();
	}


	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
		
		JLabel username_label      = new JLabel("Username: ", JLabel.RIGHT);
		JLabel email_address_label = new JLabel("E-mail address: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(username_label);
		upper_inner_panel.add(username_textfield);
		upper_inner_panel.add(email_address_label);
		upper_inner_panel.add(email_address_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 80));
		upper_outer_panel.setMaximumSize(new Dimension(400, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		JLabel attribute_label = new JLabel("Attributes");

		// Attribute table
		attribute_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921796L;

			@Override
	    		public boolean isCellEditable(int row, int column)
			{
				switch(column)
				{
					case 0:
						return true;
					case 1:
						return false;
					case 2:
					default:
						return ((String)external_attribute_table_model.getValueAt(row, 1)).equals("true") ? true : false;
				}
	    		}
		};

		attribute_table_model.setDataVector(null, new Object[] {"Selection", "Attribute name", "Attribute value"});
		attribute_table = new JTable(attribute_table_model)
		{
			private static final long serialVersionUID = -1113582265865921797L;

			@Override
			public Class getColumnClass(int column)
			{
				switch(column)
				{
					case 0:
				        	return Boolean.class;
				    	case 1:
				        case 2:
					default:
						return String.class;
				}
			}
		};

		JScrollPane attribute_table_panel = new JScrollPane();
		attribute_table_panel.setPreferredSize(new Dimension(400, 200));
		attribute_table_panel.setMaximumSize(new Dimension(400, 200));
		attribute_table_panel.setAlignmentX(0.0f);
		attribute_table_panel.getViewport().add(attribute_table);

		// Buttons
		submit_button = (is_registering_mode_flag) ? new JButton("Register") : new JButton("Edit");
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
		main_panel.add(attribute_label);
		main_panel.add(attribute_table_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		if(is_registering_mode_flag)
			setTitle("User Registration");
		else
			setTitle("User Editing");

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

						if(is_registering_mode_flag && validate_input_registering_mode())
						{
							String username      = username_textfield.getText();
							String email_address = email_address_textfield.getText();

							// Call to C function
							if(register_user_main(username, email_address))
							{
								result_flag = true;
		        					dispose();
							}
						}
						else if(!is_registering_mode_flag && validate_input_editing_mode())
						{
							String username = username_textfield.getText();
							
							for (int j = 0 ; j < attribute_table_model.getRowCount() ; j++)
	            				System.out.println(attribute_table_model.getValueAt(j,0).toString() + " " + attribute_table_model.getValueAt(j,2));

							if(is_email_address_edited_flag && is_attribute_list_edited_flag)
							{
								String email_address = email_address_textfield.getText();

								// Call to C function
								if(edit_user_email_address_and_attribute_list_main(username, email_address))
								{
									result_flag = true;
									dispose();
								}
							}
							else if(is_email_address_edited_flag)
							{
								String email_address = email_address_textfield.getText();
								
								// Call to C function
								if(edit_user_email_address_only_main(username, email_address))
								{
									result_flag = true;
									dispose();
								}
							}
							else if(is_attribute_list_edited_flag)
							{
								// Call to C function
								if(edit_user_attribute_list_only_main(username))
								{
									result_flag = true;
									dispose();
								}
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

	private void init_attribute_table(){

		// Attribute table
		attribute_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921796L;

			@Override
	    		public boolean isCellEditable(int row, int column)
			{
				switch(column)
				{
					case 0:
						return true;
					case 1:
						return false;
					case 2:
					default:
						return ((String)external_attribute_table_model.getValueAt(row, 1)).equals("true") ? true : false;
				}
	    		}
		};

		attribute_table_model.setDataVector(null, new Object[] {"Selection", "Attribute name", "Attribute value"});
		attribute_table = new JTable(attribute_table_model)
		{
			private static final long serialVersionUID = -1113582265865921797L;

			@Override
			public Class getColumnClass(int column)
			{
				switch(column)
				{
					case 0:
				        	return Boolean.class;
				    	case 1:
				        case 2:
					default:
						return String.class;
				}
			}
		};
	}

	public void registerUser(String username, String email_address){
		if(is_registering_mode_flag && validate_input_registering_web_mode(username, email_address))
		{

			System.out.println("------ REGISTER USER ------------");
			System.out.println(username);
			System.out.println(email_address);
			// Call to C function
			if(register_user_main(username, email_address))
			{
					System.out.println("Register `Success");
					result_flag = true;
					result = "Success";
			}
		}
		else
			result_flag = false;
	}

	public void editUser(String username ,String email_address){

		System.out.println("USERNAME :" + username);
		System.out.println("Email Address :" + email_address);
		
		for (int j = 0 ; j < attribute_table_model.getRowCount() ; j++)
	       	System.out.println(attribute_table_model.getValueAt(j,0).toString() + " " + attribute_table_model.getValueAt(j,2));

		if(!is_registering_mode_flag && validate_input_editing_web_mode(email_address)){

			if(is_email_address_edited_flag && is_attribute_list_edited_flag)
			{

				System.out.println("Email & Attribute");

				// Call to C function
				if(edit_user_email_address_and_attribute_list_main(username, email_address))
				{
					result_flag = true;
					result      = result      = "Edit Email & Attribute Success";
				}
			}
			else if(is_email_address_edited_flag)
			{
				System.out.println("Email");
									
				// Call to C function
				if(edit_user_email_address_only_main(username, email_address))
				{
					result_flag = true;	
					result      = "Edit Email Success";
				}
			}
			else if(is_attribute_list_edited_flag)
			{

				System.out.println("Attribute");
				// Call to C function
				if(edit_user_attribute_list_only_main(username))
				{	
					result_flag = true;
					result      = "Edit Attribute Success";
				}
			}
		}
	}

	private void init_attribute_table_registering_mode()
	{
		int row_count = external_attribute_table_model.getRowCount();
		for(int i=0; i < row_count; i++)
		{
			String  full_attribute_name;
			boolean is_numerical_attribute_flag;

			full_attribute_name         = (String)external_attribute_table_model.getValueAt(i, 0);
			is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;

			attribute_table_model.insertRow(attribute_table.getRowCount(), new Object[] {
				false, full_attribute_name, is_numerical_attribute_flag ? "(value)" : "(none)"});
		}
	}

	public Object[][] getTableAttribute () {
	    DefaultTableModel dtm = (DefaultTableModel) attribute_table.getModel();
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	public void setTableAttribute (String flag) {

	    int i  = 0;

	    int pos = 0;

	    System.out.println("Start Set table Attribute"); 

	    for (String str: flag.split(",")){
		    for (String r: str.split(" ")){
		    		System.out.println("R : " + r);
		    		if(pos == 0){
			    		if(r.equals("true")){
			            	System.out.println("Set in TRUE");
			            	attribute_table_model.setValueAt(true,i,pos);
			            }
			            else if(r.equals("false")){
			            	System.out.println("Set in FALSE");
			            	attribute_table_model.setValueAt(false,i,pos);
			            }
		        	}
		        	else if(pos == 2){
			            attribute_table_model.setValueAt(r,i,pos);
		        	}
		            i++;
		    }
		    i = 0;
		    pos = 2;
		}

		System.out.println("In attribute_table_model :");

	    for (int j = 0 ; j < attribute_table_model.getRowCount() ; j++)
	            System.out.println(attribute_table_model.getValueAt(j,0).toString() + " " + attribute_table_model.getValueAt(j,2));

	    System.out.println("End set table");

	}

	private String get_username_from_user_tree_table()
	{
		UserTreeTableNode user_node = get_selected_user_node_from_user_tree_table();
		return user_node.getName();
	} 

	public String getUserEdit(){
		return get_username_from_user_tree_table();
	}

	public String getEmailEdit(){
		return get_email_address_from_user_tree_table();
	}


	private String get_email_address_from_user_tree_table()
	{
		UserTreeTableNode user_node = get_selected_user_node_from_user_tree_table();
		return user_node.getEmailAddress();
	} 

	private UserTreeTableNode get_selected_user_node_from_user_tree_table()
	{
		int i;
		int base             = 0;
		int child_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(external_user_tree_table.get_user_tree_table_root());

		for(i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(
				external_user_tree_table.get_user_tree_table_root(), i);

			int child_sub_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(node);

			base += child_sub_root_count+1;
		}

		if(base == selected_row)    // At a user level
		{
			return (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(external_user_tree_table.get_user_tree_table_root(), i);
		}

		return null;
	}

	private void init_username_textfield(String username)
	{
		username_textfield.setText(username);
		username_textfield.setEnabled(false);
	}

	private void init_email_address_textfield(String email_address)
	{
		email_address_textfield.setText(email_address);
	}

	private void init_attribute_table_editing_mode()
	{
		int row_count = external_attribute_table_model.getRowCount();
		for(int i=0; i < row_count; i++)
		{
			String  full_attribute_name;
			boolean is_numerical_attribute_flag;
			boolean is_selected_flag;
			String  attribute_name;

			// Reference parameter
			AtomicReference<String> attribute_value_ref = new AtomicReference<String>("");

			full_attribute_name         = (String)external_attribute_table_model.getValueAt(i, 0);
			is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;
			attribute_name              = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);

			is_selected_flag = is_attribute_selected(attribute_name, attribute_value_ref);			
			if(is_selected_flag)
			{
				attribute_table_model.insertRow(attribute_table.getRowCount(), new Object[] 
					{true, full_attribute_name, is_numerical_attribute_flag ? attribute_value_ref.get() : "(none)"});
			}
			else
			{
				attribute_table_model.insertRow(attribute_table.getRowCount(), new Object[] 
					{false, full_attribute_name, is_numerical_attribute_flag ? "(value)" : "(none)"});
			}
		}
	}

	private boolean is_attribute_selected(String attribute_name, AtomicReference<String> attribute_value_ref)
	{
			int i;
			int base             = 0;
			int child_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(external_user_tree_table.get_user_tree_table_root());

			for(i=0; i < child_root_count && base != selected_row; i++)
			{
				UserTreeTableNode node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(
					external_user_tree_table.get_user_tree_table_root(), i);

				int child_sub_root_count  = external_user_tree_table.get_user_tree_table_model().getChildCount(node);
				base += child_sub_root_count+1;
			}

			if(base == selected_row)    // At a user level
			{
				UserTreeTableNode user_node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(
					external_user_tree_table.get_user_tree_table_root(), i);

				int child_sub_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(user_node);

				for(int j=0; j < child_sub_root_count; j++)  // At an attribute level
				{
					UserTreeTableNode attribute_node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(user_node, j);
					if(attribute_node.getName().equals(attribute_name))
					{
						attribute_value_ref.set(Integer.toString(attribute_node.getAttributeValue()));
						return true;
					}
				}
			}

			return false;
	}

	private boolean validate_input_registering_mode()
	{
		Pattern p;
		Matcher m;
		int     noRowChecked;

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(new String(username_textfield.getText()));
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			return false;
		}

		// Validate e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(new String(email_address_textfield.getText()));
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the email address");
			return false;
		}

		// Validate selected attributes
		noRowChecked = 0;

		for(int i=0; i < attribute_table_model.getRowCount(); i++)
		{
			boolean is_checked_flag;
			boolean is_numerical_attribute_flag;

			is_checked_flag = ((Boolean)attribute_table_model.getValueAt(i, 0)).booleanValue();
			if(is_checked_flag)
			{
				noRowChecked++;
				is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;
				if(is_numerical_attribute_flag)
				{
					String attribute_name  = (String)attribute_table_model.getValueAt(i, 1);
					String attribute_value = (String)attribute_table_model.getValueAt(i, 2);

					p = Pattern.compile("^[0-9]+");
					m = p.matcher(attribute_value);

					if(!m.matches())
					{
						JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value" + "\"" + attribute_name + "\"");
						return false;
					}
				}
			}
		}

		if(noRowChecked == 0)
		{
			JOptionPane.showMessageDialog(this, "Please select at least 1 attribute");
			return false;
		}

		return true;
	}

	// WEB
	private boolean validate_input_registering_web_mode(String username, String email_address)
	{

		System.out.println("Start Validate");


		Pattern p;
		Matcher m;
		int     noRowChecked;

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username);
		if(!m.matches())
		{
			//JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			result = "Please input correct format for the username";
			return false;
		}

		// Validate e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(email_address);
		if(!m.matches())
		{
			//JOptionPane.showMessageDialog(this, "Please input correct format for the email address");
			result = "Please input correct format for the email address";
			return false;
		}

		// Validate selected attributes
		noRowChecked = 0;

		for(int i=0; i < attribute_table_model.getRowCount(); i++)
		{
			boolean is_checked_flag;
			boolean is_numerical_attribute_flag;

			is_checked_flag = ((Boolean)attribute_table_model.getValueAt(i, 0)).booleanValue();
			if(is_checked_flag)
			{
				noRowChecked++;
				is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;
				if(is_numerical_attribute_flag)
				{
					String attribute_name  = (String)attribute_table_model.getValueAt(i, 1);
					String attribute_value = (String)attribute_table_model.getValueAt(i, 2);

					p = Pattern.compile("^[0-9]+");
					m = p.matcher(attribute_value);

					if(!m.matches())
					{
						//JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value" + "\"" + attribute_name + "\"");
						result = "Please input correct format for the attribute value" + "\"" + attribute_name + "\"";
						return false;
					}
				}
			}
		}

		if(noRowChecked == 0)
		{
			//JOptionPane.showMessageDialog(this, "Please select at least 1 attribute");
			result = "Please select at least 1 attribute";
			return false;
		}

		return true;
	}


	private boolean validate_input_editing_mode()
	{
		Pattern p;
		Matcher m;
		int     noRowChecked;

		// Validate e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(new String(email_address_textfield.getText()));
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the email address");
			return false;
		}

		// Validate selected attributes
		noRowChecked = 0;

		for(int i=0; i < attribute_table_model.getRowCount(); i++)
		{
			boolean is_checked_flag;
			boolean is_numerical_attribute_flag;

			is_checked_flag = ((Boolean)attribute_table_model.getValueAt(i, 0)).booleanValue();
			if(is_checked_flag)
			{
				noRowChecked++;
				is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;
				if(is_numerical_attribute_flag)
				{
					String attribute_name  = (String)attribute_table_model.getValueAt(i, 1);
					String attribute_value = (String)attribute_table_model.getValueAt(i, 2);

					p = Pattern.compile("^[0-9]+");
					m = p.matcher(attribute_value);

					if(!m.matches())
					{
						JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value" + "\"" + attribute_name + "\"");
						return false;
					}
				}
			}
		}

		if(noRowChecked == 0)
		{
			JOptionPane.showMessageDialog(this, "Please select at least 1 attribute");
			return false;
		}

		return check_for_update();
	}

	private boolean validate_input_editing_web_mode(String email)
	{
		Pattern p;
		Matcher m;
		int     noRowChecked;

		// Validate e-mail address
		p = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

		m = p.matcher(email);
		if(!m.matches())
		{
			//JOptionPane.showMessageDialog(this, "Please input correct format for the email address");
				
			result = "Please input correct format for the email address";

			return false;
		}

		// Validate selected attributes
		noRowChecked = 0;

		for(int i=0; i < attribute_table_model.getRowCount(); i++)
		{
			boolean is_checked_flag;
			boolean is_numerical_attribute_flag;

			is_checked_flag = ((Boolean)attribute_table_model.getValueAt(i, 0)).booleanValue();
			if(is_checked_flag)
			{
				noRowChecked++;
				is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;
				if(is_numerical_attribute_flag)
				{
					String attribute_name  = (String)attribute_table_model.getValueAt(i, 1);
					String attribute_value = (String)attribute_table_model.getValueAt(i, 2);

					p = Pattern.compile("^[0-9]+");
					m = p.matcher(attribute_value);

					if(!m.matches())
					{
						//JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value" + "\"" + attribute_name + "\"");
						
						result = "Please input correct format for the attribute value" + "\"" + attribute_name + "\"";

						return false;
					}
				}
			}
		}

		if(noRowChecked == 0)
		{
			//JOptionPane.showMessageDialog(this, "Please select at least 1 attribute");
			
			result = "Please select at least 1 attribute";

			return false;
		}

		return checkForUpdate(email);
	}

	private boolean check_for_update()
	{
		is_email_address_edited_flag  = false;
		is_attribute_list_edited_flag = false;

		// Check e-mail address update
		if(!email_address_textfield.getText().equals(current_email_address))
			is_email_address_edited_flag = true;

		// Check attribute list
		int i;
		int base             = 0;
		int child_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(external_user_tree_table.get_user_tree_table_root());

		for(i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(
				external_user_tree_table.get_user_tree_table_root(), i);

			int child_sub_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(node);
			base += child_sub_root_count+1;
		}

		if(base == selected_row)    // At a user level
		{
			UserTreeTableNode user_node;
			int               child_sub_root_count;
			int		  rowCount;

			user_node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(external_user_tree_table.get_user_tree_table_root(), i);
			child_sub_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(user_node);

			rowCount = attribute_table_model.getRowCount();
			for(int j=0; j < rowCount && !is_attribute_list_edited_flag; j++)
			{
				boolean is_attribute_checked_flag = ((Boolean)attribute_table_model.getValueAt(j, 0)).booleanValue();
				String  attribute_name            = (String)attribute_table_model.getValueAt(j, 1);
				boolean found_flag		  = false;

				for(int k=0; k < child_sub_root_count && !is_attribute_list_edited_flag; k++)    // At an attribute level
				{
					UserTreeTableNode attribute_node;
					String            attribute_node_name;

					attribute_node      = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(user_node, k);
					attribute_node_name = (attribute_node.getNameTableCell().indexOf(" = ") >= 0) ? attribute_node.getNameTableCell(
						).substring(0, attribute_node.getNameTableCell().indexOf(" = ")) : attribute_node.getNameTableCell();

					if(attribute_node_name.equals(attribute_name))
					{
						boolean is_numerical_attribute_flag = (attribute_node.getNameTableCell().indexOf(" = ") >= 0);

						found_flag = true;
						if(is_numerical_attribute_flag)
						{
							int current_attribute_value = attribute_node.getAttributeValue();
							int attribute_value         = Integer.parseInt((String)attribute_table_model.getValueAt(j, 2));

							if((is_attribute_checked_flag && attribute_value != current_attribute_value) || !is_attribute_checked_flag)
								is_attribute_list_edited_flag = true;
						}
						else
						{
							if(!is_attribute_checked_flag)
								is_attribute_list_edited_flag = true;
						}
					}
				}

				if(!found_flag && is_attribute_checked_flag)
					is_attribute_list_edited_flag = true;
			}
		}

		if(is_email_address_edited_flag || is_attribute_list_edited_flag)
			return true;

		JOptionPane.showMessageDialog(this, "No any update");
		return false;
	}


	// web
	public boolean checkForUpdate(String email)
	{
		is_email_address_edited_flag  = false;
		is_attribute_list_edited_flag = false;

		// Check e-mail address update
		if(!email.equals(current_email_address)){
			is_email_address_edited_flag = true;
			System.out.println("EMAIL UPDATE");
		}

		// Check attribute list
		int i;
		int base             = 0;
		int child_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(external_user_tree_table.get_user_tree_table_root());

		for(i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(
				external_user_tree_table.get_user_tree_table_root(), i);

			int child_sub_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(node);
			base += child_sub_root_count+1;
		}

		if(base == selected_row)    // At a user level
		{
			UserTreeTableNode user_node;
			int               child_sub_root_count;
			int		  rowCount;

			user_node = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(external_user_tree_table.get_user_tree_table_root(), i);
			child_sub_root_count = external_user_tree_table.get_user_tree_table_model().getChildCount(user_node);

			rowCount = attribute_table_model.getRowCount();
			for(int j=0; j < rowCount && !is_attribute_list_edited_flag; j++)
			{
				boolean is_attribute_checked_flag = ((Boolean)attribute_table_model.getValueAt(j, 0)).booleanValue();
				String  attribute_name            = (String)attribute_table_model.getValueAt(j, 1);
				boolean found_flag		  = false;

				for(int k=0; k < child_sub_root_count && !is_attribute_list_edited_flag; k++)    // At an attribute level
				{
					UserTreeTableNode attribute_node;
					String            attribute_node_name;

					attribute_node      = (UserTreeTableNode)external_user_tree_table.get_user_tree_table_model().getChild(user_node, k);
					attribute_node_name = (attribute_node.getNameTableCell().indexOf(" = ") >= 0) ? attribute_node.getNameTableCell(
						).substring(0, attribute_node.getNameTableCell().indexOf(" = ")) : attribute_node.getNameTableCell();

					if(attribute_node_name.equals(attribute_name))
					{
						boolean is_numerical_attribute_flag = (attribute_node.getNameTableCell().indexOf(" = ") >= 0);

						found_flag = true;
						if(is_numerical_attribute_flag)
						{
							int current_attribute_value = attribute_node.getAttributeValue();
							int attribute_value         = Integer.parseInt((String)attribute_table_model.getValueAt(j, 2));

							if((is_attribute_checked_flag && attribute_value != current_attribute_value) || !is_attribute_checked_flag)
								is_attribute_list_edited_flag = true;
						}
						else
						{
							if(!is_attribute_checked_flag)
								is_attribute_list_edited_flag = true;
						}
					}
				}

				if(!found_flag && is_attribute_checked_flag)
					is_attribute_list_edited_flag = true;
			}
		}

		if(is_email_address_edited_flag || is_attribute_list_edited_flag)
			return true;

		// JOptionPane.showMessageDialog(this, "No any update");
		result = "No any update";
		return false;
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
		return result;
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		if(alert_msg.indexOf("Sending an e-mail") != -1){
			System.out.println("Sending an e-mail failed");
			result_flag = true;
		}
		
		result = alert_msg;

		// JOptionPane.showMessageDialog(main_panel, alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Call to C function
		uninit_backend();

		// Notify alert message to user and then terminate the application
		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}

	// Index starts at 1
	private synchronized String get_user_attribute_by_index_callback_handler(final int index)
	{
		int    count      = 0;
		String buffer_ret = new String("");

		for(int i=0; i < attribute_table_model.getRowCount(); i++)
		{
			boolean is_checked_flag;
			boolean is_numerical_attribute_flag;
			String  full_attribute_name;
			String  attribute_name;
			String  attribute_value;

			is_checked_flag = ((Boolean)attribute_table_model.getValueAt(i, 0)).booleanValue();
			if(is_checked_flag)
			{
				count++;
				if(count == index)
				{
					is_numerical_attribute_flag = ((String)external_attribute_table_model.getValueAt(i, 1)).equals("true") ? true : false;
					full_attribute_name         = (String)attribute_table_model.getValueAt(i, 1);
					attribute_name              = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);

					buffer_ret = new String("[\"end_of_user_attribute_list_flag\"=\"0\"]\n");
					buffer_ret += "[\"attribute_name\"=\"" + attribute_name + "\"]\n";
					buffer_ret += "[\"is_numerical_attribute_flag\"=\"" + ((is_numerical_attribute_flag) ? "1" : "0").toString() + "\"]\n";

					if(is_numerical_attribute_flag)
					{
						attribute_value = (String)attribute_table_model.getValueAt(i, 2);
						buffer_ret += "[\"attribute_value\"=\"" + attribute_value + "\"]\n";
					}

					break;
				}
			}
		}

		if(count != index)
		{
			buffer_ret = new String("[\"end_of_user_attribute_list_flag\"=\"1\"]\n");
		}

		return buffer_ret;
	}
}




