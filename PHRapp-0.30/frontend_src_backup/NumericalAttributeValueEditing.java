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

class NumericalAttributeValueEditing extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1313582265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean edit_user_attribute_value_main(String username, String attribute_name, String attribute_authority_name, String attribute_value);

	// Variables
	private JPanel        main_panel                = new JPanel();

	private JTextField    username_textfield        = new JTextField(TEXTFIELD_LENGTH);
	private JTextField    attribute_name_textfield  = new JTextField(TEXTFIELD_LENGTH);
	private JTextField    attribute_value_textfield = new JTextField(TEXTFIELD_LENGTH);

	private JButton       edit_button               = new JButton("Edit");
	private JButton       cancel_button             = new JButton("Cancel");

	private int           current_attribute_value;

	// Return variable
	private boolean       result_flag;

	public NumericalAttributeValueEditing(Component parent, UserTreeTable external_user_tree_table, int selected_row)
	{
		result_flag = false;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");

		String username = get_username_from_user_tree_table(external_user_tree_table, selected_row);

		// Reference parameters
		AtomicReference<String> attribute_name_ref  = new AtomicReference<String>("");
		AtomicReference<String> attribute_value_ref = new AtomicReference<String>("");
		get_attribute_info(external_user_tree_table, selected_row, attribute_name_ref, attribute_value_ref);

		current_attribute_value = Integer.parseInt(attribute_value_ref.get());
	
		init_ui(parent);
		init_textfields(username, attribute_name_ref.get(), attribute_value_ref.get());
		setup_actions();
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		JLabel username_label        = new JLabel("Username: ", JLabel.RIGHT);
		JLabel attribute_name_label  = new JLabel("Attribute name: ", JLabel.RIGHT);
		JLabel attribute_value_label = new JLabel("Attribute value: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(username_label);
		upper_inner_panel.add(username_textfield);
		upper_inner_panel.add(attribute_name_label);
		upper_inner_panel.add(attribute_name_textfield);
		upper_inner_panel.add(attribute_value_label);
		upper_inner_panel.add(attribute_value_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 115));
		upper_outer_panel.setMaximumSize(new Dimension(400, 115));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Buttons
		edit_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(400, 30));
		buttons_panel.setMaximumSize(new Dimension(400, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(edit_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(upper_outer_panel);
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		setTitle("Numerical Attribute Value Editing");
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private final void setup_actions()
	{
		// Edit button
		edit_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						edit_button.setEnabled(false);
						cancel_button.setEnabled(false);

						if(validate_input())
						{
							String username                 = username_textfield.getText();
							String full_attribute_name      = attribute_name_textfield.getText();
							String attribute_value          = attribute_value_textfield.getText();

							String attribute_name           = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);
							String attribute_authority_name = full_attribute_name.substring(0, full_attribute_name.indexOf("."));

							// Call to C function
							if(edit_user_attribute_value_main(username, attribute_name, attribute_authority_name, attribute_value))
							{
								result_flag = true;
								dispose();
							}
						}

						edit_button.setEnabled(true);
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
						edit_button.setEnabled(false);
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
		String  attribute_value = attribute_value_textfield.getText();

		// Validate attribute value
		p = Pattern.compile("^[0-9]+");
		m = p.matcher(attribute_value);

		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value");
			return false;
		}

		// Check update
		if(Integer.parseInt(attribute_value) == current_attribute_value)
		{
			JOptionPane.showMessageDialog(this, "No any update");
			return false;
		}

		return true;
	}

	private void init_textfields(String username, String attribute_name, String attribute_value)
	{
		username_textfield.setText(username);
		username_textfield.setEnabled(false);

		attribute_name_textfield.setText(attribute_name);
		attribute_name_textfield.setEnabled(false);

		attribute_value_textfield.setText(attribute_value);
	}

	private String get_username_from_user_tree_table(UserTreeTable user_tree_table, int selected_row)
	{
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(int i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			if(base + child_sub_root_count + 1 <= selected_row)
			{
				base += child_sub_root_count+1;
			}
			else
			{
				return node.getName();
			}
		}

		return null;
	}

	private void get_attribute_info(UserTreeTable user_tree_table, int selected_row, 
		AtomicReference<String> attribute_name_ref, AtomicReference<String> attribute_value_ref)
	{
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(int i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			if(base + child_sub_root_count + 1 <= selected_row)
			{
				base += child_sub_root_count+1;
			}
			else
			{
				int no_child = selected_row-base-1;
				base = selected_row;

				if(child_sub_root_count > 0)
				{
					UserTreeTableNode attribute_node = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(node, no_child);
					attribute_name_ref.set(attribute_node.getAuthorityName() + "." + attribute_node.getName());
					attribute_value_ref.set(Integer.toString(attribute_node.getAttributeValue()));
					return;
				}
			}
		}	
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



