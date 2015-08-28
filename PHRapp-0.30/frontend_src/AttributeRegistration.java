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

class AttributeRegistration extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1113582265865921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native boolean register_attribute_main(String attribute_name, boolean is_numerical_attribute_flag);

	// Variables
	private JPanel     main_panel                           = new JPanel();

	private JTextField attribute_name_textfield             = new JTextField(TEXTFIELD_LENGTH);
	private JCheckBox  is_numerical_attribute_flag_checkbox = new JCheckBox("Numerical attribute?", false);

	private JButton    register_button                      = new JButton("Register");
	private JButton    cancel_button                        = new JButton("Cancel");

	// Return variable
	private boolean    registration_result_flag;

	public AttributeRegistration(Component parent)
	{
		registration_result_flag = false;

		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent);
		setup_actions();
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
	
		// Attribute name
		JLabel attribute_name_label = new JLabel("Attribute name: ", JLabel.RIGHT);

		JPanel attribute_name_inner_panel = new JPanel(new SpringLayout());
		attribute_name_inner_panel.add(attribute_name_label);
		attribute_name_inner_panel.add(attribute_name_textfield);

		SpringUtilities.makeCompactGrid(attribute_name_inner_panel, 1, 2, 5, 10, 10, 0);

		JPanel attribute_name_outer_panel = new JPanel();
		attribute_name_outer_panel.setLayout(new BoxLayout(attribute_name_outer_panel, BoxLayout.X_AXIS));
		attribute_name_outer_panel.setPreferredSize(new Dimension(400, 35));
		attribute_name_outer_panel.setMaximumSize(new Dimension(400, 35));
		attribute_name_outer_panel.setAlignmentX(0.0f);
		attribute_name_outer_panel.add(attribute_name_inner_panel);

		// Numerical attribute flag checkbox
        	is_numerical_attribute_flag_checkbox.setFocusable(false);
		is_numerical_attribute_flag_checkbox.setAlignmentX(0.0f);

		JPanel is_numerical_attribute_flag_checkbox_inner_panel = new JPanel();
		is_numerical_attribute_flag_checkbox_inner_panel.setLayout(new BoxLayout(is_numerical_attribute_flag_checkbox_inner_panel, BoxLayout.X_AXIS));
		is_numerical_attribute_flag_checkbox_inner_panel.setPreferredSize(new Dimension(165, 30));
		is_numerical_attribute_flag_checkbox_inner_panel.setMaximumSize(new Dimension(165, 30));
		is_numerical_attribute_flag_checkbox_inner_panel.setAlignmentX(0.0f);
		is_numerical_attribute_flag_checkbox_inner_panel.add(is_numerical_attribute_flag_checkbox);

		JPanel is_numerical_attribute_flag_checkbox_outer_panel = new JPanel();
		is_numerical_attribute_flag_checkbox_outer_panel.setPreferredSize(new Dimension(400, 30));
		is_numerical_attribute_flag_checkbox_outer_panel.setMaximumSize(new Dimension(400, 30));
		is_numerical_attribute_flag_checkbox_outer_panel.setAlignmentX(0.0f);
		is_numerical_attribute_flag_checkbox_outer_panel.add(is_numerical_attribute_flag_checkbox_inner_panel);

		// Buttons
		register_button.setAlignmentX(0.5f);
		cancel_button.setAlignmentX(0.5f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(400, 30));
		buttons_panel.setMaximumSize(new Dimension(400, 30));
		buttons_panel.setAlignmentX(0.0f);
		buttons_panel.add(register_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(attribute_name_outer_panel);
		main_panel.add(is_numerical_attribute_flag_checkbox_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);

		add(main_panel);

		setTitle("Attribute Registration");
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
	}

	private final void setup_actions()
	{
		// Register button
		register_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						register_button.setEnabled(false);
						cancel_button.setEnabled(false);

						if(validate_input())
						{
							String attribute_name               = attribute_name_textfield.getText();
							boolean is_numerical_attribute_flag = is_numerical_attribute_flag_checkbox.isSelected();

							// Call to C function
							if(register_attribute_main(attribute_name, is_numerical_attribute_flag))
							{
								registration_result_flag = true;
		        					dispose();
							}
						}

						register_button.setEnabled(true);
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
						register_button.setEnabled(false);
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

		// Validate attribute name
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");
		m = p.matcher(attribute_name_textfield.getText());

		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the attribute name");
			return false;
		}

		return true;
	}

	public boolean get_registration_result()
	{
		return registration_result_flag;
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



