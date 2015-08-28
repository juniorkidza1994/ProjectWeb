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

class NumericalAttributeInformationEntry extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1133582265865921754L;

	// Variables
	private JPanel              main_panel                         = new JPanel();
	private JTextField          authority_name_textfield           = new JTextField(TEXTFIELD_LENGTH);
	private JTextField          attribute_name_textfield           = new JTextField(TEXTFIELD_LENGTH);
	private JTextField          attribute_value_textfield          = new JTextField(TEXTFIELD_LENGTH);

	private JRadioButton[]      comparison_operation_radio_buttons = new JRadioButton[5];
       	private ButtonGroup         comparison_operation_group;
        private final String        morethan_operation                 = ComparisonOperation.MORETHAN.toString();
	private final String        morethan_or_equal_operation        = ComparisonOperation.MORETHAN_OR_EQUAL.toString();
	private final String        lessthan_operation                 = ComparisonOperation.LESSTHAN.toString();
	private final String        lessthan_or_equal_operation        = ComparisonOperation.LESSTHAN_OR_EQUAL.toString();
	private final String        equal_operation                    = ComparisonOperation.EQUAL.toString();

	private JButton             submit_button;
	private JButton             cancel_button                      = new JButton("Cancel");

	private boolean             is_adding_mode_flag;          // Adding or editing mode

	// These for editing mode only
	private int                 current_attribute_value;
	private ComparisonOperation current_comparison_operation;

	// Return variable
	private boolean             result_flag;

	public NumericalAttributeInformationEntry(Component parent, String authority_name, String attribute_name)   // Adding mode
	{
		is_adding_mode_flag = true;
		result_flag         = false;

		init_ui(parent, authority_name, attribute_name);
		setup_actions();
	}

	public NumericalAttributeInformationEntry(Component parent, String authority_name, String attribute_name, 
		int current_attribute_value, ComparisonOperation current_comparison_operation)                     // Editing mode
	{
		is_adding_mode_flag               = false;
		result_flag                       = false;
		this.current_attribute_value      = current_attribute_value;
		this.current_comparison_operation = current_comparison_operation;

		init_ui(parent, authority_name, attribute_name);
		set_attribute_value(current_attribute_value);
		set_comparison_operation(current_comparison_operation);
		setup_actions();
	}

	private final void init_ui(Component parent, String authority_name, String attribute_name)
	{
		authority_name_textfield.setText(authority_name);
		authority_name_textfield.setEditable(false);

		attribute_name_textfield.setText(attribute_name);
		attribute_name_textfield.setEditable(false);

		JLabel authority_name_label  = new JLabel("Authority name: ", JLabel.RIGHT);
		JLabel attribute_name_label  = new JLabel("Attribute name: ", JLabel.RIGHT);
		JLabel attribute_value_label = new JLabel("Attribute value: ", JLabel.RIGHT);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(authority_name_label);
		upper_inner_panel.add(authority_name_textfield);
		upper_inner_panel.add(attribute_name_label);
		upper_inner_panel.add(attribute_name_textfield);
		upper_inner_panel.add(attribute_value_label);
		upper_inner_panel.add(attribute_value_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 115));
		upper_outer_panel.setMaximumSize(new Dimension(400, 115));
		upper_outer_panel.setAlignmentX(0.5f);
		upper_outer_panel.add(upper_inner_panel);

		// Comparison operation
        	comparison_operation_radio_buttons[0] = new JRadioButton(morethan_operation);
        	comparison_operation_radio_buttons[0].setActionCommand(morethan_operation);
		comparison_operation_radio_buttons[0].setSelected(false);

		comparison_operation_radio_buttons[1] = new JRadioButton(morethan_or_equal_operation);
        	comparison_operation_radio_buttons[1].setActionCommand(morethan_or_equal_operation);
		comparison_operation_radio_buttons[1].setSelected(false);

		comparison_operation_radio_buttons[2] = new JRadioButton(lessthan_operation);
        	comparison_operation_radio_buttons[2].setActionCommand(lessthan_operation);
		comparison_operation_radio_buttons[2].setSelected(false);

		comparison_operation_radio_buttons[3] = new JRadioButton(lessthan_or_equal_operation);
        	comparison_operation_radio_buttons[3].setActionCommand(lessthan_or_equal_operation);
		comparison_operation_radio_buttons[3].setSelected(false);

		comparison_operation_radio_buttons[4] = new JRadioButton(equal_operation);
        	comparison_operation_radio_buttons[4].setActionCommand(equal_operation);
		comparison_operation_radio_buttons[4].setSelected(false);

		comparison_operation_group = new ButtonGroup();
            	comparison_operation_group.add(comparison_operation_radio_buttons[0]);
		comparison_operation_group.add(comparison_operation_radio_buttons[1]);
		comparison_operation_group.add(comparison_operation_radio_buttons[2]);
		comparison_operation_group.add(comparison_operation_radio_buttons[3]);
		comparison_operation_group.add(comparison_operation_radio_buttons[4]);

		// Comparison operation panel
		JPanel comparison_operation_inner_panel = new JPanel(new SpringLayout());
		comparison_operation_inner_panel.setBorder(new EmptyBorder(new Insets(0, 10, 0, 10)));
		comparison_operation_inner_panel.setPreferredSize(new Dimension(120, 110));
		comparison_operation_inner_panel.setMaximumSize(new Dimension(120, 110));
		comparison_operation_inner_panel.add(comparison_operation_radio_buttons[0]);
		comparison_operation_inner_panel.add(comparison_operation_radio_buttons[1]);
		comparison_operation_inner_panel.add(comparison_operation_radio_buttons[2]);
		comparison_operation_inner_panel.add(comparison_operation_radio_buttons[3]);
		comparison_operation_inner_panel.add(comparison_operation_radio_buttons[4]);
		comparison_operation_inner_panel.add(new JLabel(""));

		SpringUtilities.makeCompactGrid(comparison_operation_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel comparison_operation_outer_panel = new JPanel(new GridLayout(0, 1));
		comparison_operation_outer_panel.setLayout(new BoxLayout(comparison_operation_outer_panel, BoxLayout.Y_AXIS));
    		comparison_operation_outer_panel.setBorder(BorderFactory.createTitledBorder("Operation:"));
		comparison_operation_outer_panel.setAlignmentX(0.5f);
		comparison_operation_outer_panel.add(comparison_operation_inner_panel);

		// Buttons
		submit_button = (is_adding_mode_flag) ? new JButton("Add") : new JButton("Edit");
		submit_button.setAlignmentX(0.0f);
		cancel_button.setAlignmentX(0.0f);

		JPanel buttons_panel = new JPanel();
		buttons_panel.setPreferredSize(new Dimension(400, 30));
		buttons_panel.setMaximumSize(new Dimension(400, 30));
		buttons_panel.setAlignmentX(0.5f);
		buttons_panel.add(submit_button);
		buttons_panel.add(cancel_button);

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		main_panel.add(upper_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(comparison_operation_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(buttons_panel);

		setModalityType(ModalityType.APPLICATION_MODAL);
		add(main_panel);

		if(is_adding_mode_flag)
			setTitle("Numerical Attribute Information Entry");
		else
			setTitle("Numerical Attribute Information Editing");

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

						if((is_adding_mode_flag && validate_input_adding_mode()) 
							|| (!is_adding_mode_flag && validate_input_editing_mode()))
						{		
							result_flag = true;
							dispose();
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

	private boolean validate_input_adding_mode()
	{
		Pattern p;
		Matcher m;

		// Validate attribute value
		p = Pattern.compile("^[0-9]+");
		m = p.matcher(attribute_value_textfield.getText());

		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value");
			return false;
		}

		// Validate comparison operation
		for(Enumeration<AbstractButton> buttons = comparison_operation_group.getElements(); buttons.hasMoreElements();)
		{
			AbstractButton button = buttons.nextElement();
			if(button.isSelected())
				return true;
		}

		JOptionPane.showMessageDialog(this, "Please select the comparison operation");

		return false;
	}

	private boolean validate_input_editing_mode()
	{
		Pattern p;
		Matcher m;

		// Validate attribute value
		p = Pattern.compile("^[0-9]+");
		m = p.matcher(get_attribute_value_from_textfield());

		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the attribute value");
			return false;
		}

		// Validate comparison operation
		if(get_comparison_operation() == null)
		{
			JOptionPane.showMessageDialog(this, "Please select the comparison operation");
			return false;
		}

		return check_attribute_information_update();
	}

	private boolean check_attribute_information_update()
	{
		if(get_attribute_value() == current_attribute_value && get_comparison_operation() == current_comparison_operation)
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

	public int get_attribute_value()
	{
		return Integer.parseInt(attribute_value_textfield.getText());
	}

	protected void set_attribute_value(int attribute_value)
	{
		attribute_value_textfield.setText(Integer.toString(attribute_value));
	}

	protected String get_attribute_value_from_textfield()
	{
		return attribute_value_textfield.getText();
	}

	public ComparisonOperation get_comparison_operation()
	{
		String comparison_operation = comparison_operation_group.getSelection().getActionCommand();
		if(comparison_operation.equals(morethan_operation))
		{
			return ComparisonOperation.MORETHAN;
		}
		else if(comparison_operation.equals(morethan_or_equal_operation))
		{
			return ComparisonOperation.MORETHAN_OR_EQUAL;
		}
		else if(comparison_operation.equals(lessthan_operation))
		{
			return ComparisonOperation.LESSTHAN;
		}
		else if(comparison_operation.equals(lessthan_or_equal_operation))
		{
			return ComparisonOperation.LESSTHAN_OR_EQUAL;
		}
		else if(comparison_operation.equals(equal_operation))
		{
			return ComparisonOperation.EQUAL;
		}
		else
		{
			return null;
		}
	}

	protected void set_comparison_operation(ComparisonOperation comparison_operation)
	{
		if(comparison_operation == ComparisonOperation.MORETHAN)
			comparison_operation_radio_buttons[0].setSelected(true);
		else if(comparison_operation == ComparisonOperation.MORETHAN_OR_EQUAL)
			comparison_operation_radio_buttons[1].setSelected(true);
		else if(comparison_operation == ComparisonOperation.LESSTHAN)
			comparison_operation_radio_buttons[2].setSelected(true);
		else if(comparison_operation == ComparisonOperation.LESSTHAN_OR_EQUAL)
			comparison_operation_radio_buttons[3].setSelected(true);
		else if(comparison_operation == ComparisonOperation.EQUAL)
			comparison_operation_radio_buttons[4].setSelected(true);
	}
}



