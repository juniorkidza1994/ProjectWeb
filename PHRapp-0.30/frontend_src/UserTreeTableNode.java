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

class UserTreeTableNode implements ConstantVars
{
	// Variables
	private String  name_table_cell;                   // Show on table
	private String  type_table_cell;
	private String  email_address_table_cell;

	private String  name;                              // User or attribute name
	private String  type;                              // Root node, user or attribute type
	private String  email_address;
	private String  authority_name;
	private boolean is_numerical_attribute_flag;
	private int     attribute_value;                   // Value of an attribute (if it's numerical attribute)

	private ArrayList<UserTreeTableNode> children      = new ArrayList<UserTreeTableNode>();
	
	public UserTreeTableNode(String name, String type, String authority_name, boolean is_numerical_attribute_flag, int attribute_value, String email_address) 
	{
		this.name                        = new String(name);
		this.type                        = new String(type);
		this.authority_name              = new String(authority_name);
		this.is_numerical_attribute_flag = is_numerical_attribute_flag;
		this.attribute_value             = attribute_value;
		this.email_address               = new String(email_address);

		create_type_table_cell();
		create_name_table_cell();
		create_email_address_table_cell();
	}

	private void create_type_table_cell()
	{
		// Create type_table_cell which uses to render in a tree table
		type_table_cell = new String(type);
	}

	private void create_name_table_cell()
	{
		// Create name_table_cell which uses to render in a tree table
		if(type_table_cell.equals(USER_TYPE))
		{
			name_table_cell = new String(authority_name + "." + name);
		}
		else if(type_table_cell.equals(ATTRIBUTE_TYPE))
		{
			if(is_numerical_attribute_flag)
			{
				name_table_cell = new String(authority_name + "." + name + " = " + Integer.toString(attribute_value));
			}
			else
			{
				name_table_cell = new String(authority_name + "." + name);
			}
		}
		else
		{
			name_table_cell = new String(name);
		}
	}

	private void create_email_address_table_cell()
	{
		// Create email_address_table_cell which uses to render in a tree table
		email_address_table_cell = new String(email_address);
	}

	public String getName() 
	{
		return name;
	}
	
	public String getType() 
	{
		return type;
	}

	public String getAuthorityName()
	{
		return authority_name;
	}

	public void setAttributeValue(int attribute_value)
	{
		this.attribute_value = attribute_value;

		// Re-create name_table_cell
		create_name_table_cell();
	}

	public int getAttributeValue()
	{
		return attribute_value;
	}

	public void setEmailAddress(String email_address)
	{
		this.email_address = email_address;

		// Re-create email_address_table_cell
		create_email_address_table_cell();
	}

	public String getEmailAddress()
	{
		return email_address;
	}

	public String getNameTableCell() 
	{
		return name_table_cell;
	}
	
	public String getTypeTableCell() 
	{
		return type_table_cell;
	}

	public String getEmailAddressTableCell() 
	{
		return email_address_table_cell;
	}

	public ArrayList<UserTreeTableNode> getChildren() 
	{
		return children;
	}
}



