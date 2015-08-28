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

public class UserTreeTable implements ConstantVars 
{
	private JXTreeTable        user_tree_table;
	private UserTreeTableModel user_tree_table_model;
	private UserTreeTableNode  user_tree_table_root;

	public UserTreeTable()
	{
		user_tree_table_root  = new UserTreeTableNode("Root", ROOT_NODE_TYPE, "null", false, 0, "null");
		user_tree_table_model = new UserTreeTableModel(user_tree_table_root);
	  	user_tree_table       = new JXTreeTable(user_tree_table_model);
		user_tree_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	}

	public void add_user(final String username, final String authority_name, final String email_address)
	{
		user_tree_table_root.getChildren().add(new UserTreeTableNode(username, USER_TYPE, authority_name, false, 0, email_address));
	}

	public boolean attach_numerical_user_attribute(final String username, final String attribute_name, final String authority_name, final int attribute_value)
	{
		// Search for the user's node and then attach an attribute(sub-child) to that user
		for(int i=0; i < user_tree_table_model.getChildCount(user_tree_table_root); i++)
		{
			UserTreeTableNode node = (UserTreeTableNode)user_tree_table_model.getChild(user_tree_table_root, i);
			if(node.getName().equals(username))
			{
				node.getChildren().add(new UserTreeTableNode(attribute_name, ATTRIBUTE_TYPE, authority_name, true, attribute_value, ""));
				return true;
			}
		}

		return false;
	}

	public boolean attach_non_numerical_user_attribute(final String username, final String attribute_name, final String authority_name)
	{
		// Search for the user's node and then attach an attribute(sub-child) to that user
		for(int i=0; i < user_tree_table_model.getChildCount(user_tree_table_root); i++)
		{
			UserTreeTableNode node = (UserTreeTableNode)user_tree_table_model.getChild(user_tree_table_root, i);
			if(node.getName().equals(username))
			{
				node.getChildren().add(new UserTreeTableNode(attribute_name, ATTRIBUTE_TYPE, authority_name, false, 0, ""));
				return true;
			}
		}

		return false;
	}

	public void repaint()
	{
		user_tree_table_model = new UserTreeTableModel(user_tree_table_root);
		user_tree_table       = new JXTreeTable(user_tree_table_model);
		user_tree_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		System.gc();
	}

	public void clear_user_tree_table()
	{
		user_tree_table_root = new UserTreeTableNode("Root", ROOT_NODE_TYPE, "null", false, 0, "null");
	}

	public JXTreeTable get_user_tree_table()
	{
		return user_tree_table;
	}

	public UserTreeTableModel get_user_tree_table_model()
	{
		return user_tree_table_model;
	}

	public UserTreeTableNode get_user_tree_table_root()
	{
		return user_tree_table_root;
	}

	public int get_selected_row()
	{
		int row = user_tree_table.convertRowIndexToModel(user_tree_table.getSelectedRow());
		if(row < 0)
			return row;

		int base             = 0;
		int actual_row       = 0;
		int child_root_count = user_tree_table_model.getChildCount(user_tree_table_root);

		for(int i=0; i < child_root_count && base != row; i++)
		{
			UserTreeTableNode node = (UserTreeTableNode)user_tree_table_model.getChild(user_tree_table_root, i);
			int child_sub_root_count = user_tree_table_model.getChildCount(node);

			if(user_tree_table.isExpanded(base) == false)
			{
				actual_row += child_sub_root_count+1;
				base++;
			}
			else
			{
				if(child_sub_root_count+1 <= row-base)
				{
					actual_row += child_sub_root_count+1;
					base       += child_sub_root_count+1;
				}
				else
				{
					actual_row += row-base;
					base       = row;
				}
			}
		}

		return actual_row;
	}
}



