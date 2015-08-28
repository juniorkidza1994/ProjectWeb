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

public class AccessPolicyTree extends JPanel implements ConstantVars
{
	private static final long      serialVersionUID = -1513582265865921795L;

    	private DefaultMutableTreeNode root_node;
    	private DefaultTreeModel       tree_model;
    	private JTree                  tree;
	private JScrollPane            main_panel;

	private boolean                first_branch_of_policy;
	private StringBuffer           access_policy;

    	public AccessPolicyTree()
	{
		super(new GridLayout(1, 0));
		init_ui();
    	}

	private void init_ui()
	{
        	root_node  = new DefaultMutableTreeNode("Root of access policy");
        	tree_model = new DefaultTreeModel(root_node);
        	tree       = new JTree(tree_model);
		tree.setSelectionRow(0);           // Focus on root node at first
        	tree.setEditable(false);
        	tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        	tree.setShowsRootHandles(true);

		DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
		Icon icon = null;
		renderer.setLeafIcon(icon);
		renderer.setClosedIcon(icon);
		renderer.setOpenIcon(icon);
		tree.setCellRenderer(renderer);

		main_panel = new JScrollPane(tree);
		add(main_panel);
	}

	public DefaultMutableTreeNode add_attribute_to_selected_branch(final String authority_name, final String attribute_name)
	{
		Object                 child       = "Attribute: " + authority_name + "." + attribute_name;
        	DefaultMutableTreeNode parent_node = null;
        	TreePath               parent_path = tree.getSelectionPath();

        	if(parent_path == null)
            		parent_node = root_node;
        	else
            		parent_node = (DefaultMutableTreeNode)(parent_path.getLastPathComponent());

		return add_object(parent_node, child);
	}

	public DefaultMutableTreeNode add_attribute_to_selected_branch(final String authority_name, 
		final String attribute_name, final ComparisonOperation operation, int attribute_value)
	{
		Object                 child       = "Attribute: " + authority_name + "." + attribute_name + " " + operation.toString() + " " + attribute_value;
        	DefaultMutableTreeNode parent_node = null;
        	TreePath               parent_path = tree.getSelectionPath();

        	if(parent_path == null)
            		parent_node = root_node;
        	else
            		parent_node = (DefaultMutableTreeNode)(parent_path.getLastPathComponent());

		return add_object(parent_node, child);
	}

	public DefaultMutableTreeNode add_user_to_selected_branch(final String authority_name, final String username)
	{
		Object                 child       = "User: " + authority_name + "." + username;
        	DefaultMutableTreeNode parent_node = null;
        	TreePath               parent_path = tree.getSelectionPath();

        	if(parent_path == null)
            		parent_node = root_node;
        	else
            		parent_node = (DefaultMutableTreeNode)(parent_path.getLastPathComponent());

		return add_object(parent_node, child);
	}

	private DefaultMutableTreeNode add_object(DefaultMutableTreeNode parent, Object child)
	{
        	DefaultMutableTreeNode child_node = new DefaultMutableTreeNode(child);

		if(parent == null)
            		parent = root_node;
	
        	tree_model.insertNodeInto(child_node, parent, parent.getChildCount());

        	// Make sure the user can see the new node.
            	tree.scrollPathToVisible(new TreePath(child_node.getPath()));

        	return child_node;
    	}

	public void remove_selected_attribute_and_sub_attributes()
	{
        	TreePath current_selection = tree.getSelectionPath();
        	if(current_selection != null)
		{
            		DefaultMutableTreeNode current_node = (DefaultMutableTreeNode)(current_selection.getLastPathComponent());
            		MutableTreeNode        parent       = (MutableTreeNode)(current_node.getParent());
            			
			if(parent != null)
                		tree_model.removeNodeFromParent(current_node);
			
			tree.setSelectionRow(0);           // Focus on the root node
        	}
    	}

	public boolean did_user_specified_access_policy()
	{
		if(tree_model.getChildCount(root_node) > 0)
			return true;
		else
			return false;
	}

	public String transform_tree_to_access_policy()
	{
		if(tree_model.getChildCount(root_node) == 0)
		{
			// There is only a root node
			access_policy          = new StringBuffer("There is only a root node");
		}
		else
		{
			access_policy          = new StringBuffer("");
			first_branch_of_policy = true;

			transform_tree_to_access_policy(root_node);
		}

		return access_policy.toString();
	}

	private void transform_tree_to_access_policy(Object node)
	{
		int count = tree_model.getChildCount(node);
		for(int i=0; i < count; i++)
		{
			Object child = tree_model.getChild(node, i);

			if(tree_model.isLeaf(child))
			{
				if(!first_branch_of_policy)
					access_policy.append(" or ");

				first_branch_of_policy = false;

				boolean    first_node_of_branch = true;
				TreeNode[] full_path            = tree_model.getPathToRoot((TreeNode)child);

				for(TreeNode partial_path: full_path)
				{
					if(!partial_path.toString().equals("Root of access policy"))
					{
						String new_node = partial_path.toString();

						new_node = replace_string(new_node, "Attribute: ", "AttributeNode__SUB__");
						new_node = replace_string(new_node, "User: ", "UsernameNode__SUB__");
						new_node = replace_string(new_node, ".", "__SUB__");

						if(first_node_of_branch)
						{
							first_node_of_branch = false;
							access_policy.append("(" + new_node);
						}
						else
						{
							access_policy.append(" and " + new_node);
						}
					}
				}

				access_policy.append(")");
			}	
			else
			{
		   		transform_tree_to_access_policy(child);
			}
		}
	}

	private String replace_string(String str, String pattern, String replace)
	{
		int          s      = 0;
		int          e      = 0;
		StringBuffer result = new StringBuffer();

		while((e = str.indexOf(pattern, s)) >= 0)
		{
			result.append(str.substring(s, e));
			result.append(replace);
			s = e + pattern.length();
		}

		result.append(str.substring(s));
		return result.toString();
	}
		
	public JTree get_tree()
	{
		return tree;
	}

	public DefaultTreeModel get_tree_model()
	{
		return tree_model;
	}

	public boolean is_selected_node_editable_attribute()
	{
        	TreePath current_selection = tree.getSelectionPath();
        	if(current_selection != null)
		{
            		DefaultMutableTreeNode current_node = (DefaultMutableTreeNode)(current_selection.getLastPathComponent());
			if(current_node.toString().startsWith("Attribute: "))
			{ 
				if(current_node.toString().indexOf(" " + ComparisonOperation.MORETHAN.toString() + " ") > 0)
					return true;
				else if(current_node.toString().indexOf(" " + ComparisonOperation.MORETHAN_OR_EQUAL.toString() + " ") > 0)
					return true;
				else if(current_node.toString().indexOf(" " + ComparisonOperation.LESSTHAN.toString() + " ") > 0)
					return true;
				else if(current_node.toString().indexOf(" " + ComparisonOperation.LESSTHAN_OR_EQUAL.toString() + " ") > 0)
					return true;
				else if(current_node.toString().indexOf(" " + ComparisonOperation.EQUAL.toString() + " ") > 0)
					return true;
			}
        	}

		return false;
    	}

	public boolean is_selected_node_removable()
	{
        	TreePath current_selection = tree.getSelectionPath();
        	if(current_selection != null)
		{
            		DefaultMutableTreeNode current_node = (DefaultMutableTreeNode)(current_selection.getLastPathComponent());
            		MutableTreeNode        parent = (MutableTreeNode)(current_node.getParent());
            			
			if(parent != null)
                		return true;
        	}

		return false;
    	}

	public String get_selected_node_to_string()
	{
		TreePath current_selection = tree.getSelectionPath();
        	if(current_selection == null)
			return null;

		DefaultMutableTreeNode current_node = (DefaultMutableTreeNode)(current_selection.getLastPathComponent());
		return current_node.toString();
	}

	public void change_numerical_attribute_information_at_selected_node(final String authority_name, 
		final String attribute_name, final ComparisonOperation operation, int attribute_value)
	{
		TreePath current_selection = tree.getSelectionPath();
		if(current_selection == null)
			return;

		Object new_numerical_attribute = "Attribute: " + authority_name + "." + attribute_name + " " + operation.toString() + " " + attribute_value;
		tree_model.valueForPathChanged(current_selection, new_numerical_attribute);
	}
}



