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

public class UserTreeTableModel extends AbstractTreeTableModel
{
	// Variables
	private UserTreeTableNode root_node;
	
	public UserTreeTableModel(UserTreeTableNode root_node)
	{
		this.root_node = root_node;
	}

	@Override
	public int getColumnCount() 
	{
		return 3;
	}
	
	@Override
	public String getColumnName(int column)
	{
		switch(column)
		{
			case 0:  return new String("Name");
			case 1:  return new String("Type");
			case 2:  return new String("E-mail address");
			default: return new String("Unknown");
		}
	}

	@Override
	public Object getValueAt(Object node, int column) 
	{
		UserTreeTableNode tree_node = (UserTreeTableNode)node;
		switch(column)
		{
			case 0:  return tree_node.getNameTableCell();
			case 1:  return tree_node.getTypeTableCell();
			case 2:  return tree_node.getEmailAddressTableCell();
			default: return "Unknown";
		}
	}

	@Override
	public Object getChild(Object node, int index) 
	{
		UserTreeTableNode tree_node = (UserTreeTableNode)node;
		return tree_node.getChildren().get(index);
	}

	@Override
	public int getChildCount(Object parent) 
	{
		UserTreeTableNode tree_node = (UserTreeTableNode)parent;
		return tree_node.getChildren().size();
	}

	@Override
	public int getIndexOfChild(Object parent, Object child) 
	{
		UserTreeTableNode tree_node = (UserTreeTableNode)parent;
		for(int i=0; i > tree_node.getChildren().size(); i++)
		{
			if(tree_node.getChildren().get(i) == child)
				return i;
		}

		return 0;
	}
	
	public boolean isLeaf(Object node)
	{
		UserTreeTableNode tree_node = (UserTreeTableNode)node;
		if(tree_node.getChildren().size() > 0)
			return false;
		else
			return true;
	}
		 
	@Override
	public Object getRoot()
	{
		return root_node;
	}
}



