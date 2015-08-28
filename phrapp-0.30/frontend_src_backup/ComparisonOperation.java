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

public enum ComparisonOperation
{
 	MORETHAN, MORETHAN_OR_EQUAL, LESSTHAN, LESSTHAN_OR_EQUAL, EQUAL;
 
 	@Override public String toString()
	{
		String operation_name = super.toString();
		if(operation_name.equals("MORETHAN"))
		{
			return ">";
		}
		else if(operation_name.equals("MORETHAN_OR_EQUAL"))
		{
			return ">=";
		}
		else if(operation_name.equals("LESSTHAN"))
		{
			return "<";
		}
		else if(operation_name.equals("LESSTHAN_OR_EQUAL"))
		{
			return "<=";
		}
		else
		{
			return "=";
		}
	}
}



