import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import java.util.regex.*;
import javax.swing.border.*;

import java.io.*;

import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.*;

import org.jdesktop.swingx.*;
import org.jdesktop.swingx.treetable.*;

import org.apache.commons.lang3.*;

class ConfirmSignal
{
	private boolean locked;
 
  	public ConfirmSignal()
	{
    		locked = true;
 	}
 
  	public synchronized void wait_signal() throws InterruptedException
	{
    		while(locked)
      			wait();

		locked = true;
 	}
 
  	public synchronized void send_signal()
	{
    		if(locked)
      			notify();

    		locked = false;
  	}
}



