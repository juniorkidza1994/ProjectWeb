import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.lang.*;
import java.util.regex.*;
import javax.swing.border.*;

public class ShutdownHook extends Thread
{
	// Declaration of the Native C functions
	private native void record_transaction_logout_log(String username);
	private native void uninit_backend();

	// Variable
	private String username;

	public ShutdownHook(String username)
	{
		this.username = new String(username);
	}

	public void run()
	{
		// Call to C functions
		record_transaction_logout_log(username);
		uninit_backend();
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		//JOptionPane.showMessageDialog(null, alert_msg);
		System.out.println(alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Notify alert message to user and then terminate the application
		//JOptionPane.showMessageDialog(null, alert_msg);
		//System.exit(1);
		System.out.println(alert_msg);
	}
}



