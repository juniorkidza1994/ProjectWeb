import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.lang.*;
import java.util.regex.*;
import javax.swing.border.*;

public class EmU_ShutdownHook extends Thread
{
	// Declaration of the Native C functions
	private native void uninit_backend();

	public EmU_ShutdownHook()
	{
	}

	public void run()
	{
		// Call to C functions
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



