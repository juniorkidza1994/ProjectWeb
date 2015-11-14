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

class AdminTransactionAuditing extends JDialog implements ConstantVars
{
	private static final long serialVersionUID = -1113582265825921754L;

	// Declaration of the Native C functions
	private native void uninit_backend();
	private native void audit_all_transaction_logs_main(boolean audit_admin_log_flag, boolean audit_login_log_flag);
	private native void audit_some_period_time_transaction_logs_main(boolean audit_admin_log_flag, 
		boolean audit_login_log_flag, String start_date_time, String end_date_time);

	// Variables
	private JPanel             main_panel                   = new JPanel();
	private JButton            close_button                 = new JButton("Close");

	private DefaultTableModel  transaction_log_table_model;
	private JTable             transaction_log_table;

	private TransactionLogType transaction_log_type;
	private ConfirmSignal      confirm_dialg_exiting;

	public AdminTransactionAuditing(Component parent, TransactionLogType transaction_log_type, ConfirmSignal confirm_dialg_exiting)
	{
		this.transaction_log_type  = transaction_log_type;
		this.confirm_dialg_exiting = confirm_dialg_exiting;
	
		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent);
		setup_actions();

		switch(transaction_log_type)
		{
			case ADMIN_LOGIN_LOG:

				// Call to C function
				audit_all_transaction_logs_main(true, true);
				break;

			case ADMIN_EVENT_LOG:

				// Call to C function
				audit_all_transaction_logs_main(true, false);
				break;
	
			case SYSTEM_LOGIN_LOG:

				// Call to C function
				audit_all_transaction_logs_main(false, true);
				break;

			case SYSTEM_EVENT_LOG:

				// Call to C function
				audit_all_transaction_logs_main(false, false);
				break;
		}
	}

	// WEB

	public AdminTransactionAuditing(TransactionLogType transaction_log_type)
	{
		this.transaction_log_type  = transaction_log_type;

		init_transaction_log_table();
	
		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");

		switch(transaction_log_type)
		{
			case ADMIN_LOGIN_LOG:

				// Call to C function
				audit_all_transaction_logs_main(true, true);
				break;

			case ADMIN_EVENT_LOG:

				// Call to C function
				audit_all_transaction_logs_main(true, false);
				break;
	
			case SYSTEM_LOGIN_LOG:

				// Call to C function
				audit_all_transaction_logs_main(false, true);
				break;

			case SYSTEM_EVENT_LOG:

				// Call to C function
				audit_all_transaction_logs_main(false, false);
				break;
		}
	}

	public Object[][] getTableLog() {

	    DefaultTableModel dtm = transaction_log_table_model;
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	private final void init_ui(Component parent)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		int dialog_width_size = get_dialog_width_size();

		// Transaction log type
		JLabel transaction_log_type_label = new JLabel("Transaction log type: ", JLabel.RIGHT);

		JTextField transaction_log_type_textfield = new JTextField(TEXTFIELD_LENGTH);
		transaction_log_type_textfield.setText(get_transaction_log_type());
		transaction_log_type_textfield.setEnabled(false);

		JPanel transaction_log_type_inner_panel = new JPanel(new SpringLayout());
		transaction_log_type_inner_panel.add(transaction_log_type_label);
		transaction_log_type_inner_panel.add(transaction_log_type_textfield);

		SpringUtilities.makeCompactGrid(transaction_log_type_inner_panel, 1, 2, 5, 10, 10, 0);

		JPanel transaction_log_type_outer_panel = new JPanel();
		transaction_log_type_outer_panel.setLayout(new BoxLayout(transaction_log_type_outer_panel, BoxLayout.X_AXIS));
		transaction_log_type_outer_panel.setPreferredSize(new Dimension(400, 35));
		transaction_log_type_outer_panel.setMaximumSize(new Dimension(400, 35));
		transaction_log_type_outer_panel.setAlignmentX(0.0f);
		transaction_log_type_outer_panel.add(transaction_log_type_inner_panel);

		// Audit all transactions checkbox
		JCheckBox audit_all_transactions_checkbox = new JCheckBox("Audit all transactions", true);
        	audit_all_transactions_checkbox.setFocusable(false);
		audit_all_transactions_checkbox.setAlignmentX(0.0f);
		audit_all_transactions_checkbox.setEnabled(false);

		JPanel audit_all_transactions_checkbox_panel = new JPanel();
		audit_all_transactions_checkbox_panel.setLayout(new BoxLayout(audit_all_transactions_checkbox_panel, BoxLayout.X_AXIS));
		audit_all_transactions_checkbox_panel.setPreferredSize(new Dimension(400, 30));
		audit_all_transactions_checkbox_panel.setMaximumSize(new Dimension(400, 30));
		audit_all_transactions_checkbox_panel.setAlignmentX(0.0f);
		audit_all_transactions_checkbox_panel.add(audit_all_transactions_checkbox);

		// Transaction logs
		JLabel transaction_log_label = (transaction_log_type == TransactionLogType.ADMIN_LOGIN_LOG 
			|| transaction_log_type == TransactionLogType.SYSTEM_LOGIN_LOG) ? new JLabel("Login Logs") : new JLabel("Event Logs");

		init_transaction_log_table();

		JScrollPane transaction_log_table_panel = new JScrollPane();
		transaction_log_table_panel.setPreferredSize(new Dimension(dialog_width_size, 200));
		transaction_log_table_panel.setMaximumSize(new Dimension(dialog_width_size, 200));
		transaction_log_table_panel.setAlignmentX(0.0f);
		transaction_log_table_panel.getViewport().add(transaction_log_table);
		
		// Button
		close_button.setAlignmentX(0.5f);

		JPanel close_button_panel = new JPanel();
		close_button_panel.setPreferredSize(new Dimension(dialog_width_size, 30));
		close_button_panel.setMaximumSize(new Dimension(dialog_width_size, 30));
		close_button_panel.setAlignmentX(0.0f);
		close_button_panel.add(close_button);		

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(transaction_log_type_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 5)));
		main_panel.add(audit_all_transactions_checkbox_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 5)));
		main_panel.add(transaction_log_label);
		main_panel.add(Box.createRigidArea(new Dimension(0, 2)));
		main_panel.add(transaction_log_table_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 5)));
		main_panel.add(close_button_panel);		

		setModalityType(ModalityType.MODELESS);
		setModalExclusionType(ModalExclusionType.TOOLKIT_EXCLUDE);

		add(main_panel);

		setTitle("Transaction Auditing");
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
		setVisible(true);
	}

	public AdminTransactionAuditing(Component parent, TransactionLogType transaction_log_type, int start_year_index, int start_month_index, int start_day_index, 
		int start_hour_index, int start_minute_index, int end_year_index, int end_month_index, int end_day_index, int end_hour_index, 
		int end_minute_index, ConfirmSignal confirm_dialg_exiting)
	{
		this.transaction_log_type  = transaction_log_type;
		this.confirm_dialg_exiting = confirm_dialg_exiting;
	
		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_ui(parent, start_year_index, start_month_index, start_day_index, start_hour_index, 
			start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, end_minute_index);

		setup_actions();

		String start_date_time;  // 'YYYY-MM-DD HH:MM:SS'
		String end_date_time;    // 'YYYY-MM-DD HH:MM:SS'
		
		start_date_time = String.format("%04d-%02d-%02d %02d:%02d:00", LOWER_BOUND_AUDITING_YEAR + start_year_index, 
			start_month_index + 1, start_day_index + 1, start_hour_index, start_minute_index);

		end_date_time = String.format("%04d-%02d-%02d %02d:%02d:00", LOWER_BOUND_AUDITING_YEAR + end_year_index, 
			end_month_index + 1, end_day_index + 1, end_hour_index, end_minute_index);

		switch(transaction_log_type)
		{
			case ADMIN_LOGIN_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(true, true, start_date_time, end_date_time);
				break;

			case ADMIN_EVENT_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(true, false, start_date_time, end_date_time);
				break;
	
			case SYSTEM_LOGIN_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(false, true, start_date_time, end_date_time);
				break;

			case SYSTEM_EVENT_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(false, false, start_date_time, end_date_time);
				break;
		}
	}

	// WEB
	public AdminTransactionAuditing(TransactionLogType transaction_log_type, int start_year_index, int start_month_index, int start_day_index, 
		int start_hour_index, int start_minute_index, int end_year_index, int end_month_index, int end_day_index, int end_hour_index, 
		int end_minute_index)
	{
		this.transaction_log_type  = transaction_log_type;
		this.confirm_dialg_exiting = confirm_dialg_exiting;
	
		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");
			
		init_transaction_log_table();

		String start_date_time;  // 'YYYY-MM-DD HH:MM:SS'
		String end_date_time;    // 'YYYY-MM-DD HH:MM:SS'
		
		start_date_time = String.format("%04d-%02d-%02d %02d:%02d:00", LOWER_BOUND_AUDITING_YEAR + start_year_index, 
			start_month_index + 1, start_day_index + 1, start_hour_index, start_minute_index);

		end_date_time = String.format("%04d-%02d-%02d %02d:%02d:00", LOWER_BOUND_AUDITING_YEAR + end_year_index, 
			end_month_index + 1, end_day_index + 1, end_hour_index, end_minute_index);

		switch(transaction_log_type)
		{
			case ADMIN_LOGIN_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(true, true, start_date_time, end_date_time);
				break;

			case ADMIN_EVENT_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(true, false, start_date_time, end_date_time);
				break;
	
			case SYSTEM_LOGIN_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(false, true, start_date_time, end_date_time);
				break;

			case SYSTEM_EVENT_LOG:

				// Call to C function
				audit_some_period_time_transaction_logs_main(false, false, start_date_time, end_date_time);
				break;
		}
	}

	private final void init_ui(Component parent, int start_year_index, int start_month_index, int start_day_index, int start_hour_index, 
		int start_minute_index, int end_year_index, int end_month_index, int end_day_index, int end_hour_index, int end_minute_index)
	{
		setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

		int dialog_width_size = get_dialog_width_size();

		// Transaction log type
		JLabel transaction_log_type_label = new JLabel("Transaction log type: ", JLabel.RIGHT);

		JTextField transaction_log_type_textfield = new JTextField(TEXTFIELD_LENGTH);
		transaction_log_type_textfield.setText(get_transaction_log_type());
		transaction_log_type_textfield.setEnabled(false);

		JPanel transaction_log_type_inner_panel = new JPanel(new SpringLayout());
		transaction_log_type_inner_panel.add(transaction_log_type_label);
		transaction_log_type_inner_panel.add(transaction_log_type_textfield);

		SpringUtilities.makeCompactGrid(transaction_log_type_inner_panel, 1, 2, 5, 10, 10, 0);

		JPanel transaction_log_type_outer_panel = new JPanel();
		transaction_log_type_outer_panel.setLayout(new BoxLayout(transaction_log_type_outer_panel, BoxLayout.X_AXIS));
		transaction_log_type_outer_panel.setPreferredSize(new Dimension(400, 35));
		transaction_log_type_outer_panel.setMaximumSize(new Dimension(400, 35));
		transaction_log_type_outer_panel.setAlignmentX(0.0f);
		transaction_log_type_outer_panel.add(transaction_log_type_inner_panel);

		// Start date
		JLabel start_date_label = new JLabel("Start date: ", JLabel.TRAILING);
	
		JComboBox start_year_combobox = new JComboBox();
		build_year(start_year_combobox, start_year_index);
		start_year_combobox.setSelectedIndex(0);
		start_year_combobox.setEnabled(false);

		JComboBox start_month_combobox = new JComboBox();
		build_month(start_month_combobox, start_month_index);
		start_month_combobox.setSelectedIndex(0);
		start_month_combobox.setEnabled(false);

		JComboBox start_day_combobox = new JComboBox();
		build_day(start_day_combobox, start_day_index);
		start_day_combobox.setSelectedIndex(0);
		start_day_combobox.setEnabled(false);

		// Start time
		JComboBox start_hour_combobox = new JComboBox();
		build_hour(start_hour_combobox, start_hour_index);
		start_hour_combobox.setSelectedIndex(0);
		start_hour_combobox.setEnabled(false);

		JComboBox start_minute_combobox = new JComboBox();
		build_minute(start_minute_combobox, start_minute_index);
		start_minute_combobox.setSelectedIndex(0);
		start_minute_combobox.setEnabled(false);

		// End date
		JLabel end_date_label = new JLabel("End date: ", JLabel.TRAILING);

		JComboBox end_year_combobox = new JComboBox();
		build_year(end_year_combobox, end_year_index);
		end_year_combobox.setSelectedIndex(0);
		end_year_combobox.setEnabled(false);

		JComboBox end_month_combobox = new JComboBox();
		build_month(end_month_combobox, end_month_index);
		end_month_combobox.setSelectedIndex(0);
		end_month_combobox.setEnabled(false);

		JComboBox end_day_combobox = new JComboBox();
		build_day(end_day_combobox, end_day_index);
		end_day_combobox.setSelectedIndex(0);
		end_day_combobox.setEnabled(false);

		// End time
		JComboBox end_hour_combobox = new JComboBox();
		build_hour(end_hour_combobox, end_hour_index);
		end_hour_combobox.setSelectedIndex(0);
		end_hour_combobox.setEnabled(false);

		JComboBox end_minute_combobox = new JComboBox();
		build_minute(end_minute_combobox, end_minute_index);
		end_minute_combobox.setSelectedIndex(0);
		end_minute_combobox.setEnabled(false);

		JPanel datetime_comboboxes_inner_panel = new JPanel(new SpringLayout());
		datetime_comboboxes_inner_panel.add(start_date_label);
		datetime_comboboxes_inner_panel.add(start_month_combobox);
		datetime_comboboxes_inner_panel.add(start_day_combobox);
		datetime_comboboxes_inner_panel.add(start_year_combobox);

		datetime_comboboxes_inner_panel.add(new JLabel(""));
		datetime_comboboxes_inner_panel.add(start_hour_combobox);
		datetime_comboboxes_inner_panel.add(start_minute_combobox);
		datetime_comboboxes_inner_panel.add(new JLabel(""));

		datetime_comboboxes_inner_panel.add(end_date_label);
		datetime_comboboxes_inner_panel.add(end_month_combobox);
		datetime_comboboxes_inner_panel.add(end_day_combobox);
		datetime_comboboxes_inner_panel.add(end_year_combobox);

		datetime_comboboxes_inner_panel.add(new JLabel(""));
		datetime_comboboxes_inner_panel.add(end_hour_combobox);
		datetime_comboboxes_inner_panel.add(end_minute_combobox);
		datetime_comboboxes_inner_panel.add(new JLabel(""));
		
		SpringUtilities.makeCompactGrid(datetime_comboboxes_inner_panel, 4, 4, 5, 0, 10, 10);

		JPanel datetime_comboboxes_outer_panel = new JPanel();
		datetime_comboboxes_outer_panel.setLayout(new BoxLayout(datetime_comboboxes_outer_panel, BoxLayout.X_AXIS));
		datetime_comboboxes_outer_panel.setPreferredSize(new Dimension(500, 130));
		datetime_comboboxes_outer_panel.setMaximumSize(new Dimension(500, 130));
		datetime_comboboxes_outer_panel.setAlignmentX(0.0f);
		datetime_comboboxes_outer_panel.add(datetime_comboboxes_inner_panel);

		// Transaction logs
		JLabel transaction_log_label = (transaction_log_type == TransactionLogType.ADMIN_LOGIN_LOG 
			|| transaction_log_type == TransactionLogType.SYSTEM_LOGIN_LOG) ? new JLabel("Login Logs") : new JLabel("Event Logs");

		init_transaction_log_table();

		JScrollPane transaction_log_table_panel = new JScrollPane();
		transaction_log_table_panel.setPreferredSize(new Dimension(dialog_width_size, 200));
		transaction_log_table_panel.setMaximumSize(new Dimension(dialog_width_size, 200));
		transaction_log_table_panel.setAlignmentX(0.0f);
		transaction_log_table_panel.getViewport().add(transaction_log_table);
		
		// Button
		close_button.setAlignmentX(0.5f);

		JPanel close_button_panel = new JPanel();
		close_button_panel.setPreferredSize(new Dimension(dialog_width_size, 30));
		close_button_panel.setMaximumSize(new Dimension(dialog_width_size, 30));
		close_button_panel.setAlignmentX(0.0f);
		close_button_panel.add(close_button);		

		// Main panel
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));
		main_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));

		main_panel.add(transaction_log_type_outer_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(datetime_comboboxes_outer_panel);
		main_panel.add(transaction_log_label);
		main_panel.add(Box.createRigidArea(new Dimension(0, 2)));
		main_panel.add(transaction_log_table_panel);
		main_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		main_panel.add(close_button_panel);		

		setModalityType(ModalityType.MODELESS);
		setModalExclusionType(ModalExclusionType.TOOLKIT_EXCLUDE);

		add(main_panel);

		setTitle("Transaction Auditing");
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		pack();
		setLocationRelativeTo(parent);
		setResizable(false);
		setVisible(true);
	}

	private int get_dialog_width_size()
	{
		switch(transaction_log_type)
		{
			case ADMIN_LOGIN_LOG:
				return 550;

			case ADMIN_EVENT_LOG:
				return 900;
	
			case SYSTEM_LOGIN_LOG:
				return 700;

			case SYSTEM_EVENT_LOG:
			default:
				return 900;
		}
	}

	private String get_transaction_log_type()
	{
		switch(transaction_log_type)
		{
			case ADMIN_LOGIN_LOG:
				return "Admin login log";

			case ADMIN_EVENT_LOG:
				return "Admin event log";
	
			case SYSTEM_LOGIN_LOG:
				return "System login log";

			case SYSTEM_EVENT_LOG:
			default:
				return "System event log";
		}
	}

	private void init_transaction_log_table()
	{
		if(transaction_log_type == TransactionLogType.ADMIN_LOGIN_LOG)
		{
			transaction_log_table_model = new DefaultTableModel()
			{
				private static final long serialVersionUID = -1113582265865921793L;

				@Override
	    			public boolean isCellEditable(int row, int column)
				{
	       				return false;
	    			}
			};

	    		transaction_log_table_model.setDataVector(null, new Object[] {"Datetime", "Event type", "IP address"});
	    		transaction_log_table = new JTable(transaction_log_table_model);
			transaction_log_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		}
		else if(transaction_log_type == TransactionLogType.SYSTEM_LOGIN_LOG)
		{
			transaction_log_table_model = new DefaultTableModel()
			{
				private static final long serialVersionUID = -1113582265865921793L;

				@Override
	    			public boolean isCellEditable(int row, int column)
				{
	       				return false;
	    			}
			};

	    		transaction_log_table_model.setDataVector(null, new Object[] {"Datetime", "Username", "Event type", "IP address"});
	    		transaction_log_table = new JTable(transaction_log_table_model);
			transaction_log_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		}
		else  // Event log (TransactionLogType.ADMIN_EVENT_LOG or TransactionLogType.SYSTEM_EVENT_LOG)
		{
			transaction_log_table_model = new DefaultTableModel()
			{
				private static final long serialVersionUID = -1113582265865921793L;

				@Override
	    			public boolean isCellEditable(int row, int column)
				{
	       				return false;
	    			}
			};

	    		transaction_log_table_model.setDataVector(null, new Object[] {"Date/time", "Actor", "Event", "Object(user)", "Object", "Actor's IP address"});
	    		transaction_log_table = new JTable(transaction_log_table_model);
			transaction_log_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		}
	}

	private void build_year(JComboBox year_combobox, int year_index)
	{
		year_combobox.addItem(Integer.toString(LOWER_BOUND_AUDITING_YEAR + year_index));
	}

	private void build_month(JComboBox month_combobox, int month_index)
	{
		final String[] MONTH_LIST = {"January", "February", "March", "April", "May", 
			"June", "July", "August", "September", "October", "November", "December"};

		month_combobox.addItem(MONTH_LIST[month_index]);
	}

	private void build_day(JComboBox day_combobox, int day_index)
	{
		day_combobox.addItem(Integer.toString(day_index + 1));
	}

	private void build_hour(JComboBox hour_combobox, int hour_index)
	{
		if(hour_index < 10)
			hour_combobox.addItem("0" + Integer.toString(hour_index));
		else
			hour_combobox.addItem(Integer.toString(hour_index));
	}

	private void build_minute(JComboBox minute_combobox, int minute_index)
	{
		if(minute_index < 10)
			minute_combobox.addItem("0" + Integer.toString(minute_index));
		else
			minute_combobox.addItem(Integer.toString(minute_index));
	}

	private final void setup_actions()
	{
		// Set an event for close button
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter()
		{
            		@Override
            		public void windowClosing(final WindowEvent e)
			{
				// Send an exiting signal
				confirm_dialg_exiting.send_signal();

		        	dispose();
            		}
        	});

		// Close button
		close_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						close_button.setEnabled(false);
			
						// Send an exiting signal
						confirm_dialg_exiting.send_signal();

		        			dispose();
					}
				});
		    	}
		});
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

	private synchronized void add_transaction_admin_login_log_to_table_callback_handler(final String date_time, final String ip_address, final boolean is_logout_flag)
	{
		transaction_log_table_model.insertRow(transaction_log_table.getRowCount(), new Object[] 
			{date_time, (is_logout_flag) ? "logout" : "login", ip_address});	
	}

	private synchronized void add_transaction_system_login_log_to_table_callback_handler(final String date_time, final String username, 
		final String user_authority_name, final boolean is_admin_flag, final String ip_address, final boolean is_logout_flag)
	{
		final String INVALID_USERNAME = "invalid_user";
		String       username_full;

		if(username.equals(INVALID_USERNAME))
		{
			username_full = INVALID_USERNAME;
		}
		else
		{
			username_full = user_authority_name + "." + username;
			if(is_admin_flag)
				username_full += "(admin)";
		}

		transaction_log_table_model.insertRow(transaction_log_table.getRowCount(), new Object[] 
			{date_time, username_full, (is_logout_flag) ? "logout" : "login", ip_address});	
	}

	private synchronized void add_transaction_event_log_to_table_callback_handler(final String date_time, final String actor_name, 
		final String actor_authority_name, final boolean is_actor_admin_flag, final String object_description, final String event_description, 
		final String object_owner_name, final String object_owner_authority_name, final boolean is_object_owner_admin_flag, final String actor_ip_address)
	{
		final String NO_REFERENCE_USERNAME = "no_reference_user";
		final String PASSWD_FORGETTOR_NAME = "password_forgettor";
		final String ITS_ADMIN_NAME        = "its_administrator";

		String       actor;
		String       object_owner;

		if(actor_name.equals(NO_REFERENCE_USERNAME))
		{
			actor = "-";
		}
		else if(actor_name.equals(PASSWD_FORGETTOR_NAME))
		{
			actor = PASSWD_FORGETTOR_NAME;
		}
		else if(actor_name.equals(ITS_ADMIN_NAME))
		{
			actor = actor_authority_name + "'s admin";
		}
		else
		{
			actor = actor_authority_name + "." + actor_name;
			if(is_actor_admin_flag)
				actor += "(admin)";
		}

		if(object_owner_name.equals(NO_REFERENCE_USERNAME))
		{
			object_owner = "-";
		}
		else
		{
			object_owner = object_owner_authority_name + "." + object_owner_name;
			if(is_object_owner_admin_flag)
				object_owner += "(admin)";
		}

		transaction_log_table_model.insertRow(transaction_log_table.getRowCount(), new Object[] 
			{date_time, actor, event_description, object_owner, object_description, actor_ip_address});	
	}
}



