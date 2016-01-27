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

public class AdminMain extends JFrame implements ConstantVars
{
	private static final long serialVersionUID = -1113582265865921788L;

	// Declaration of the Native C functions
	private native void init_backend();
	private native void store_variables_to_backend(String ssl_cert_hash, String username, 
		String authority_name, String passwd, String user_auth_ip_addr, String audit_server_ip_addr);
	private native void update_attribute_list_main();
	private native void update_user_list_main();
	private native void update_admin_list_main();
	private native void update_authority_list_main();
	private native boolean remove_attribute_main(String attribute_name);
	private native boolean reset_user_passwd_main(String username);
	private native boolean remove_user_main(String username);
	private native boolean remove_user_attribute_main(String username, String attribute_name, String attribute_authority_name);
	private native boolean reset_admin_passwd_main(String username);
	private native boolean remove_admin_main(String username);
	private native boolean remove_authority_main(String authority_name);

	// Variables
	private JPanel            main_panel                                   = new JPanel();
	private ReentrantLock     working_lock                                 = new ReentrantLock();
	private ShutdownHook      shutdown_hooker;

	// Info page
	private JPanel            info_outer_panel                             = new JPanel();
	private JScrollPane       info_scollpane_page                          = new JScrollPane(info_outer_panel);

	private JTextField        email_address_textfield                      = new JTextField(TEXTFIELD_LENGTH);

	private JButton           change_passwd_button                         = new JButton("Change a password");
	private JButton           change_email_address_button                  = new JButton("Change an e-mail address");

	private JTextField        audit_server_ip_address_textfield            = new JTextField(TEXTFIELD_LENGTH);
	private JTextField        phr_server_ip_address_textfield              = new JTextField(TEXTFIELD_LENGTH);
	private JTextField        emergency_server_ip_address_textfield        = new JTextField(TEXTFIELD_LENGTH);

	private JButton           change_server_addresses_configuration_button = new JButton("Change configuration");

	private JTextField        mail_server_url_textfield                    = new JTextField(TEXTFIELD_LENGTH);
	private JTextField        authority_email_address_textfield            = new JTextField(TEXTFIELD_LENGTH);

	private JButton           change_mail_server_configuration_button      = new JButton("Change configuration");

	// Attribute page
	private JPanel            attribute_page                               = new JPanel();
	private DefaultTableModel attribute_table_model;
	private JTable            attribute_table;

	private JButton           attribute_registration_button                = new JButton("Register an attribute");
	private JButton           attribute_removal_button                     = new JButton("Remove an attribute");
	private JButton           attribute_page_refresh_info_button           = new JButton("Refresh");

	// User page
	private JPanel            user_page                                    = new JPanel();
	private JScrollPane       user_tree_table_panel                        = new JScrollPane();
	private UserTreeTable     user_tree_table;

	private JButton           user_registration_button                     = new JButton("Register a user");
	private JButton           user_or_user_attribute_editing_button        = new JButton("Edit");
	private JButton           user_passwd_resetting_button                 = new JButton("Reset a password");
	private JButton           user_or_user_attribute_removal_button        = new JButton("Remove");
	private JButton           user_page_refresh_info_button                = new JButton("Refresh");

	// Admin page
	private JPanel            admin_page                                   = new JPanel();
	private DefaultTableModel admin_table_model;
	private JTable            admin_table;

	private JButton           admin_registration_button                    = new JButton("Register an admin");
	private JButton           admin_editing_button                         = new JButton("Edit");
	private JButton           admin_passwd_resetting_button                = new JButton("Reset a password");
	private JButton           admin_removal_button                         = new JButton("Remove");
	private JButton           admin_page_refresh_info_button               = new JButton("Refresh");

	// Authority page
	private JPanel            authority_page                               = new JPanel();
	private DefaultTableModel authority_table_model;
	private JTable            authority_table;

	private JButton           authority_registration_button                = new JButton("Register an authority");
	private JButton           authority_removal_button                     = new JButton("Remove");
	private JButton           authority_editing_button                     = new JButton("Edit");
	private JButton           authority_page_refresh_info_button           = new JButton("Refresh");
	
	// Transaction auditing page
	private JPanel            transaction_auditing_page                    = new JPanel();

	private JRadioButton[]    transaction_log_type_radio_buttons           = new JRadioButton[4];
       	private ButtonGroup       transaction_log_type_group;
        private final String      transaction_admin_login_log_type             = new String("Audit an admin login Log");
        private final String      transaction_admin_event_log_type             = new String("Audit an admin event Log");
	private final String      transaction_system_login_log_type            = new String("Audit a system login Log");
        private final String      transaction_system_event_log_type            = new String("Audit a system event Log");

	private JCheckBox         audit_all_transactions_checkbox              = new JCheckBox("Audit all transactions", true);

	private Calendar          start_date_calendar                          = Calendar.getInstance();
	private JComboBox         start_year_combobox;
	private JComboBox         start_month_combobox;
	private JComboBox         start_day_combobox;

	private JComboBox         start_hour_combobox;
	private JComboBox         start_minute_combobox;

	private Calendar          end_date_calendar                            = Calendar.getInstance();
	private JComboBox         end_year_combobox;
	private JComboBox         end_month_combobox;
	private JComboBox         end_day_combobox;

	private JComboBox         end_hour_combobox;
	private JComboBox         end_minute_combobox;

	private JButton           search_transaction_log_button                = new JButton("Search");

	private int               transaction_log_thread_counter               = 0;
	private ReentrantLock     transaction_log_thread_counter_lock          = new ReentrantLock();

	// Statusbar
	private JLabel            statusbar_label                              = new JLabel("");

	// Derive from Login object 
	private String            username;
	private String            passwd;
	private String            email_address;
	private String            authority_name;
	private String            user_auth_ip_addr;
	private String            audit_server_ip_addr;
	private String            phr_server_ip_addr;
	private String            emergency_server_ip_addr;
	private String            mail_server_url;
	private String            authority_email_address;
	private String            authority_email_passwd;

	// WEB
	private ArrayList<String> m_user_tree								   = new ArrayList<String>();// 100 Max element
	private boolean			  m_is_reset_admin_pwd;

	private boolean 		  m_result_reset_flag_user_pwd 				   = false;
	private boolean 		  m_result_reset_flag_admin_pwd 			   = false;
	private String 			  m_result_msg ;

	public AdminMain(String username, String passwd, String email_address, String authority_name, String user_auth_ip_addr, String audit_server_ip_addr, 
		String phr_server_ip_addr, String emergency_server_ip_addr, String mail_server_url, String authority_email_address, String authority_email_passwd, 
		String ssl_cert_hash)
	{
		super("PHR system: Admin Main");

		this.username                 = username;
		this.email_address            = email_address;
		this.passwd                   = passwd;
		this.authority_name           = authority_name;
		this.user_auth_ip_addr        = user_auth_ip_addr;
		this.audit_server_ip_addr     = audit_server_ip_addr;
		this.phr_server_ip_addr       = phr_server_ip_addr;
		this.emergency_server_ip_addr = emergency_server_ip_addr;
		this.mail_server_url          = mail_server_url;
		this.authority_email_address  = authority_email_address;
		this.authority_email_passwd   = authority_email_passwd;
		
		// Load JNI backend library
		System.loadLibrary("PHRapp_Admin_JNI");

		working_lock.lock();

		// Call to C functions
		init_backend();
		store_variables_to_backend(ssl_cert_hash, username, authority_name, passwd, user_auth_ip_addr, audit_server_ip_addr);

		// WEB
		initUserTable();

		init_ui();
		setup_actions();

		// Call to C functions
		update_attribute_list_main();
		update_user_list_main();
		update_admin_list_main();
		update_authority_list_main();

		working_lock.unlock();

		automatic_relogin();
	}

	private final void init_ui()
	{
		main_panel.setLayout(new BorderLayout());

		create_info_page();
		create_attribute_page();
		create_user_page();
		create_admin_page();
		create_authority_page();
		create_transaction_auditing_page();

		JTabbedPane tabbed_pane = new JTabbedPane();
		tabbed_pane.addTab("Info", info_scollpane_page);
		tabbed_pane.addTab("Attribute Management", attribute_page);
		tabbed_pane.addTab("User Management", user_page);
		tabbed_pane.addTab("Admin Management", admin_page);
		tabbed_pane.addTab("Authority Management", authority_page);
		tabbed_pane.addTab("Transaction Auditing", transaction_auditing_page);
		main_panel.add(tabbed_pane, BorderLayout.CENTER);
		main_panel.add(statusbar_label, BorderLayout.SOUTH);

		getContentPane().add(main_panel);

		setSize(600, 550);
		setLocationRelativeTo(null);
		setResizable(false);
		setVisible(true);
	}

	private final void create_info_page()
	{
		// Authority name
		JLabel authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);

		JTextField authority_name_textfield = new JTextField(TEXTFIELD_LENGTH);
		authority_name_textfield.setText(authority_name);
		authority_name_textfield.setEditable(false);

		// Username
		JLabel username_label = new JLabel("Username: ", JLabel.RIGHT);

		JTextField username_textfield = new JTextField(TEXTFIELD_LENGTH);
		username_textfield.setText(username + "(admin privilege)");
		username_textfield.setEditable(false);

		// Email address
		JLabel email_address_label = new JLabel("E-mail address: ", JLabel.RIGHT);

		email_address_textfield.setText(email_address);
		email_address_textfield.setEditable(false);

		JPanel basic_info_upper_inner_panel = new JPanel(new SpringLayout());
		basic_info_upper_inner_panel.add(authority_name_label);
		basic_info_upper_inner_panel.add(authority_name_textfield);
		basic_info_upper_inner_panel.add(username_label);
		basic_info_upper_inner_panel.add(username_textfield);
		basic_info_upper_inner_panel.add(email_address_label);
		basic_info_upper_inner_panel.add(email_address_textfield);

		SpringUtilities.makeCompactGrid(basic_info_upper_inner_panel, 3, 2, 5, 0, 10, 10);

		JPanel basic_info_upper_outer_panel = new JPanel();
		basic_info_upper_outer_panel.setLayout(new BoxLayout(basic_info_upper_outer_panel, BoxLayout.X_AXIS));
		basic_info_upper_outer_panel.setPreferredSize(new Dimension(430, 110));
		basic_info_upper_outer_panel.setMaximumSize(new Dimension(430, 110));
		basic_info_upper_outer_panel.setAlignmentX(0.0f);
		basic_info_upper_outer_panel.add(basic_info_upper_inner_panel);

		// Change password and e-mail address buttons
		change_passwd_button.setAlignmentX(0.5f);
		change_email_address_button.setAlignmentX(0.5f);

		JPanel basic_info_buttons_panel = new JPanel();
		basic_info_buttons_panel.setPreferredSize(new Dimension(430, 30));
		basic_info_buttons_panel.setMaximumSize(new Dimension(430, 30));
		basic_info_buttons_panel.setAlignmentX(0.0f);
		basic_info_buttons_panel.add(change_passwd_button);
		basic_info_buttons_panel.add(change_email_address_button);

		// Basic info panel
		JPanel basic_info_inner_panel = new JPanel();
		basic_info_inner_panel.setLayout(new BoxLayout(basic_info_inner_panel, BoxLayout.Y_AXIS));
		basic_info_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		basic_info_inner_panel.setPreferredSize(new Dimension(450, 190));
		basic_info_inner_panel.setMaximumSize(new Dimension(450, 190));
		basic_info_inner_panel.setAlignmentX(0.0f);
		basic_info_inner_panel.add(basic_info_upper_outer_panel);
		basic_info_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		basic_info_inner_panel.add(basic_info_buttons_panel);

		JPanel basic_info_outer_panel = new JPanel(new GridLayout(0, 1));
		basic_info_outer_panel.setLayout(new BoxLayout(basic_info_outer_panel, BoxLayout.Y_AXIS));
    		basic_info_outer_panel.setBorder(BorderFactory.createTitledBorder("Basic Info"));
		basic_info_outer_panel.setAlignmentX(0.5f);
		basic_info_outer_panel.add(basic_info_inner_panel);

		JPanel basic_info_panel = new JPanel();
		basic_info_panel.setPreferredSize(new Dimension(555, 230));
		basic_info_panel.setMaximumSize(new Dimension(555, 230));
		basic_info_panel.setAlignmentX(0.0f);
		basic_info_panel.add(basic_info_outer_panel);

		// Audit server's IP address
		JLabel audit_server_ip_address_label = new JLabel("Audit server's IP address: ", JLabel.RIGHT);

		audit_server_ip_address_textfield.setText(audit_server_ip_addr);
		audit_server_ip_address_textfield.setEditable(false);

		// PHR server's IP address
		JLabel phr_server_ip_address_label = new JLabel("PHR server's IP address: ", JLabel.RIGHT);

		phr_server_ip_address_textfield.setText(phr_server_ip_addr);
		phr_server_ip_address_textfield.setEditable(false);

		// Emergency server's IP address
		JLabel emergency_server_ip_address_label = new JLabel("Emergency server's IP address: ", JLabel.RIGHT);

		emergency_server_ip_address_textfield.setText(emergency_server_ip_addr);
		emergency_server_ip_address_textfield.setEditable(false);

		JPanel server_addresses_configuration_upper_inner_panel = new JPanel(new SpringLayout());
		server_addresses_configuration_upper_inner_panel.add(audit_server_ip_address_label);
		server_addresses_configuration_upper_inner_panel.add(audit_server_ip_address_textfield);
		server_addresses_configuration_upper_inner_panel.add(phr_server_ip_address_label);
		server_addresses_configuration_upper_inner_panel.add(phr_server_ip_address_textfield);
		server_addresses_configuration_upper_inner_panel.add(emergency_server_ip_address_label);
		server_addresses_configuration_upper_inner_panel.add(emergency_server_ip_address_textfield);
		
		SpringUtilities.makeCompactGrid(server_addresses_configuration_upper_inner_panel, 3, 2, 5, 0, 10, 10);

		JPanel server_addresses_configuration_upper_outer_panel = new JPanel();
		server_addresses_configuration_upper_outer_panel.setLayout(new BoxLayout(server_addresses_configuration_upper_outer_panel, BoxLayout.X_AXIS));
		server_addresses_configuration_upper_outer_panel.setPreferredSize(new Dimension(430, 113));
		server_addresses_configuration_upper_outer_panel.setMaximumSize(new Dimension(430, 113));
		server_addresses_configuration_upper_outer_panel.setAlignmentX(0.0f);
		server_addresses_configuration_upper_outer_panel.add(server_addresses_configuration_upper_inner_panel);

		// Change server addresses configuration button
		change_server_addresses_configuration_button.setAlignmentX(0.5f);

		JPanel server_addresses_configuration_button_panel = new JPanel();
		server_addresses_configuration_button_panel.setPreferredSize(new Dimension(430, 30));
		server_addresses_configuration_button_panel.setMaximumSize(new Dimension(430, 30));
		server_addresses_configuration_button_panel.setAlignmentX(0.0f);
		server_addresses_configuration_button_panel.add(change_server_addresses_configuration_button);

		// Server addresses configuration panel
		JPanel server_addresses_configuration_inner_panel = new JPanel();
		server_addresses_configuration_inner_panel.setLayout(new BoxLayout(server_addresses_configuration_inner_panel, BoxLayout.Y_AXIS));
		server_addresses_configuration_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		server_addresses_configuration_inner_panel.setPreferredSize(new Dimension(450, 193));
		server_addresses_configuration_inner_panel.setMaximumSize(new Dimension(450, 193));
		server_addresses_configuration_inner_panel.setAlignmentX(0.0f);
		server_addresses_configuration_inner_panel.add(server_addresses_configuration_upper_outer_panel);
		server_addresses_configuration_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		server_addresses_configuration_inner_panel.add(server_addresses_configuration_button_panel);

		JPanel server_addresses_configuration_outer_panel = new JPanel(new GridLayout(0, 1));
		server_addresses_configuration_outer_panel.setLayout(new BoxLayout(server_addresses_configuration_outer_panel, BoxLayout.Y_AXIS));
    		server_addresses_configuration_outer_panel.setBorder(BorderFactory.createTitledBorder("Server Addresses Configuration"));
		server_addresses_configuration_outer_panel.setAlignmentX(0.5f);
		server_addresses_configuration_outer_panel.add(server_addresses_configuration_inner_panel);

		JPanel server_addresses_configuration_panel = new JPanel();
		server_addresses_configuration_panel.setPreferredSize(new Dimension(555, 231));
		server_addresses_configuration_panel.setMaximumSize(new Dimension(555, 231));
		server_addresses_configuration_panel.setAlignmentX(0.0f);
		server_addresses_configuration_panel.add(server_addresses_configuration_outer_panel);

		// Mail server url
		JLabel mail_server_url_label = new JLabel("Mail server url: ", JLabel.RIGHT);

		mail_server_url_textfield.setText(mail_server_url);
		mail_server_url_textfield.setEditable(false);

		// Authority e-mail address
		JLabel authority_email_address_label = new JLabel("E-mail address: ", JLabel.RIGHT);

		authority_email_address_textfield.setText(authority_email_address);
		authority_email_address_textfield.setEditable(false);

		JPanel mail_server_configuration_upper_inner_panel = new JPanel(new SpringLayout());
		mail_server_configuration_upper_inner_panel.add(mail_server_url_label);
		mail_server_configuration_upper_inner_panel.add(mail_server_url_textfield);
		mail_server_configuration_upper_inner_panel.add(authority_email_address_label);
		mail_server_configuration_upper_inner_panel.add(authority_email_address_textfield);

		SpringUtilities.makeCompactGrid(mail_server_configuration_upper_inner_panel, 2, 2, 5, 0, 10, 10);

		JPanel mail_server_configuration_upper_outer_panel = new JPanel();
		mail_server_configuration_upper_outer_panel.setLayout(new BoxLayout(mail_server_configuration_upper_outer_panel, BoxLayout.X_AXIS));
		mail_server_configuration_upper_outer_panel.setPreferredSize(new Dimension(430, 75));
		mail_server_configuration_upper_outer_panel.setMaximumSize(new Dimension(430, 75));
		mail_server_configuration_upper_outer_panel.setAlignmentX(0.0f);
		mail_server_configuration_upper_outer_panel.add(mail_server_configuration_upper_inner_panel);

		// Change mail server configuration button
		change_mail_server_configuration_button.setAlignmentX(0.5f);

		JPanel change_mail_server_configuration_button_panel = new JPanel();
		change_mail_server_configuration_button_panel.setPreferredSize(new Dimension(430, 30));
		change_mail_server_configuration_button_panel.setMaximumSize(new Dimension(430, 30));
		change_mail_server_configuration_button_panel.setAlignmentX(0.0f);
		change_mail_server_configuration_button_panel.add(change_mail_server_configuration_button);

		// Mail server configuration panel
		JPanel mail_server_configuration_inner_panel = new JPanel();
		mail_server_configuration_inner_panel.setLayout(new BoxLayout(mail_server_configuration_inner_panel, BoxLayout.Y_AXIS));
		mail_server_configuration_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		mail_server_configuration_inner_panel.setPreferredSize(new Dimension(450, 155));
		mail_server_configuration_inner_panel.setMaximumSize(new Dimension(450, 155));
		mail_server_configuration_inner_panel.setAlignmentX(0.0f);
		mail_server_configuration_inner_panel.add(mail_server_configuration_upper_outer_panel);
		mail_server_configuration_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		mail_server_configuration_inner_panel.add(change_mail_server_configuration_button_panel);

		JPanel mail_server_configuration_outer_panel = new JPanel(new GridLayout(0, 1));
		mail_server_configuration_outer_panel.setLayout(new BoxLayout(mail_server_configuration_outer_panel, BoxLayout.Y_AXIS));
    		mail_server_configuration_outer_panel.setBorder(BorderFactory.createTitledBorder("Mail Server Configuration"));
		mail_server_configuration_outer_panel.setAlignmentX(0.5f);
		mail_server_configuration_outer_panel.add(mail_server_configuration_inner_panel);

		JPanel mail_server_configuration_panel = new JPanel();
		mail_server_configuration_panel.setPreferredSize(new Dimension(555, 195));
		mail_server_configuration_panel.setMaximumSize(new Dimension(555, 195));
		mail_server_configuration_panel.setAlignmentX(0.0f);
		mail_server_configuration_panel.add(mail_server_configuration_outer_panel);

		// Info outer panel
		info_outer_panel.setLayout(new BoxLayout(info_outer_panel, BoxLayout.Y_AXIS));
		info_outer_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		info_outer_panel.add(basic_info_panel);
		info_outer_panel.add(server_addresses_configuration_panel);
		info_outer_panel.add(mail_server_configuration_panel);
	}

	
	private final void create_attribute_page()
	{
		// Attributes
		JLabel attribute_label = new JLabel("Attributes");

		// All attribute table, including revoked attributes
		attribute_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		attribute_table_model.setDataVector(null, new Object[] {"Attribute name", "Numerical attribute?"});
    		attribute_table = new JTable(attribute_table_model);
		attribute_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane attribute_table_panel = new JScrollPane();
		attribute_table_panel.setPreferredSize(new Dimension(600, 200));
		attribute_table_panel.setMaximumSize(new Dimension(600, 200));
		attribute_table_panel.setAlignmentX(0.0f);
		attribute_table_panel.getViewport().add(attribute_table);

		// Attribute buttons
		attribute_registration_button.setAlignmentX(0.5f);
		attribute_removal_button.setAlignmentX(0.5f);
		attribute_removal_button.setEnabled(false);

		JPanel attribute_buttons_panel = new JPanel();
		attribute_buttons_panel.setPreferredSize(new Dimension(600, 30));
		attribute_buttons_panel.setMaximumSize(new Dimension(600, 30));
		attribute_buttons_panel.setAlignmentX(0.0f);
		attribute_buttons_panel.add(attribute_registration_button);
		attribute_buttons_panel.add(attribute_removal_button);

		// Refresh button
		attribute_page_refresh_info_button.setAlignmentX(0.5f);

		JPanel attribute_page_refresh_info_button_panel = new JPanel();
		attribute_page_refresh_info_button_panel.setPreferredSize(new Dimension(600, 30));
		attribute_page_refresh_info_button_panel.setMaximumSize(new Dimension(600, 30));
		attribute_page_refresh_info_button_panel.setAlignmentX(0.0f);
		attribute_page_refresh_info_button_panel.add(attribute_page_refresh_info_button);

		attribute_page.setLayout(new BoxLayout(attribute_page, BoxLayout.Y_AXIS));
		attribute_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		attribute_page.add(attribute_label);
		attribute_page.add(attribute_table_panel);
		attribute_page.add(Box.createRigidArea(new Dimension(0, 10)));
		attribute_page.add(attribute_buttons_panel);
		attribute_page.add(Box.createRigidArea(new Dimension(0, 10)));
		attribute_page.add(attribute_page_refresh_info_button_panel);
	}

	private final void create_user_page()
	{
		// Users
		JLabel user_label = new JLabel("Users");
	//	user_tree_table = new UserTreeTable();

		user_tree_table_panel.setPreferredSize(new Dimension(600, 200));
		user_tree_table_panel.setMaximumSize(new Dimension(600, 200));
		user_tree_table_panel.setAlignmentX(0.0f);
		user_tree_table_panel.getViewport().add(user_tree_table.get_user_tree_table());

		// User buttons
		user_registration_button.setAlignmentX(0.5f);
		user_or_user_attribute_editing_button.setAlignmentX(0.5f);
		user_passwd_resetting_button.setAlignmentX(0.5f);
		user_or_user_attribute_removal_button.setAlignmentX(0.5f);
		user_registration_button.setEnabled(false);
		user_or_user_attribute_editing_button.setEnabled(false);
		user_passwd_resetting_button.setEnabled(false);
		user_or_user_attribute_removal_button.setEnabled(false);

		JPanel user_buttons_panel = new JPanel();
		user_buttons_panel.setPreferredSize(new Dimension(600, 30));
		user_buttons_panel.setMaximumSize(new Dimension(600, 30));
		user_buttons_panel.setAlignmentX(0.0f);
		user_buttons_panel.add(user_registration_button);
		user_buttons_panel.add(user_or_user_attribute_editing_button);
		user_buttons_panel.add(user_passwd_resetting_button);
		user_buttons_panel.add(user_or_user_attribute_removal_button);

		// Refresh button
		user_page_refresh_info_button.setAlignmentX(0.5f);

		JPanel user_page_refresh_info_button_panel = new JPanel();
		user_page_refresh_info_button_panel.setPreferredSize(new Dimension(600, 30));
		user_page_refresh_info_button_panel.setMaximumSize(new Dimension(600, 30));
		user_page_refresh_info_button_panel.setAlignmentX(0.0f);
		user_page_refresh_info_button_panel.add(user_page_refresh_info_button);

		user_page.setLayout(new BoxLayout(user_page, BoxLayout.Y_AXIS));
		user_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		user_page.add(user_label);
		user_page.add(user_tree_table_panel);
		user_page.add(Box.createRigidArea(new Dimension(0, 10)));
		user_page.add(user_buttons_panel);
		user_page.add(Box.createRigidArea(new Dimension(0, 10)));
		user_page.add(user_page_refresh_info_button_panel);
	}

	private final void create_admin_page()
	{
		// Admins
		JLabel admin_label = new JLabel("Admins");

		admin_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		admin_table_model.setDataVector(null, new Object[] {"Username", "E-mail address"});
    		admin_table = new JTable(admin_table_model);
		admin_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane admin_table_panel = new JScrollPane();
		admin_table_panel.setPreferredSize(new Dimension(600, 200));
		admin_table_panel.setMaximumSize(new Dimension(600, 200));
		admin_table_panel.setAlignmentX(0.0f);
		admin_table_panel.getViewport().add(admin_table);

		// Admin buttons
		admin_registration_button.setAlignmentX(0.5f);
		admin_editing_button.setAlignmentX(0.5f);
		admin_passwd_resetting_button.setAlignmentX(0.5f);
		admin_removal_button.setAlignmentX(0.5f);
		admin_editing_button.setEnabled(false);
		admin_passwd_resetting_button.setEnabled(false);
		admin_removal_button.setEnabled(false);

		JPanel admin_buttons_panel = new JPanel();
		admin_buttons_panel.setPreferredSize(new Dimension(600, 30));
		admin_buttons_panel.setMaximumSize(new Dimension(600, 30));
		admin_buttons_panel.setAlignmentX(0.0f);
		admin_buttons_panel.add(admin_registration_button);
		admin_buttons_panel.add(admin_editing_button);
		admin_buttons_panel.add(admin_passwd_resetting_button);
		admin_buttons_panel.add(admin_removal_button);

		// Refresh button
		admin_page_refresh_info_button.setAlignmentX(0.5f);

		JPanel admin_page_refresh_info_button_panel = new JPanel();
		admin_page_refresh_info_button_panel.setPreferredSize(new Dimension(600, 30));
		admin_page_refresh_info_button_panel.setMaximumSize(new Dimension(600, 30));
		admin_page_refresh_info_button_panel.setAlignmentX(0.0f);
		admin_page_refresh_info_button_panel.add(admin_page_refresh_info_button);

		admin_page.setLayout(new BoxLayout(admin_page, BoxLayout.Y_AXIS));
		admin_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		admin_page.add(admin_label);
		admin_page.add(admin_table_panel);
		admin_page.add(Box.createRigidArea(new Dimension(0, 10)));
		admin_page.add(admin_buttons_panel);
		admin_page.add(Box.createRigidArea(new Dimension(0, 10)));
		admin_page.add(admin_page_refresh_info_button_panel);
	}

	private final void create_authority_page()
	{
		// Authorities
		JLabel authority_label = new JLabel("Authorities");

		authority_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		authority_table_model.setDataVector(null, new Object[] {"Authority name", "IP address", "Join status"});
    		authority_table = new JTable(authority_table_model);
		authority_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane authority_table_panel = new JScrollPane();
		authority_table_panel.setPreferredSize(new Dimension(600, 200));
		authority_table_panel.setMaximumSize(new Dimension(600, 200));
		authority_table_panel.setAlignmentX(0.0f);
		authority_table_panel.getViewport().add(authority_table);

		// Authority buttons
		authority_registration_button.setAlignmentX(0.5f);
		authority_editing_button.setAlignmentX(0.5f);
		authority_editing_button.setEnabled(false);
		authority_removal_button.setAlignmentX(0.5f);
		authority_removal_button.setEnabled(false);
	
		JPanel authority_buttons_panel = new JPanel();
		authority_buttons_panel.setPreferredSize(new Dimension(600, 30));
		authority_buttons_panel.setMaximumSize(new Dimension(600, 30));
		authority_buttons_panel.setAlignmentX(0.0f);
		authority_buttons_panel.add(authority_registration_button);
		authority_buttons_panel.add(authority_editing_button);
		authority_buttons_panel.add(authority_removal_button);

		// Refresh button
		authority_page_refresh_info_button.setAlignmentX(0.5f);

		JPanel authority_page_refresh_info_button_panel = new JPanel();
		authority_page_refresh_info_button_panel.setPreferredSize(new Dimension(600, 30));
		authority_page_refresh_info_button_panel.setMaximumSize(new Dimension(600, 30));
		authority_page_refresh_info_button_panel.setAlignmentX(0.0f);
		authority_page_refresh_info_button_panel.add(authority_page_refresh_info_button);

		authority_page.setLayout(new BoxLayout(authority_page, BoxLayout.Y_AXIS));
		authority_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		authority_page.add(authority_label);
		authority_page.add(authority_table_panel);
		authority_page.add(Box.createRigidArea(new Dimension(0, 10)));
		authority_page.add(authority_buttons_panel);
		authority_page.add(Box.createRigidArea(new Dimension(0, 10)));
		authority_page.add(authority_page_refresh_info_button_panel);		
	}

	private final void create_transaction_auditing_page()
	{
		// Transaction log type
        	transaction_log_type_radio_buttons[0] = new JRadioButton(transaction_admin_login_log_type);
        	transaction_log_type_radio_buttons[0].setActionCommand(transaction_admin_login_log_type);
		transaction_log_type_radio_buttons[0].setSelected(false);

		transaction_log_type_radio_buttons[1] = new JRadioButton(transaction_admin_event_log_type);
        	transaction_log_type_radio_buttons[1].setActionCommand(transaction_admin_event_log_type);
		transaction_log_type_radio_buttons[1].setSelected(false);

		transaction_log_type_radio_buttons[2] = new JRadioButton(transaction_system_login_log_type);
        	transaction_log_type_radio_buttons[2].setActionCommand(transaction_system_login_log_type);
		transaction_log_type_radio_buttons[2].setSelected(false);

		transaction_log_type_radio_buttons[3] = new JRadioButton(transaction_system_event_log_type);
        	transaction_log_type_radio_buttons[3].setActionCommand(transaction_system_event_log_type);
		transaction_log_type_radio_buttons[3].setSelected(false);

		transaction_log_type_group = new ButtonGroup();
            	transaction_log_type_group.add(transaction_log_type_radio_buttons[0]);
		transaction_log_type_group.add(transaction_log_type_radio_buttons[1]);
		transaction_log_type_group.add(transaction_log_type_radio_buttons[2]);
		transaction_log_type_group.add(transaction_log_type_radio_buttons[3]);

		// Transaction log type panel
		JPanel transaction_log_type_inner_panel = new JPanel();
		transaction_log_type_inner_panel.setLayout(new BoxLayout(transaction_log_type_inner_panel, BoxLayout.Y_AXIS));
		transaction_log_type_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		transaction_log_type_inner_panel.setPreferredSize(new Dimension(250, 120));
		transaction_log_type_inner_panel.setMaximumSize(new Dimension(250, 120));
		transaction_log_type_inner_panel.setAlignmentX(0.0f);
		transaction_log_type_inner_panel.add(transaction_log_type_radio_buttons[0]);
		transaction_log_type_inner_panel.add(transaction_log_type_radio_buttons[1]);
		transaction_log_type_inner_panel.add(transaction_log_type_radio_buttons[2]);
		transaction_log_type_inner_panel.add(transaction_log_type_radio_buttons[3]);

		JPanel transaction_log_type_outer_panel = new JPanel(new GridLayout(0, 1));
		transaction_log_type_outer_panel.setLayout(new BoxLayout(transaction_log_type_outer_panel, BoxLayout.Y_AXIS));
    		transaction_log_type_outer_panel.setBorder(BorderFactory.createTitledBorder("Transaction"));
		transaction_log_type_outer_panel.setAlignmentX(0.5f);
		transaction_log_type_outer_panel.add(transaction_log_type_inner_panel);

		// Audit all transactions checkbox
        	audit_all_transactions_checkbox.setFocusable(false);
		audit_all_transactions_checkbox.setAlignmentX(0.0f);

		JPanel audit_all_transactions_checkbox_panel = new JPanel();
		audit_all_transactions_checkbox_panel.setLayout(new BoxLayout(audit_all_transactions_checkbox_panel, BoxLayout.X_AXIS));
		audit_all_transactions_checkbox_panel.setAlignmentX(0.0f);
		audit_all_transactions_checkbox_panel.add(audit_all_transactions_checkbox);

		// Start date
		JLabel start_date_label = new JLabel("Start date: ", JLabel.TRAILING);
	
		start_year_combobox = new JComboBox();
		build_year_list(start_year_combobox);
		start_year_combobox.setSelectedIndex(start_date_calendar.get(Calendar.YEAR) - LOWER_BOUND_AUDITING_YEAR);

		start_month_combobox = new JComboBox();
		build_month_list(start_month_combobox);
		start_month_combobox.setSelectedIndex(start_date_calendar.get(Calendar.MONTH));

		start_day_combobox = new JComboBox();
		build_day_list(start_date_calendar, start_day_combobox, start_month_combobox);
		start_day_combobox.setSelectedIndex(start_date_calendar.get(Calendar.DATE)-1);

		// Start time
		start_hour_combobox = new JComboBox();
		build_hour_list(start_hour_combobox);
		start_hour_combobox.setSelectedIndex(0);

		start_minute_combobox = new JComboBox();
		build_minute_list(start_minute_combobox);
		start_minute_combobox.setSelectedIndex(0);

		// End date
		JLabel end_date_label = new JLabel("End date: ", JLabel.TRAILING);

		end_year_combobox = new JComboBox();
		build_year_list(end_year_combobox);
		end_year_combobox.setSelectedIndex(end_date_calendar.get(Calendar.YEAR) - LOWER_BOUND_AUDITING_YEAR);

		end_month_combobox = new JComboBox();
		build_month_list(end_month_combobox);
		end_month_combobox.setSelectedIndex(end_date_calendar.get(Calendar.MONTH));

		end_day_combobox = new JComboBox();
		build_day_list(end_date_calendar, end_day_combobox, end_month_combobox);
		end_day_combobox.setSelectedIndex(end_date_calendar.get(Calendar.DATE)-1);

		// End time
		end_hour_combobox = new JComboBox();
		build_hour_list(end_hour_combobox);
		end_hour_combobox.setSelectedIndex(0);

		end_minute_combobox = new JComboBox();
		build_minute_list(end_minute_combobox);
		end_minute_combobox.setSelectedIndex(0);

		set_transaction_auditing_datetime_comboboxes_enable(false);

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
		datetime_comboboxes_outer_panel.setAlignmentX(0.0f);
		datetime_comboboxes_outer_panel.add(datetime_comboboxes_inner_panel);

		// Auditing date/time panel
		JPanel auditing_datetime_inner_panel = new JPanel();
		auditing_datetime_inner_panel.setLayout(new BoxLayout(auditing_datetime_inner_panel, BoxLayout.Y_AXIS));
		auditing_datetime_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		auditing_datetime_inner_panel.setPreferredSize(new Dimension(500, 200));
		auditing_datetime_inner_panel.setMaximumSize(new Dimension(500, 200));
		auditing_datetime_inner_panel.setAlignmentX(0.0f);
		auditing_datetime_inner_panel.add(audit_all_transactions_checkbox_panel);
		auditing_datetime_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		auditing_datetime_inner_panel.add(datetime_comboboxes_outer_panel);
		auditing_datetime_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));

		JPanel auditing_datetime_outer_panel = new JPanel(new GridLayout(0, 1));
		auditing_datetime_outer_panel.setLayout(new BoxLayout(auditing_datetime_outer_panel, BoxLayout.Y_AXIS));
    		auditing_datetime_outer_panel.setBorder(BorderFactory.createTitledBorder("Auditing Period"));
		auditing_datetime_outer_panel.setAlignmentX(0.5f);
		auditing_datetime_outer_panel.add(auditing_datetime_inner_panel);

		// Transaction log search button
		search_transaction_log_button.setAlignmentX(0.5f);	

		JPanel search_transaction_log_button_panel = new JPanel();
		search_transaction_log_button_panel.setPreferredSize(new Dimension(580, 30));
		search_transaction_log_button_panel.setMaximumSize(new Dimension(580, 30));
		search_transaction_log_button_panel.setAlignmentX(0.0f);
		search_transaction_log_button_panel.add(search_transaction_log_button);

		JPanel transaction_auditing_panel = new JPanel();
		transaction_auditing_panel.setAlignmentX(0.5f);
		transaction_auditing_panel.add(transaction_log_type_outer_panel);
		transaction_auditing_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		transaction_auditing_panel.add(auditing_datetime_outer_panel);
		transaction_auditing_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		transaction_auditing_panel.add(search_transaction_log_button_panel);

		transaction_auditing_page.setLayout(new BoxLayout(transaction_auditing_page, BoxLayout.Y_AXIS));
		transaction_auditing_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		transaction_auditing_page.add(transaction_auditing_panel);
	}

	private void setup_actions()
	{
		// Set an event for close button
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter()
		{
            		@Override
            		public void windowClosing(final WindowEvent e)
			{
				// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
				// we call it manay times. Note that, the tryLock() could not detect the same thead
				if(!working_lock.isLocked())
				{
					working_lock.lock();
				}
				else
				{
					JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
					return;
				}

				// Terminate the application
				System.exit(0);
            		}
        	});

		// Set Java shutdown hook
		shutdown_hooker = new ShutdownHook(username);
		Runtime.getRuntime().addShutdownHook(shutdown_hooker);

		// Change password button
		change_passwd_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						change_passwd_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							change_passwd_button.setEnabled(true);
							return;
						}

						// Call new password changing object
						NewPasswordChanging new_passwd_changing_dialog = new NewPasswordChanging(main_panel, true, passwd);
						new_passwd_changing_dialog.setVisible(true);

						// If a password is changed then update it
						if(new_passwd_changing_dialog.get_result())
							passwd = new_passwd_changing_dialog.get_new_passwd();

						working_lock.unlock();
						change_passwd_button.setEnabled(true);
					}
				});
            		}
        	});

		// Change email address button
		change_email_address_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						change_email_address_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							change_email_address_button.setEnabled(true);
							return;
						}

						// Call email address changing object
						EmailAddressChanging email_address_changing_dialog = new EmailAddressChanging(main_panel, true, email_address, passwd);
						email_address_changing_dialog.setVisible(true);

						// If an e-mail address is changed then update it
						if(email_address_changing_dialog.get_result())
						{
							email_address = email_address_changing_dialog.get_email_address();
							email_address_textfield.setText(email_address);
						}

						working_lock.unlock();
						change_email_address_button.setEnabled(true);
					}
				});
            		}
        	});

		// Change server addresses configuration button
		change_server_addresses_configuration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						change_server_addresses_configuration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							change_server_addresses_configuration_button.setEnabled(true);
							return;
						}

						// Call server addresses configuration changing object
						ServerAddressesConfigurationChanging server_addresses_configuration_changing_dialog;
						server_addresses_configuration_changing_dialog = new ServerAddressesConfigurationChanging(
							main_panel, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr, passwd);

						server_addresses_configuration_changing_dialog.setVisible(true);

						// If any address is changed then update it
						if(server_addresses_configuration_changing_dialog.get_result())
						{
							audit_server_ip_addr     = server_addresses_configuration_changing_dialog.get_updated_audit_server_ip_address();
							phr_server_ip_addr       = server_addresses_configuration_changing_dialog.get_updated_phr_server_ip_address();
							emergency_server_ip_addr = server_addresses_configuration_changing_dialog.get_updated_emergency_server_ip_address();

							audit_server_ip_address_textfield.setText(audit_server_ip_addr);
							phr_server_ip_address_textfield.setText(phr_server_ip_addr);
							emergency_server_ip_address_textfield.setText(emergency_server_ip_addr);
						}

						working_lock.unlock();
						change_server_addresses_configuration_button.setEnabled(true);
					}
				});
            		}
        	});

		// Change mail server configuration button
		change_mail_server_configuration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						change_mail_server_configuration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							change_mail_server_configuration_button.setEnabled(true);
							return;
						}

						// Call mail server configuration changing object
						MailServerConfigurationChanging mail_server_configuration_changing_dialog;
						mail_server_configuration_changing_dialog = new MailServerConfigurationChanging(
							main_panel, mail_server_url, authority_email_address, authority_email_passwd, passwd);

						mail_server_configuration_changing_dialog.setVisible(true);

						// If there is any update then update it
						if(mail_server_configuration_changing_dialog.get_result())
						{
							mail_server_url         = mail_server_configuration_changing_dialog.get_updated_mail_server_url();
							authority_email_address = mail_server_configuration_changing_dialog.get_updated_authority_email_address();
							authority_email_passwd  = mail_server_configuration_changing_dialog.get_updated_authority_email_passwd();

							mail_server_url_textfield.setText(mail_server_url);
							authority_email_address_textfield.setText(authority_email_address);
						}

						working_lock.unlock();
						change_mail_server_configuration_button.setEnabled(true);
					}
				});
            		}
        	});

		// Attribute table
		attribute_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							int row = attribute_table.getSelectedRow();
							if(row == -1)
							{
								JOptionPane.showMessageDialog(main_panel, "No any row selected");
								attribute_removal_button.setEnabled(false);
								return;
							}

							attribute_removal_button.setEnabled(true);
						}
					});
				}
			}
		});

		// Attribute registration button
		attribute_registration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						attribute_registration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							attribute_registration_button.setEnabled(true);
							return;
						}

						// Call attribute registration object
						AttributeRegistration attribute_registration_dialog = new AttributeRegistration(main_panel);
						attribute_registration_dialog.setVisible(true);

						// If a new attribute is registered then update the attribute list
						if(attribute_registration_dialog.get_registration_result())
						{
							// Call to C functions
							update_attribute_list_main();
							update_user_list_main();
						}

						working_lock.unlock();
						attribute_registration_button.setEnabled(true);
					}
				});
            		}
        	});

		// Attribute removal button
		attribute_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						attribute_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							attribute_removal_button.setEnabled(true);
							return;
						}

						int row = attribute_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							attribute_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Removing the attribute may affect to an attribute list of some users!!!\n" + 
							"Are you sure to remove this attribute?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							attribute_removal_button.setEnabled(true);
							return;
						}

						String full_attribute_name = attribute_table.getModel().getValueAt(row, 0).toString();
						String attribute_name      = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);

						// Call to C functions
						if(remove_attribute_main(attribute_name))
						{
							update_attribute_list_main();
							update_user_list_main();

							working_lock.unlock();
							attribute_removal_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							attribute_removal_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Attribute page refresh info button
		attribute_page_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						attribute_page_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							attribute_page_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C functions
						update_attribute_list_main();
						update_user_list_main();

						working_lock.unlock();
						attribute_page_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// User tree table
		set_user_tree_table_listener();

		// User registration button
		user_registration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_registration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_registration_button.setEnabled(true);
							return;
						}

						// Call user management object
						UserManagement user_registration_dialog = new UserManagement(main_panel, attribute_table_model);
						user_registration_dialog.setVisible(true);

						// If a new user is registered then update the user list
						if(user_registration_dialog.get_result())
						{
							// Call to C functions
							update_attribute_list_main();
							update_user_list_main();
						}

						working_lock.unlock();
						user_registration_button.setEnabled(true);
					}
				});
            		}
        	});

		// User or user attribute editing button
		user_or_user_attribute_editing_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_or_user_attribute_editing_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_or_user_attribute_editing_button.setEnabled(true);
							return;
						}

						int selected_row = user_tree_table.get_selected_row();
						if(selected_row >= 0)
						{
							if(is_selected_row_user(selected_row))
							{
								// Call user management object
								UserManagement user_editing_dialog = new UserManagement(main_panel, 
									attribute_table_model, user_tree_table, selected_row);

								user_editing_dialog.setVisible(true);

								// If a user is edited attributes or e-mail address then update the user list
								if(user_editing_dialog.get_result())
								{
									// Call to C functions
									update_attribute_list_main();
									update_user_list_main();

									working_lock.unlock();
									user_or_user_attribute_editing_button.setEnabled(false);
									return;
								}
							}
							else if(is_selected_row_editable_attribute(selected_row))
							{
								NumericalAttributeValueEditing attribute_value_editing_dialog;

								// Call numerical attribute value editing object
								attribute_value_editing_dialog = new NumericalAttributeValueEditing(
									main_panel, user_tree_table, selected_row);

								attribute_value_editing_dialog.setVisible(true);

								// If an attribute value is edited then update the user list
								if(attribute_value_editing_dialog.get_result())
								{
									// Call to C functions
									update_attribute_list_main();
									update_user_list_main();

									working_lock.unlock();
									user_or_user_attribute_editing_button.setEnabled(false);
									return;
								}
							}
						}
						
						working_lock.unlock();
						user_or_user_attribute_editing_button.setEnabled(true);
					}
				});
            		}
        	});

		// User passwd resetting button
		user_passwd_resetting_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_passwd_resetting_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_passwd_resetting_button.setEnabled(true);
							return;
						}

						int selected_row = user_tree_table.get_selected_row();
						if(selected_row >= 0)
						{
							int confirm_result = JOptionPane.showConfirmDialog(main_panel, "Are you sure to reset a password for this user?", 
								"Reset Password Confirmation", JOptionPane.YES_NO_OPTION);

							if(confirm_result != JOptionPane.YES_OPTION)
							{
								working_lock.unlock();
								user_passwd_resetting_button.setEnabled(true);
								return;
							}

							String username = get_selected_username_from_user_tree_table(selected_row);

							// Call to C functions
							if(reset_user_passwd_main(username))
							{
								update_attribute_list_main();
								update_user_list_main();

								JOptionPane.showMessageDialog(main_panel, "The new user's password " + 
									"was sent to the user's e-mail address already");

								working_lock.unlock();
								user_passwd_resetting_button.setEnabled(false);
								return;
							}	
						}
						
						working_lock.unlock();
						user_passwd_resetting_button.setEnabled(true);
					}
				});
            		}
        	});

		// User or user attribute removal button
		user_or_user_attribute_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_or_user_attribute_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_or_user_attribute_removal_button.setEnabled(true);
							return;
						}

						int selected_row = user_tree_table.get_selected_row();
						if(selected_row >= 0)
						{
							if(is_selected_row_user(selected_row))   // User
							{
								int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
									"Are you sure to remove this user?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

								if(confirm_result != JOptionPane.YES_OPTION)
								{
									working_lock.unlock();
									user_or_user_attribute_removal_button.setEnabled(true);
									return;
								}

								String username = get_selected_username_from_user_tree_table(selected_row);

								// Call to C functions
								if(remove_user_main(username))
								{
									update_attribute_list_main();
									update_user_list_main();

									working_lock.unlock();
									user_or_user_attribute_removal_button.setEnabled(false);
									return;
								}
							}
							else  // User attribute
							{
								int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
									"Are you sure to remove this user attribute?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

								if(confirm_result != JOptionPane.YES_OPTION)
								{
									working_lock.unlock();
									user_or_user_attribute_removal_button.setEnabled(true);
									return;
								}

								String username                 = get_root_username_from_user_tree_table(selected_row);
								String full_attribute_name      = get_selected_full_attribute_name_from_user_tree_table(selected_row);
								String attribute_name           = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);
								String attribute_authority_name = full_attribute_name.substring(0, full_attribute_name.indexOf("."));

								// Call to C functions
								if(remove_user_attribute_main(username, attribute_name, attribute_authority_name))
								{
									update_attribute_list_main();
									update_user_list_main();

									working_lock.unlock();
									user_or_user_attribute_removal_button.setEnabled(false);
									return;
								}
							}
						}

						working_lock.unlock();
						user_or_user_attribute_removal_button.setEnabled(true);
					}
				});
            		}
        	});

		// User page refresh info button
		user_page_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_page_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_page_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C functions
						update_attribute_list_main();
						update_user_list_main();

						working_lock.unlock();
						user_page_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// Admin table
		admin_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							admin_editing_button.setEnabled(true);
							admin_passwd_resetting_button.setEnabled(true);
							admin_removal_button.setEnabled(true);
						}
					});
				}
			}
		});

		// Admin registration button
		admin_registration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						admin_registration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							admin_registration_button.setEnabled(true);
							return;
						}

						// Call admin management object
						AdminManagement admin_registration_dialog = new AdminManagement(main_panel);
						admin_registration_dialog.setVisible(true);

						// If a new admin is registered then update the admin list
						if(admin_registration_dialog.get_result())
						{
							// Call to C function
							update_admin_list_main();
						}

						working_lock.unlock();
						admin_registration_button.setEnabled(true);
					}
				});
            		}
        	});

		// Admin editing button
		admin_editing_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						admin_editing_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							admin_editing_button.setEnabled(true);
							return;
						}

						int row = admin_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							admin_editing_button.setEnabled(false);
							admin_passwd_resetting_button.setEnabled(false);
							admin_removal_button.setEnabled(false);
							return;
						}

						String username      = admin_table.getModel().getValueAt(row, 0).toString();
						String email_address = admin_table.getModel().getValueAt(row, 1).toString();

						// Call admin management object
						AdminManagement admin_editing_dialog = new AdminManagement(main_panel, username, email_address);
						admin_editing_dialog.setVisible(true);

						// If an admin's e-mail address is edited then update the admin list
						if(admin_editing_dialog.get_result())
						{
							// Call to C function
							update_admin_list_main();

							working_lock.unlock();
							admin_editing_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							admin_editing_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Admin passwd resetting button
		admin_passwd_resetting_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						admin_passwd_resetting_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							admin_passwd_resetting_button.setEnabled(true);
							return;
						}

						int row = admin_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							admin_editing_button.setEnabled(false);
							admin_passwd_resetting_button.setEnabled(false);
							admin_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, "Are you sure to reset a password for this admin?", 
							"Reset Password Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							admin_passwd_resetting_button.setEnabled(true);
							return;
						}

						String username = admin_table.getModel().getValueAt(row, 0).toString();

						// Call to C functions
						if(reset_admin_passwd_main(username))
						{
							update_admin_list_main();
							JOptionPane.showMessageDialog(main_panel, "The new admin's password " + 
								"was sent to the admin's e-mail address already");

							working_lock.unlock();
							admin_passwd_resetting_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							admin_passwd_resetting_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Admin removal button
		admin_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						admin_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							admin_removal_button.setEnabled(true);
							return;
						}

						int row = admin_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							admin_editing_button.setEnabled(false);
							admin_passwd_resetting_button.setEnabled(false);
							admin_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to remove this admin?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							admin_removal_button.setEnabled(true);
							return;
						}

						String username = admin_table.getModel().getValueAt(row, 0).toString();

						// Call to C functions
						if(remove_admin_main(username))
						{
							update_admin_list_main();

							working_lock.unlock();
							admin_removal_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							admin_removal_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Admin page refresh info button
		admin_page_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						admin_page_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							admin_page_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C function
						update_admin_list_main();

						working_lock.unlock();
						admin_page_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// Authority table
		authority_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							int row = authority_table.getSelectedRow();
							if(row == -1)
							{
								JOptionPane.showMessageDialog(main_panel, "No any row selected");
								authority_editing_button.setEnabled(false);
								authority_removal_button.setEnabled(false);
								return;
							}

							String status = authority_table.getModel().getValueAt(row, 2).toString();
							if(status.indexOf("Removed already") == -1)
							{
								authority_editing_button.setEnabled(true);
								authority_removal_button.setEnabled(true);
							}
							else
							{
								authority_editing_button.setEnabled(false);
								authority_removal_button.setEnabled(false);
							}
						}
					});
				}
			}
		});

		// Authority registration button
		authority_registration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						authority_registration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							authority_registration_button.setEnabled(true);
							return;
						}

						// Call authority management object
						AuthorityManagement authority_registration_dialog = new AuthorityManagement(main_panel);
						authority_registration_dialog.setVisible(true);

						// If a new authority is registered then update the authority list
						if(authority_registration_dialog.get_result())
						{
							// Call to C function
							update_authority_list_main();
						}

						working_lock.unlock();
						authority_registration_button.setEnabled(true);
					}
				});
            		}
        	});

		// Authority editing button
		authority_editing_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						authority_editing_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							authority_editing_button.setEnabled(true);
							return;
						}

						int row = authority_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							authority_editing_button.setEnabled(false);
							authority_removal_button.setEnabled(false);
							return;
						}

						String authority_name = authority_table.getModel().getValueAt(row, 0).toString();
						String ip_address     = authority_table.getModel().getValueAt(row, 1).toString();

						// Call authority management object
						AuthorityManagement authority_editing_dialog = new AuthorityManagement(main_panel, authority_name, ip_address);
						authority_editing_dialog.setVisible(true);

						// If an authority's ip address is edited then update the authority list
						if(authority_editing_dialog.get_result())
						{
							// Call to C function
							update_authority_list_main();

							working_lock.unlock();
							authority_editing_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							authority_editing_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Authority removal button
		authority_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						authority_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							authority_removal_button.setEnabled(true);
							return;
						}

						int row = authority_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							authority_editing_button.setEnabled(false);
							authority_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to remove this authority?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							authority_removal_button.setEnabled(true);
							return;
						}

						String authority_name = authority_table.getModel().getValueAt(row, 0).toString();

						// Call to C functions
						if(remove_authority_main(authority_name))
						{
							update_authority_list_main();

							working_lock.unlock();
							authority_removal_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							authority_removal_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Authority page refresh info button
		authority_page_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						authority_page_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							authority_page_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C function
						update_authority_list_main();

						working_lock.unlock();
						authority_page_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// Audit all transactions checkbox
		audit_all_transactions_checkbox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
					set_transaction_auditing_datetime_comboboxes_enable(false);
				else
					set_transaction_auditing_datetime_comboboxes_enable(true);
			}
		});

		// Start year combobox
		start_year_combobox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					int year = Integer.parseInt((String)start_year_combobox.getSelectedItem());
					start_date_calendar.set(Calendar.YEAR, year);
					start_month_combobox.setSelectedIndex(0);
					start_date_calendar.set(Calendar.MONTH, 0);
					build_day_list(start_date_calendar, start_day_combobox, start_month_combobox);
					start_date_calendar.set(Calendar.DATE, 1);
				}
			}
		});

		// Start month combobox
		start_month_combobox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					start_date_calendar.set(Calendar.MONTH, start_month_combobox.getSelectedIndex());
					build_day_list(start_date_calendar, start_day_combobox, start_month_combobox);
					start_date_calendar.set(Calendar.DATE, 1);
				}
			}
		});

		// Start day combobox
		start_day_combobox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					int day = Integer.parseInt((String)start_day_combobox.getSelectedItem());
					start_date_calendar.set(Calendar.DATE, day);
				}
			}
		});

		// End year combobox
		end_year_combobox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					int year = Integer.parseInt((String)end_year_combobox.getSelectedItem());
					end_date_calendar.set(Calendar.YEAR, year);
					end_month_combobox.setSelectedIndex(0);
					end_date_calendar.set(Calendar.MONTH, 0);
					build_day_list(end_date_calendar, end_day_combobox, end_month_combobox);
					end_date_calendar.set(Calendar.DATE, 1);
				}
			}
		});

		// End month combobox
		end_month_combobox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					end_date_calendar.set(Calendar.MONTH, end_month_combobox.getSelectedIndex());
            				build_day_list(end_date_calendar, end_day_combobox, end_month_combobox);
            				end_date_calendar.set(Calendar.DATE, 1);
				}
			}
		});

		// End day combobox
		end_day_combobox.addItemListener(new ItemListener()
		{
			public void itemStateChanged(ItemEvent event)
			{
				if(event.getStateChange() == ItemEvent.SELECTED)
				{
					int day = Integer.parseInt((String)end_day_combobox.getSelectedItem());
					end_date_calendar.set(Calendar.DATE, day);
				}
			}
		});

		// Search transaction log button
		search_transaction_log_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						search_transaction_log_button.setEnabled(false);
						transaction_log_thread_counter_lock.lock();

						if(transaction_log_thread_counter == 0)
						{
							// We could not use tryLock() becuase the SwingUtilities is the same thread even if
							// we call it manay times. Note that, the tryLock() could not detect the same thead
							if(!working_lock.isLocked())
							{
								working_lock.lock();
							}
							else
							{
								transaction_log_thread_counter_lock.unlock();
								JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
								search_transaction_log_button.setEnabled(true);
								return;
							}
						}

						if(!validate_transaction_log_search_input()) 
						{
							if(transaction_log_thread_counter == 0)
								working_lock.unlock();

							transaction_log_thread_counter_lock.unlock();
							search_transaction_log_button.setEnabled(true);
							return;
						}

						if(transaction_log_thread_counter + 1 > MAX_CONCURRENT_TRANSACTION_LOGS)
						{
							transaction_log_thread_counter_lock.unlock();
							JOptionPane.showMessageDialog(main_panel, "The number of concurrent transaction logs exceeded");
							search_transaction_log_button.setEnabled(true);
							return;
						}

						transaction_log_thread_counter++;
						transaction_log_thread_counter_lock.unlock();

						String  transaction_log_type = transaction_log_type_group.getSelection().getActionCommand();
						boolean audit_all_transactions_flag = audit_all_transactions_checkbox.isSelected();

						if(audit_all_transactions_flag)
						{
							// Run on another thread
							if(transaction_log_type.equals(transaction_admin_login_log_type))
							{
								audit_all_transaction_logs(TransactionLogType.ADMIN_LOGIN_LOG);
							}
							else if(transaction_log_type.equals(transaction_admin_event_log_type))
							{
								audit_all_transaction_logs(TransactionLogType.ADMIN_EVENT_LOG);
							}
							else if(transaction_log_type.equals(transaction_system_login_log_type))
							{
								audit_all_transaction_logs(TransactionLogType.SYSTEM_LOGIN_LOG);
							}
							else if(transaction_log_type.equals(transaction_system_event_log_type))
							{
								audit_all_transaction_logs(TransactionLogType.SYSTEM_EVENT_LOG);
							}
						}
						else
						{
							int start_year_index   = start_year_combobox.getSelectedIndex();
							int start_month_index  = start_month_combobox.getSelectedIndex();
							int start_day_index    = start_day_combobox.getSelectedIndex();
							int start_hour_index   = start_hour_combobox.getSelectedIndex();
							int start_minute_index = start_minute_combobox.getSelectedIndex();
							int end_year_index     = end_year_combobox.getSelectedIndex();
							int end_month_index    = end_month_combobox.getSelectedIndex();
							int end_day_index      = end_day_combobox.getSelectedIndex();
							int end_hour_index     = end_hour_combobox.getSelectedIndex();
							int end_minute_index   = end_minute_combobox.getSelectedIndex();
		
							// Run on another thread
							if(transaction_log_type.equals(transaction_admin_login_log_type))
							{
								audit_some_period_time_transaction_logs(TransactionLogType.ADMIN_LOGIN_LOG, start_year_index, 
								start_month_index, start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, 
								end_day_index, end_hour_index, end_minute_index);
							}
							else if(transaction_log_type.equals(transaction_admin_event_log_type))
							{
								audit_some_period_time_transaction_logs(TransactionLogType.ADMIN_EVENT_LOG, start_year_index, 
								start_month_index, start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, 
								end_day_index, end_hour_index, end_minute_index);
							}
							else if(transaction_log_type.equals(transaction_system_login_log_type))
							{
								audit_some_period_time_transaction_logs(TransactionLogType.SYSTEM_LOGIN_LOG, start_year_index, 
								start_month_index, start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, 
								end_day_index, end_hour_index, end_minute_index);
							}
							else if(transaction_log_type.equals(transaction_system_event_log_type))
							{
								audit_some_period_time_transaction_logs(TransactionLogType.SYSTEM_EVENT_LOG, start_year_index, 
								start_month_index, start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, 
								end_day_index, end_hour_index, end_minute_index);
							}
						}

						search_transaction_log_button.setEnabled(true);
		    			}
				});
			}
		});
	}

	private void automatic_relogin()
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				int    counter = 0;
				int    hour_left, minute_left, second_left;
				String status;

				while(counter < ENFORCING_RELOGIN_TIME)
				{
					hour_left   = (ENFORCING_RELOGIN_TIME - counter)/3600;
					minute_left = ((ENFORCING_RELOGIN_TIME - counter)%3600)/60;
					second_left = ((ENFORCING_RELOGIN_TIME - counter)%3600)%60;

					status = " Login session time left: ";					
					if(hour_left > 0)
					{
						status += hour_left + " hours";

						if(minute_left > 0)
							status += " " + minute_left + " minutes";

						if(second_left > 0)
							status += " " + second_left + " seconds";
					}
					else if(minute_left > 0)
					{
						status += minute_left + " minutes";

						if(second_left > 0)
							status += " " + second_left + " seconds";
					}
					else
					{
						status += second_left + " seconds";
					}

					statusbar_label.setText(status);

					try{
						Thread.sleep(1000);
					}
					catch(InterruptedException ex){
						Thread.currentThread().interrupt();
					}

					counter++;
				}

				// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
				// we call it manay times. Note that, the tryLock() could not detect the same thead
				if(working_lock.isLocked())
				{
					statusbar_label.setText(" You must re-log in when the working task is done");
				}

				working_lock.lock();
				statusbar_label.setText(" You must re-log in");

				Runtime.getRuntime().removeShutdownHook(shutdown_hooker);
				shutdown_hooker.run();
				statusbar_label.setText(" You must re-log in (now!!)");

				int relogin_result = JOptionPane.showConfirmDialog(main_panel, "Login session has expired, do you want to re-log in?", 
					"Re-login Confirmation", JOptionPane.YES_NO_OPTION);

				// Invisible AdminMain frame and destroy it
				setVisible(false);
				dispose();
				System.gc();

				if(relogin_result == JOptionPane.YES_OPTION)
				{
					// Call Login object
					Login login_main = new Login();
					login_main.setVisible(true);
				}
				else
				{
					// Terminate the application
					System.exit(0);
				}
			}
		};

		thread.start();
	}

	private void set_user_tree_table_listener()
	{
		user_tree_table.get_user_tree_table().addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
					   	public void run()
						{
							int selected_row = user_tree_table.get_selected_row();

							if(selected_row >= 0)
							{
								if(is_selected_row_user(selected_row))
								{
									user_or_user_attribute_editing_button.setEnabled(true);
									user_passwd_resetting_button.setEnabled(true);
									user_or_user_attribute_removal_button.setEnabled(true);
								}
								else if(is_selected_row_editable_attribute(selected_row))
								{
									user_or_user_attribute_editing_button.setEnabled(true);
									user_passwd_resetting_button.setEnabled(false);
									user_or_user_attribute_removal_button.setEnabled(true);
								}
								else
								{
									user_or_user_attribute_editing_button.setEnabled(false);
									user_passwd_resetting_button.setEnabled(false);
									user_or_user_attribute_removal_button.setEnabled(true);
								}
							}
						}
					});
				}
			}
		});
	}

	private boolean is_selected_row_editable_attribute(int row)
	{
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(int i=0; i < child_root_count && base != row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			if(base + child_sub_root_count + 1 <= row)
			{
				base += child_sub_root_count+1;
			}
			else
			{
				int no_child = row-base-1;
				base         = row;

				if(child_sub_root_count > 0)
				{
					UserTreeTableNode attribute_node = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(node, no_child);
					if(attribute_node.getNameTableCell().indexOf(" = ") >= 0)
						return true;
				}
			}
		}

		return false;
	}

	private boolean is_selected_row_user(int row)
	{
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(int i=0; i < child_root_count && base <= row; i++)
		{
			if(base == row)
				return true;

			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			base += child_sub_root_count+1;
		}

		return false;
	}

	private String get_selected_username_from_user_tree_table(int selected_row)
	{
		int i;
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			base += child_sub_root_count+1;
		}

		if(base == selected_row)    // At a user level
		{
			UserTreeTableNode user_node = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			return user_node.getName();
		}

		return null;
	}

	private String get_root_username_from_user_tree_table(int selected_row)
	{
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(int i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			if(base + child_sub_root_count + 1 <= selected_row)
			{
				base += child_sub_root_count+1;
			}
			else
			{
				return node.getName();
			}
		}

		return null;
	}

	private String get_selected_full_attribute_name_from_user_tree_table(int selected_row)
	{
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		for(int i=0; i < child_root_count && base != selected_row; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(user_tree_table.get_user_tree_table_root(), i);
			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

			if(base + child_sub_root_count + 1 <= selected_row)
			{
				base += child_sub_root_count+1;
			}
			else
			{
				int no_child = selected_row-base-1;
				base = selected_row;

				if(child_sub_root_count > 0)
				{
					UserTreeTableNode attribute_node = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(node, no_child);
					return attribute_node.getAuthorityName() + "." + attribute_node.getName();
				}
			}
		}

		return null;
	}

	private void build_year_list(JComboBox year_combobox)
	{
		for(int year_count = LOWER_BOUND_AUDITING_YEAR; year_count <= UPPER_BOUND_AUDITING_YEAR; year_count++)
			year_combobox.addItem(Integer.toString(year_count));
	}

	private void build_month_list(JComboBox month_combobox)
	{
		final String[] MONTH_LIST = {"January", "February", "March", "April", "May", 
			"June", "July", "August", "September", "October", "November", "December"};

		month_combobox.removeAllItems();
		for(int month_count = 0; month_count < 12; month_count++)
			month_combobox.addItem(MONTH_LIST[month_count]);
	}

	private void build_day_list(Calendar date_calendar, JComboBox day_combobox, JComboBox month_combobox)
	{
		day_combobox.removeAllItems();
		date_calendar.set(Calendar.MONTH, month_combobox.getSelectedIndex());
        
		int last_day = date_calendar.getActualMaximum(Calendar.DAY_OF_MONTH);

		for(int day_count = 1; day_count <= last_day; day_count++)	
			day_combobox.addItem(Integer.toString(day_count));
	}

	private void build_hour_list(JComboBox hour_combobox)
	{
		for(int hour_count = 0; hour_count <= 23; hour_count++)
		{
			if(hour_count < 10)
				hour_combobox.addItem("0" + Integer.toString(hour_count));
			else
				hour_combobox.addItem(Integer.toString(hour_count));
		}
	}

	private void build_minute_list(JComboBox minute_combobox)
	{
		for(int minute_count = 0; minute_count <= 59; minute_count++)
		{
			if(minute_count < 10)
				minute_combobox.addItem("0" + Integer.toString(minute_count));
			else
				minute_combobox.addItem(Integer.toString(minute_count));
		}
	}

	private void set_transaction_auditing_datetime_comboboxes_enable(boolean enabling_flag)
	{
		start_year_combobox.setEnabled(enabling_flag);
		start_month_combobox.setEnabled(enabling_flag);
		start_day_combobox.setEnabled(enabling_flag);
		start_hour_combobox.setEnabled(enabling_flag);
		start_minute_combobox.setEnabled(enabling_flag);

		end_year_combobox.setEnabled(enabling_flag);
		end_month_combobox.setEnabled(enabling_flag);
		end_day_combobox.setEnabled(enabling_flag);
		end_hour_combobox.setEnabled(enabling_flag);
		end_minute_combobox.setEnabled(enabling_flag);
	}

	private boolean validate_transaction_log_search_input()
	{
		boolean transaction_log_validity_flag = false;

		// Validate transaction log type
		for(Enumeration<AbstractButton> buttons = transaction_log_type_group.getElements(); buttons.hasMoreElements();)
		{
			AbstractButton button = buttons.nextElement();
			if(button.isSelected())
			{
				transaction_log_validity_flag = true;
				break;
			}
		}

		if(!transaction_log_validity_flag)
		{
			JOptionPane.showMessageDialog(this, "Please select your desired transaction log");
			return false;
		}

		if(!audit_all_transactions_checkbox.isSelected())
		{
			// Validate years of start and end
			if(start_year_combobox.getSelectedIndex() > end_year_combobox.getSelectedIndex())
			{
				JOptionPane.showMessageDialog(this, "The start year must less than or equal to the end year");
				return false;
			}
			else if(start_year_combobox.getSelectedIndex() < end_year_combobox.getSelectedIndex())
				return true;
	
			// Validate months of start and end
			if(start_month_combobox.getSelectedIndex() > end_month_combobox.getSelectedIndex())
			{
				JOptionPane.showMessageDialog(this, "The start month must less than or equal to the end month");
				return false;
			}
			else if(start_month_combobox.getSelectedIndex() < end_month_combobox.getSelectedIndex())
				return true;

			// Validate days of start and end
			if(start_day_combobox.getSelectedIndex() > end_day_combobox.getSelectedIndex())
			{
				JOptionPane.showMessageDialog(this, "The start day must less than or equal to the end day");
				return false;
			}
			else if(start_day_combobox.getSelectedIndex() < end_day_combobox.getSelectedIndex())
				return true;

			// Validate hours of start and end
			if(start_hour_combobox.getSelectedIndex() > end_hour_combobox.getSelectedIndex())
			{
				JOptionPane.showMessageDialog(this, "The start hour must less than or equal to the end hour");
				return false;
			}
			else if(start_hour_combobox.getSelectedIndex() < end_hour_combobox.getSelectedIndex())
				return true;

			// Validate minutes of start and end
			if(start_minute_combobox.getSelectedIndex() > end_minute_combobox.getSelectedIndex())
			{
				JOptionPane.showMessageDialog(this, "The start minute must less than or equal to the end minute");
				return false;
			}
			else if(start_minute_combobox.getSelectedIndex() < end_minute_combobox.getSelectedIndex())
				return true;
		}

		return true;
	}


	// Run on another thread
	private void audit_all_transaction_logs(final TransactionLogType transaction_log_type)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				ConfirmSignal            confirm_dialg_exiting        = new ConfirmSignal();
				AdminTransactionAuditing transaction_auditing_dialog;

				// Call transaction auditing object
				transaction_auditing_dialog = new AdminTransactionAuditing(main_panel, transaction_log_type, confirm_dialg_exiting);
				transaction_auditing_dialog.setVisible(true);

				try{
					// Wait for an exiting signal
					confirm_dialg_exiting.wait_signal();
				}
				catch(InterruptedException e)
				{
					e.printStackTrace();
				}

				SwingUtilities.invokeLater(new Runnable()
				{
					public void run()
					{
						transaction_log_thread_counter_lock.lock();

						transaction_log_thread_counter--;
						if(transaction_log_thread_counter == 0)
							working_lock.unlock();

						transaction_log_thread_counter_lock.unlock();
					}
				});
			}
		};

		thread.start();
	}

	// Run on another thread
	private void audit_some_period_time_transaction_logs(final TransactionLogType transaction_log_type, final int start_year_index, final int start_month_index, 
		final int start_day_index, final int start_hour_index, final int start_minute_index, final int end_year_index, final int end_month_index, 
		final int end_day_index, final int end_hour_index, final int end_minute_index)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				ConfirmSignal            confirm_dialg_exiting        = new ConfirmSignal();
				AdminTransactionAuditing transaction_auditing_dialog;

				// Call transaction auditing object
				transaction_auditing_dialog = new AdminTransactionAuditing(main_panel, transaction_log_type, start_year_index, start_month_index, 
					start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, 	
					end_minute_index, confirm_dialg_exiting);

				transaction_auditing_dialog.setVisible(true);

				try{
					// Wait for an exiting signal
					confirm_dialg_exiting.wait_signal();
				}
				catch(InterruptedException e)
				{
					e.printStackTrace();
				}

				SwingUtilities.invokeLater(new Runnable()
				{
					public void run()
					{
						transaction_log_thread_counter_lock.lock();

						transaction_log_thread_counter--;
						if(transaction_log_thread_counter == 0)
							working_lock.unlock();

						transaction_log_thread_counter_lock.unlock();
					}
				});
			}
		};

		thread.start();
	}

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{

		if(alert_msg.equals("Sending an e-mail failed (SSL connect error)")){
			if(m_is_reset_admin_pwd)
				m_result_reset_flag_admin_pwd = true;
			else
				m_result_reset_flag_user_pwd = true;
		}

		m_result_msg = alert_msg;

		//JOptionPane.showMessageDialog(main_panel, alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Notify alert message to user and then terminate the application
		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}

	private synchronized void clear_attribute_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				attribute_removal_button.setEnabled(false);
				user_registration_button.setEnabled(false);

				attribute_table_model.getDataVector().removeAllElements();
				attribute_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_attribute_to_table_callback_handler(final String attribute_name, final boolean is_numerical_attribute_flag)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				attribute_table_model.insertRow(attribute_table.getRowCount(), new Object[] {authority_name + 
						"." + attribute_name, (is_numerical_attribute_flag) ? "true" : "false"});

				user_registration_button.setEnabled(true);
			}
		});
	}

	private synchronized void clear_user_tree_table_callback_handler()
	{
		user_or_user_attribute_editing_button.setEnabled(false);
		user_passwd_resetting_button.setEnabled(false);
		user_or_user_attribute_removal_button.setEnabled(false);

		user_tree_table.clear_user_tree_table();
	}

	private synchronized void add_user_to_tree_table_callback_handler(final String username, final String email_address)
	{
		user_tree_table.add_user(username, this.authority_name, email_address);
	}

	private synchronized void attach_numerical_user_attribute_to_tree_table_callback_handler(final String username, 
		final String attribute_name, final String authority_name, final int attribute_value)
	{
		if(!user_tree_table.attach_numerical_user_attribute(username, attribute_name, authority_name, attribute_value))
			System.out.println("Attaching numical attribute \"" + authority_name + "." + attribute_name + "\" to user \"" + username + "\" failed");
	}

	private synchronized void attach_non_numerical_user_attribute_to_tree_table_callback_handler(final String username, 
		final String attribute_name, final String authority_name)
	{
		if(!user_tree_table.attach_non_numerical_user_attribute(username, attribute_name, authority_name))
			System.out.println("Attaching non-numical attribute \"" + authority_name + "." + attribute_name + "\" to user \"" + username + "\" failed");
	}

	private synchronized void repaint_user_tree_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				user_tree_table_panel.getViewport().remove(user_tree_table.get_user_tree_table());
				user_tree_table.repaint();
				user_tree_table_panel.getViewport().add(user_tree_table.get_user_tree_table());

				// Mouse listener for a user tree table
				set_user_tree_table_listener();

				user_or_user_attribute_editing_button.setEnabled(false);
				user_passwd_resetting_button.setEnabled(false);
				user_or_user_attribute_removal_button.setEnabled(false);
			}
		});
	}

	private synchronized void clear_admin_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				admin_editing_button.setEnabled(false);
				admin_passwd_resetting_button.setEnabled(false);
				admin_removal_button.setEnabled(false);

				admin_table_model.getDataVector().removeAllElements();
				admin_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_admin_to_table_callback_handler(final String username, final String email_address)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				admin_table_model.insertRow(admin_table.getRowCount(), new Object[] {username, email_address});
			}
		});
	}

	private synchronized void clear_authority_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				authority_editing_button.setEnabled(false);
				authority_removal_button.setEnabled(false);

				authority_table_model.getDataVector().removeAllElements();
				authority_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_authority_to_table_callback_handler(final String authority_name, final String ip_address, final boolean authority_join_flag)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				authority_table_model.insertRow(authority_table.getRowCount(), new Object[] {
					authority_name, ip_address, (authority_join_flag) ? "true" : "false"});
			}
		});
	}

	// ---------------------------------------------------------------------------------//
	// WEB
	public String getAuthorityName()
	{
		return authority_name;
	}

	public String getUsername()
	{
		return username + "(admin privilege)";
	}

	public String getEmail(){
		return email_address;
	}

	public String getAuditServerIP(){
		return audit_server_ip_addr;
	}

	public String getPhrServerIP()
	{
		return phr_server_ip_addr;
	}

	public String getEmergencyServerIP(){
		return emergency_server_ip_addr;
	}

	public String getMailServer(){
		return mail_server_url;
	}

	public String getAuthorityEmail(){
		return authority_email_address;
	}

	public Object getChangePasswdClass(){
		NewPasswordChanging new_passwd_changing_class = new NewPasswordChanging( true, passwd);
		return new_passwd_changing_class;
	}

	public void updateNewPasswd(String passwd){
		this.passwd = passwd;
	}

	public Object getChangeEmailClass(){
		EmailAddressChanging email_address_changing_class = new EmailAddressChanging( true, email_address, passwd);
		return email_address_changing_class;
	}

	public void updateNewEmail(String email_address){
		this.email_address = email_address;
		System.out.println(this.email_address);
	}

	public Object getServerAddressConfigClass(){
		ServerAddressesConfigurationChanging server_addresses_configuration_changing_class;
		server_addresses_configuration_changing_class = new ServerAddressesConfigurationChanging(
		audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr, passwd);
		return server_addresses_configuration_changing_class;
	}

	public Object getMailServerConfigClass(){
			MailServerConfigurationChanging mail_server_configuration_changing_class;
			mail_server_configuration_changing_class = new MailServerConfigurationChanging
			(mail_server_url, authority_email_address, authority_email_passwd, passwd);
			return mail_server_configuration_changing_class;
	}

	public void updateMailServer(MailServerConfigurationChanging mail_server_configuration_changing_class){
		mail_server_url         = mail_server_configuration_changing_class.get_updated_mail_server_url();
		authority_email_address = mail_server_configuration_changing_class.get_updated_authority_email_address();
		authority_email_passwd  = mail_server_configuration_changing_class.get_updated_authority_email_passwd();
	}

	public void updateServerAddressConfig(ServerAddressesConfigurationChanging server_addresses_configuration_changing){
		audit_server_ip_addr     = server_addresses_configuration_changing.get_updated_audit_server_ip_address();
		phr_server_ip_addr       = server_addresses_configuration_changing.get_updated_phr_server_ip_address();
		emergency_server_ip_addr = server_addresses_configuration_changing.get_updated_emergency_server_ip_address();
	}

	public boolean initAttributeTable(){
		attribute_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		attribute_table_model.setDataVector(null, new Object[] {"Attribute name", "Numerical attribute?"});
    		attribute_table = new JTable(attribute_table_model);
    		update_attribute_list_main();

    		return true;
	}

	public void updateAttributeTable(){
		update_attribute_list_main();
	}

	public Object[][] getTableAttribute () {
	    DefaultTableModel dtm = (DefaultTableModel) attribute_table.getModel();
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	public Object getRegistrationAttribute(){
		AttributeRegistration attribute_registration = new AttributeRegistration();
		return attribute_registration;
	}

	public boolean removeAttribute(String full_attribute_name){

		String attribute_name      = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);

		if(remove_attribute_main(attribute_name))
		{
			update_attribute_list_main();
			update_user_list_main();

			return true;
		}
		return false;
	}

	private AdminTransactionAuditing transaction_auditing_dialog;

	public boolean setAllLog(String transaction_log_type){

		if(transaction_log_type.equals(transaction_admin_login_log_type))
		{
			transaction_auditing_dialog = new AdminTransactionAuditing(TransactionLogType.ADMIN_LOGIN_LOG);
		}
		else if(transaction_log_type.equals(transaction_admin_event_log_type))
		{
			transaction_auditing_dialog = new AdminTransactionAuditing(TransactionLogType.ADMIN_EVENT_LOG);
		}
		else if(transaction_log_type.equals(transaction_system_login_log_type))
		{
			transaction_auditing_dialog = new AdminTransactionAuditing(TransactionLogType.SYSTEM_LOGIN_LOG);
		}
		else if(transaction_log_type.equals(transaction_system_event_log_type))
		{
			transaction_auditing_dialog = new AdminTransactionAuditing(TransactionLogType.SYSTEM_EVENT_LOG);
		}
		
		return true;
	}

	public Object[][] getLog(){
		
		// Call transaction auditing object

		return transaction_auditing_dialog.getTableLog();
	}

	public String getResultMsgTransaction(){
		
		// Call transaction auditing object

		return transaction_auditing_dialog.getResultMsg();
	}

	public boolean setPeriodLog(String transaction_log_type, final int start_year_index, final int start_month_index, 
		final int start_day_index, final int start_hour_index, final int start_minute_index, final int end_year_index, final int end_month_index, 
		final int end_day_index, final int end_hour_index, final int end_minute_index){

		TransactionLogType transaction_type;

		System.out.println(start_year_index);
		System.out.println(start_month_index);
		System.out.println(start_day_index);
		System.out.println(start_hour_index);
		System.out.println(start_minute_index);
		System.out.println(end_year_index);
		System.out.println(end_month_index);
		System.out.println(end_day_index);
		System.out.println(end_hour_index);
		System.out.println(end_minute_index);

		if(validate_transaction_log_search_input_web(start_year_index, start_month_index, 
					start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, 	
					end_minute_index)){

			if(transaction_log_type.equals(transaction_admin_login_log_type))
			{
				transaction_type = TransactionLogType.ADMIN_LOGIN_LOG;
				// Call transaction auditing object
				transaction_auditing_dialog = new AdminTransactionAuditing(transaction_type, start_year_index, start_month_index, 
						start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, 	
						end_minute_index);
			}
			else if(transaction_log_type.equals(transaction_admin_event_log_type))
			{
				transaction_type = TransactionLogType.ADMIN_EVENT_LOG;
				// Call transaction auditing object
				transaction_auditing_dialog = new AdminTransactionAuditing(transaction_type, start_year_index, start_month_index, 
						start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, 	
						end_minute_index);
			}
			else if(transaction_log_type.equals(transaction_system_login_log_type))
			{
				transaction_type = TransactionLogType.SYSTEM_LOGIN_LOG;
				// Call transaction auditing object
				transaction_auditing_dialog = new AdminTransactionAuditing(transaction_type, start_year_index, start_month_index, 
						start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, 	
						end_minute_index);
			}
			else if(transaction_log_type.equals(transaction_system_event_log_type))
			{
				transaction_type = TransactionLogType.SYSTEM_EVENT_LOG;
				// Call transaction auditing object
				transaction_auditing_dialog = new AdminTransactionAuditing(transaction_type, start_year_index, start_month_index, 
						start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, end_hour_index, 	
						end_minute_index);
			}

			return true;
		}
		else {
			return false;
		}
	}

	private String result_msg_validate_transaction;

	public String getResultMsgValidateTransaction(){
		return result_msg_validate_transaction;
	}

	private boolean validate_transaction_log_search_input_web(final int start_year_index, final int start_month_index, 
		final int start_day_index, final int start_hour_index, final int start_minute_index, final int end_year_index, final int end_month_index, 
		final int end_day_index, final int end_hour_index, final int end_minute_index)
	{
			// Validate years of start and end
			if(start_year_index > end_year_index)
			{
				//JOptionPane.showMessageDialog(this, "The start year must less than or equal to the end year");
				result_msg_validate_transaction = "The start year must less than or equal to the end year";
				return false;
			}
			else if(start_year_index < end_year_index)
				return true;
	
			// Validate months of start and end
			if(start_month_index > end_month_index)
			{
				// JOptionPane.showMessageDialog(this, "The start month must less than or equal to the end month");
				result_msg_validate_transaction = "The start month must less than or equal to the end month";
				return false;
			}
			else if(start_month_index < end_month_index)
				return true;

			// Validate days of start and end
			if(start_day_index > end_day_index)
			{
				// JOptionPane.showMessageDialog(this, "The start day must less than or equal to the end day");
				result_msg_validate_transaction = "The start day must less than or equal to the end day";
				return false;
			}
			else if(start_day_index < end_day_index)
				return true;

			// Validate hours of start and end
			if(start_hour_index > end_hour_index)
			{
				// JOptionPane.showMessageDialog(this, "The start hour must less than or equal to the end hour");
				result_msg_validate_transaction = "The start hour must less than or equal to the end hour";
				return false;
			}
			else if(start_hour_index < end_hour_index)
				return true;

			// Validate minutes of start and end
			if(start_minute_index > end_minute_index)
			{
				// JOptionPane.showMessageDialog(this, "The start minute must less than or equal to the end minute");
				result_msg_validate_transaction = "The start minute must less than or equal to the end minute";
				return false;
			}
			else if(start_minute_index < end_minute_index)
				return true;

			return true;
	}


	public boolean initAdminTable(){		

		// Admins

		admin_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		admin_table_model.setDataVector(null, new Object[] {"Username", "E-mail address"});
    		admin_table = new JTable(admin_table_model);

    		update_admin_list_main();

    	return true;
    }
	
	public Object[][] getTableAdmin () {
	    DefaultTableModel dtm = (DefaultTableModel) admin_table.getModel();
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	public Object getRegisterAdminClass(){
		AdminManagement admin_registration_class = new AdminManagement();
		return admin_registration_class;
	}

	public  void updateAdminList(){
		update_admin_list_main();
	}

	public  void updateUserList(){
		update_user_list_main();
	}

	public boolean removeAdmin(String username){
		
		if(remove_admin_main(username))
		{
			update_admin_list_main();

			return true;
		}
		else{
			return false;
		}
	}

	public void resetPasswordAdmin(String username){
		m_is_reset_admin_pwd = true;
		// Call to C functions
		if(reset_admin_passwd_main(username))
		{
			update_admin_list_main();
			m_result_reset_flag_admin_pwd = true;
			m_result_msg = "The new admin's password " + "was sent to the admin's e-mail address already";
		}
		else {
			m_result_reset_flag_admin_pwd = false;
			//m_result_msg = "Can't Send new password to email address";
		}
	}

	public boolean getResultFlagResetAdminPwd(){
		return m_result_reset_flag_admin_pwd;
	}

	AdminManagement admin_editing;

	public void initEditAdminClass(String username,String email_address){
		admin_editing = new AdminManagement(username, email_address);
	}

	public Object getEditAdminClass(){
		return admin_editing ;
	}


	public boolean initAuthorityTable(){		

		// Authorities

		authority_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		authority_table_model.setDataVector(null, new Object[] {"Authority name", "IP address", "Join status"});
    		authority_table = new JTable(authority_table_model);

    		update_authority_list_main();

    	return true;
    }

    public Object[][] getTableAuthority () {
	    DefaultTableModel dtm = (DefaultTableModel) authority_table.getModel();
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	public Object getAuthorityManagementRegisterClass(){
		AuthorityManagement authority_registration = new AuthorityManagement();
		return authority_registration;
	}

	AuthorityManagement authority_editing ;

	public void initAuthorityManagementEditClass(String authority_name, String ip_address){
		authority_editing = new AuthorityManagement(authority_name, ip_address);
	}

	public Object getAuthorityManagementEditClass(){
		return authority_editing;
	}

	public  void updateAuthorityList(){
		update_authority_list_main();
	}

	public boolean removeAuthority(String authority_name){

		if(remove_authority_main(authority_name))
		{
			update_authority_list_main();
			return true;
		}
		else
		{	
			return false;
		}
	}

	public void initUserTable(){
		user_tree_table = new UserTreeTable();
	}

	public Object[] initAllUserNodeFromUserTreeTable()
	{

		m_user_tree.clear();

		System.out.println("Test User");

		int index = 0;

		int i;
		int base             = 0;
		int child_root_count = user_tree_table.get_user_tree_table_model().getChildCount(user_tree_table.get_user_tree_table_root());

		System.out.println("Child root count : " + child_root_count);

		for(i=0; i < child_root_count ; i++)
		{
			UserTreeTableNode node   = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(
				user_tree_table.get_user_tree_table_root(), i);

			System.out.println("M " + i +  " " + node.getName() + " " + node.getType() + " " + node.getEmailAddress());

			m_user_tree.add("M+" + node.getName() + "+" + node.getType() + "+" + node.getEmailAddress());

			index ++;

			int child_sub_root_count = user_tree_table.get_user_tree_table_model().getChildCount(node);

				for(int j=0; j < child_sub_root_count; j++)  // At an attribute level
				{
					UserTreeTableNode attribute_node = (UserTreeTableNode)user_tree_table.get_user_tree_table_model().getChild(node, j);
					System.out.println("C" + j +  " " + attribute_node.getName() + "" + attribute_node.getType());
					m_user_tree.add("C+" + attribute_node.getNameTableCell() + "+" + attribute_node.getType());
					index++;
				}
		}

		System.out.println("End Test User");

		return m_user_tree.toArray();
	}

	Object m_user_manage;

	public void setUserManagement(){
		m_user_manage = new UserManagement(attribute_table_model);
	}

	public Object getUserManagement(){
		return m_user_manage;
	}

	public void resetPasswordUser(String username){
		m_is_reset_admin_pwd = false;
		if(reset_user_passwd_main(username))
		{
			update_attribute_list_main();
			update_user_list_main();

			m_result_reset_flag_user_pwd = true;

			m_result_msg = "The new user's password " + "was sent to the user's e-mail address already";
		}	
		else {
			m_result_reset_flag_user_pwd = false;
			//m_result_msg = "Can't Send new password to email address";
		}
	}

	public String getResultMsg(){
		return m_result_msg;
	}

	public boolean getResultFlagResetUserPwd(){
		return m_result_reset_flag_user_pwd;
	}

	public boolean removeUser(int selected_row){
		if(selected_row >= 0)
		{
			if(is_selected_row_user(selected_row))   // User
			{
				// int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
				// 	"Are you sure to remove this user?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

				String username = get_selected_username_from_user_tree_table(selected_row);

					// Call to C functions
				if(remove_user_main(username))
				{
					update_attribute_list_main();
					update_user_list_main();

					return true;
				}
				else
					return false;
			}
			else  // User attribute
			{
						// int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
						// 			"Are you sure to remove this user attribute?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

				String username                 = get_root_username_from_user_tree_table(selected_row);
				String full_attribute_name      = get_selected_full_attribute_name_from_user_tree_table(selected_row);
				String attribute_name           = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);
				String attribute_authority_name = full_attribute_name.substring(0, full_attribute_name.indexOf("."));

				// Call to C functions
				if(remove_user_attribute_main(username, attribute_name, attribute_authority_name))
				{
					update_attribute_list_main();
					update_user_list_main();

					return true;
				}
				else
					return false;
			}
		}
		else
			return false;
	}

	public void setEditUserClass(int selected_row){
		System.out.println(selected_row);
		if(selected_row >= 0)
		{
			if(is_selected_row_user(selected_row))
			{
				System.out.println("Edit USer");
				// Call user management object
				UserManagement user_editing_dialog = new UserManagement(attribute_table_model, user_tree_table, selected_row);
				m_user_manage = user_editing_dialog;
			}
			else if(is_selected_row_editable_attribute(selected_row))
			{

				System.out.println("Edit Attribute");
				NumericalAttributeValueEditing attribute_value_editing_dialog;

				// Call numerical attribute value editing object
				attribute_value_editing_dialog = new NumericalAttributeValueEditing(main_panel, user_tree_table, selected_row);
				m_user_manage = attribute_value_editing_dialog;
			}
		}
		else
			m_user_manage = null;
	}

	private Object m_editAttribute;

	public void setEditAttributeClass(int selected_row){

		NumericalAttributeValueEditing attribute_value_editing_dialog;

		// Call numerical attribute value editing object
		attribute_value_editing_dialog = new NumericalAttributeValueEditing(user_tree_table, selected_row);
	
		m_editAttribute = attribute_value_editing_dialog;
	} 

	public Object getEditAttributeClass(){
		return m_editAttribute;
	}

	public void closeProgram(){
		System.exit(0);
	}

}




