import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import java.util.regex.*;
import javax.swing.border.*;

import java.util.Arrays;

import java.io.*;

import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.*;

import org.jdesktop.swingx.*;
import org.jdesktop.swingx.treetable.*;

import org.apache.commons.lang3.*;

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;
import java.math.*;

public class UserMain extends JFrame implements ConstantVars
{
	private static final long serialVersionUID = -1113582265865927788L;

	// Declaration of the Native C functions
	private native void init_backend();
	private native void store_variables_to_backend(String ssl_cert_hash, String cpabe_priv_key_hash, String username, String authority_name, 
		String passwd, String user_auth_ip_addr, String audit_server_ip_addr, String phr_server_ip_addr, String emergency_server_ip_addr);
	private native void update_authority_list_main();
	private native void update_user_attribute_list_main();
	private native void update_assigned_access_permission_list_main();
	private native void update_attribute_list_main(String authority_name);
	private native void update_emergency_trusted_user_list_main();
	private native void update_emergency_phr_owner_list_main();
	private native void update_restricted_phr_access_request_list_main();
	private native boolean check_user_existence_main(String authority_name, String username);
	private native boolean verify_upload_permission_main(String phr_owner_name, String phr_owner_authority_name);
	private native boolean verify_download_permission_main(String phr_owner_name, String phr_owner_authority_name);
	private native boolean verify_delete_permission_main(String phr_owner_name, String phr_owner_authority_name);
	private native boolean generate_unique_emergency_key_main(String unique_emergency_key_attribute, String unique_emergency_key_passwd);
	private native boolean encrypt_threshold_secret_keys_main(String[] ea_trusted_user_list);
	private native boolean upload_unique_emergency_key_params_main(int remote_site_phr_id, int threshold_value, String[] ea_trusted_user_list);
	private native boolean change_restricted_level_phr_to_excusive_level_phr_main(int remote_site_phr_id);
	private native boolean encrypt_phr_main(String phr_upload_from_path, String access_policy);
	private native void cancel_phr_encrypting_main();
	private native boolean upload_phr_main(String phr_owner_name, String phr_owner_authority_name, String data_description, String confidentiality_level_flag);
	private native void cancel_phr_uploading_main();
	private native boolean download_phr_main(String phr_owner_name, String phr_owner_authority_name, int phr_id);
	private native void cancel_phr_downloading_main();
	private native boolean decrypt_phr_main(String phr_download_to_path);
	private native void cancel_phr_decrypting_main();
	private native boolean delete_phr_main(String phr_owner_name, String phr_owner_authority_name, int phr_id);
	private native boolean remove_restricted_level_phr_key_params_main(String phr_owner_name, String phr_owner_authority_name, int remote_site_phr_id);
	private native boolean load_downloading_authorized_phr_list_main(String phr_owner_name, String phr_owner_authority_name);
	private native boolean load_deletion_authorized_phr_list_main(String phr_owner_name, String phr_owner_authority_name);
	private native void record_phr_encrypting_transaction_log_main(String phr_owner_name, String phr_owner_authority_name, String phr_description, boolean success_flag);
	private native void record_phr_uploading_transaction_log_main(String phr_owner_name, String phr_owner_authority_name, String phr_description, boolean success_flag);
	private native void record_phr_downloading_transaction_log_main(String phr_owner_name, String phr_owner_authority_name, String phr_description, boolean success_flag);
	private native void record_phr_decrypting_transaction_log_main(String phr_owner_name, String phr_owner_authority_name, String phr_description, boolean success_flag);
	private native void record_phr_deletion_transaction_log_main(String phr_owner_name, String phr_owner_authority_name, String phr_description, boolean success_flag);
	private native void record_failed_uploading_emergency_key_params_transaction_log_main(String phr_owner_name, String phr_owner_authority_name, String phr_description);
	private native boolean remove_access_permission_main(String desired_user_authority_name, String desired_username);
	private native void remove_all_threshold_parameters_in_cache_main(int no_trusted_users);
	private native boolean approve_restricted_phr_access_request_main(String phr_ownername, String phr_owner_authority_name, int phr_id, String phr_description, 
		String emergency_staff_name, String emergency_unit_name);

	// Variables get from node
	private String 			  m_authority_name_node_js;

	// Variables
	private JPanel            main_panel                                                = new JPanel();
	private ReentrantLock     working_lock                                              = new ReentrantLock();
	private ShutdownHook      shutdown_hooker;

	private ArrayList<String> authority_name_list                                       = new ArrayList<String>();

	// Info page
	private JPanel            info_page                                                 = new JPanel();
	private JTextField        email_address_textfield                                   = new JTextField(TEXTFIELD_LENGTH);

	private DefaultTableModel user_attribute_table_model;
	private JTable            user_attribute_table;

	private JButton           change_passwd_button                                      = new JButton("Change a password");
	private JButton           change_email_address_button                               = new JButton("Change an e-mail address");

	// Access permission page
	private JPanel            access_permission_page                                    = new JPanel();
	private DefaultTableModel access_permission_table_model;
	private JTable            access_permission_table;

	private JButton           access_permission_assignment_button                       = new JButton("Assign permissions");
	private JButton           access_permission_editing_button                          = new JButton("Edit");
	private JButton           access_permission_removal_button                          = new JButton("Remove");
	private JButton           access_permission_page_refresh_info_button                = new JButton("Refresh");

	// PHR management page
	private JPanel            phr_management_outer_panel                                = new JPanel();
	private JScrollPane       phr_management_scollpane_page                             = new JScrollPane(phr_management_outer_panel);

	private JComboBox         phr_owner_authority_name_combobox;
	private JTextField        phr_owner_name_textfield;

	private JRadioButton[]    transaction_type_radio_buttons                            = new JRadioButton[3];
       	private ButtonGroup       transaction_type_group;
        private final String      phr_uploading_type                                        = new String("Upload a PHR");
        private final String      phr_downloading_type                                      = new String("Download a PHR");
	private final String      phr_deletion_type                                         = new String("Delete a PHR");

	private JButton           search_phr_owner_button                                   = new JButton("Search");

	// PHR uploading mode
	private JTextField        phr_upload_from_path_textfield;
	private JButton           browse_phr_upload_from_path_button                        = new JButton("Browse");

	private JTextArea         data_description_textarea;
	private JScrollPane       data_description_scrollpane;

	private JRadioButton[]    confidentiality_level_radio_buttons                       = new JRadioButton[3];
       	private ButtonGroup       confidentiality_level_group;
        private final String      phr_exclusive_level                                       = new String("Exclusive level");
        private final String      phr_restricted_level                                      = new String("Restricted level");
	private final String      phr_secure_level                                          = new String("Secure level");

	private JTextField        threshold_value_textfield;
	private JTextField        no_trusted_users_textfield;
	private int		  remote_site_phr_id;

	private AccessPolicyTree  access_policy_tree;
	private JButton           edit_attribute_button                                     = new JButton("Edit");
	private JButton           delete_attribute_button                                   = new JButton("Delete");

	private JComboBox         attribute_authority_name_combobox;
	private DefaultTableModel attribute_table_model;
	private JTable            attribute_table;
	private JButton           add_attribute_button                                      = new JButton("Add");

	private JComboBox         user_authority_name_combobox;
	private JTextField        username_for_access_policy_textfield;
	private JButton           add_user_button                                           = new JButton("Add");

	private JButton           upload_phr_button                                         = new JButton("Upload");
	private JButton           quit_phr_uploading_button                                 = new JButton("Quit");

	private JProgressBar      phr_encrypting_progressbar;
	private JProgressBar      phr_uploading_progressbar;
	private JButton           cancel_phr_uploading_transaction_button                   = new JButton("Cancel");

	private ActionListener    browse_phr_upload_from_path_button_actionlistener;
	private ActionListener    confidentiality_level_radio_buttons_actionlistener;
	private MouseAdapter      access_policy_tree_mouselistener;
	private ActionListener    edit_attribute_button_actionlistener;
	private ActionListener    delete_attribute_button_actionlistener;
	private ActionListener    attribute_authority_name_combobox_actionlistener;
	private MouseAdapter      attribute_table_mouseadapter;
	private ActionListener    add_attribute_button_actionlistener;
	private ActionListener    add_user_button_actionlistener;
	private ActionListener    upload_phr_button_actionlistener;
	private ActionListener    quit_phr_uploading_button_actionlistener;	
	private ActionListener    cancel_phr_uploading_transaction_button_actionlistener;

	private boolean           phr_encrypting_state_flag;
	private boolean           phr_uploading_state_flag;
	private boolean           cancel_phr_uploading_flag;

	private boolean           is_phr_uploaded_by_its_owner;
	private final int         phr_uploading_confidentiality_interface_preferred_size    = 200;

	// PHR downloading mode
	private DefaultTableModel phr_downloading_table_model;
	private JTable            phr_downloading_table;

	private JTextField        phr_download_to_path_textfield;
	private JButton           browse_phr_download_to_path_button                        = new JButton("Browse");

	private JButton           download_phr_button                                       = new JButton("Download");
	private JButton           quit_phr_downloading_button                               = new JButton("Quit");

	private JProgressBar      phr_downloading_progressbar;
	private JProgressBar      phr_decrypting_progressbar;
	private JButton           cancel_phr_downloading_transaction_button                 = new JButton("Cancel");

	private MouseAdapter      phr_downloading_table_mouseadapter;
	private ActionListener    browse_phr_download_to_path_button_actionlistener;
	private ActionListener    download_phr_button_actionlistener;
	private ActionListener    quit_phr_downloading_button_actionlistener;	
	private ActionListener    cancel_phr_downloading_transaction_button_actionlistener;

	private boolean           phr_downloading_state_flag;
	private boolean           phr_decrypting_state_flag;
	private boolean           cancel_phr_downloading_flag;

	// PHR deletion mode
	private DefaultTableModel phr_deletion_table_model;
	private JTable            phr_deletion_table;

	private JButton           delete_phr_button                                         = new JButton("Delete");
	private JButton           quit_phr_deletion_button                                  = new JButton("Quit");

	private MouseAdapter      phr_deletion_table_mouseadapter;
	private ActionListener    delete_phr_button_actionlistener;
	private ActionListener    quit_phr_deletion_button_actionlistener;

	// Emergency access management page
	private JPanel            emergency_access_management_outer_panel                   = new JPanel();
	private JScrollPane       emergency_access_management_scollpane_page                = new JScrollPane(emergency_access_management_outer_panel);

	private DefaultTableModel ea_trusted_user_table_model;
	private JTable            ea_trusted_user_table;

	private JButton           ea_trusted_user_add_button                                = new JButton("Add a user");
	private JButton           ea_trusted_user_removal_button                            = new JButton("Remove");
	private JButton           ea_trusted_user_refresh_info_button                       = new JButton("Refresh");

	private DefaultTableModel ea_phr_owner_table_model;
	private JTable            ea_phr_owner_table;

	private JButton           ea_phr_owner_declination_button                           = new JButton("Decline a delegate");
	private JButton           ea_phr_owner_refresh_info_button                          = new JButton("Refresh");

	private DefaultTableModel ea_restricted_phr_access_request_table_model;
	private JTable            ea_restricted_phr_access_request_table;

	private JButton           ea_phr_owner_request_cancel_button                        = new JButton("Cancel a request");
	private JButton           ea_trusted_user_approval_button                           = new JButton("Approve");
	private JButton           ea_trusted_user_no_approval_button                        = new JButton("Not approve");
	private JButton           ea_restricted_phr_access_request_refresh_info_button      = new JButton("Refresh");

	// Transaction auditing page
	private JPanel            transaction_auditing_page                                 = new JPanel();

	private JRadioButton[]    transaction_log_type_radio_buttons                        = new JRadioButton[2];
       	private ButtonGroup       transaction_log_type_group;
        private final String      transaction_login_log_type                                = new String("Audit a login Log");
        private final String      transaction_event_log_type                                = new String("Audit an event Log");

	private JCheckBox         audit_all_transactions_checkbox                           = new JCheckBox("Audit all transactions", true);

	private Calendar          start_date_calendar                                       = Calendar.getInstance();
	private JComboBox         start_year_combobox;
	private JComboBox         start_month_combobox;
	private JComboBox         start_day_combobox;

	private JComboBox         start_hour_combobox;
	private JComboBox         start_minute_combobox;

	private Calendar          end_date_calendar                                         = Calendar.getInstance();
	private JComboBox         end_year_combobox;
	private JComboBox         end_month_combobox;
	private JComboBox         end_day_combobox;

	private JComboBox         end_hour_combobox;
	private JComboBox         end_minute_combobox;

	private JButton           search_transaction_log_button                             = new JButton("Search");

	private int               transaction_log_thread_counter                            = 0;
	private ReentrantLock     transaction_log_thread_counter_lock                       = new ReentrantLock();

	// Statusbar
	private JLabel            statusbar_label                                           = new JLabel("");

	// Derive from Login object 
	private String username;
	private String passwd;
	private String email_address;
	private String authority_name;
	private String user_auth_ip_addr;
	private String audit_server_ip_addr;
	private String phr_server_ip_addr;
	private String emergency_server_ip_addr;

	// Class variable for web
	private String m_phr_owner_name;
	private int m_index_list_download;
	private String m_threshold_value  ;
	private String m_no_trusted_users ;
	private boolean m_isFinish ;
	private boolean m_result_download;


	public UserMain(String username, String passwd, String email_address, String authority_name, String user_auth_ip_addr, String audit_server_ip_addr, 
		String phr_server_ip_addr, String emergency_server_ip_addr, String ssl_cert_hash, String cpabe_priv_key_hash)
	{
		super("PHR system: User Main");

		System.out.println("OLD USERNAME: " + this.username);
		System.out.println("NEW USERNAME: " + username);

		this.username                 = username;
		this.email_address            = email_address;
		this.passwd                   = passwd;
		this.authority_name           = authority_name;
		this.user_auth_ip_addr        = user_auth_ip_addr;
		this.audit_server_ip_addr     = audit_server_ip_addr;
		this.phr_server_ip_addr       = phr_server_ip_addr;
		this.emergency_server_ip_addr = emergency_server_ip_addr;
		
		// Load JNI backend library
		System.loadLibrary("PHRapp_User_JNI");

		working_lock.lock();

		// Call to C functions
		init_backend();
		store_variables_to_backend(ssl_cert_hash, cpabe_priv_key_hash, username, authority_name, 
			passwd, user_auth_ip_addr, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr);

		update_authority_list_main();

		init_ui();
		init_actions_for_phr_uploading_mode();
		init_actions_for_phr_uploading_transaction_mode();
		init_actions_for_phr_downloading_mode();
		init_actions_for_phr_downloading_transaction_mode();
		init_actions_for_phr_deletion_mode();
		setup_actions();

		// Call to C functions
		update_user_attribute_list_main();
		update_assigned_access_permission_list_main();
		update_emergency_trusted_user_list_main();
		update_emergency_phr_owner_list_main();
		update_restricted_phr_access_request_list_main();

		working_lock.unlock();

		automatic_relogin();
	}

	private final void init_ui()
	{
		main_panel.setLayout(new BorderLayout());

		create_info_page();
		create_access_permission_page();
		create_phr_management_page();
		create_emergency_access_management_outer_panel();
		create_transaction_auditing_page();

		JTabbedPane tabbed_pane = new JTabbedPane();
		tabbed_pane.addTab("Info", info_page);
		tabbed_pane.addTab("Access Permission Management", access_permission_page);
		tabbed_pane.addTab("PHR Management", phr_management_scollpane_page);
		tabbed_pane.addTab("Emergency Access Management", emergency_access_management_scollpane_page);
		tabbed_pane.addTab("Transaction Auditing", transaction_auditing_page);
		main_panel.add(tabbed_pane, BorderLayout.CENTER);
		main_panel.add(statusbar_label, BorderLayout.SOUTH);

		getContentPane().add(main_panel);

		setSize(600, 540);
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
		username_textfield.setText(username);
		username_textfield.setEditable(false);

		// Email address
		JLabel email_address_label = new JLabel("E-mail address: ", JLabel.RIGHT);

		email_address_textfield.setText(email_address);
		email_address_textfield.setEditable(false);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(authority_name_label);
		upper_inner_panel.add(authority_name_textfield);
		upper_inner_panel.add(username_label);
		upper_inner_panel.add(username_textfield);
		upper_inner_panel.add(email_address_label);
		upper_inner_panel.add(email_address_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 3, 2, 5, 0, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(430, 110));
		upper_outer_panel.setMaximumSize(new Dimension(430, 110));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// User attributes
		JLabel user_attribute_label = new JLabel("User Attributes");

		user_attribute_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		user_attribute_table_model.setDataVector(null, new Object[] {"Attribute name"});
    		user_attribute_table = new JTable(user_attribute_table_model);
		user_attribute_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane user_attribute_table_panel = new JScrollPane();
		user_attribute_table_panel.setPreferredSize(new Dimension(300, 150));
		user_attribute_table_panel.setMaximumSize(new Dimension(300, 150));
		user_attribute_table_panel.setAlignmentX(0.0f);
		user_attribute_table_panel.getViewport().add(user_attribute_table);

		// Change password and e-mail address buttons
		change_passwd_button.setAlignmentX(0.5f);
		change_email_address_button.setAlignmentX(0.5f);

		JPanel main_buttons_panel = new JPanel();
		main_buttons_panel.setPreferredSize(new Dimension(430, 30));
		main_buttons_panel.setMaximumSize(new Dimension(430, 30));
		main_buttons_panel.setAlignmentX(0.0f);
		main_buttons_panel.add(change_passwd_button);
		main_buttons_panel.add(change_email_address_button);

		// Basic info panel
		JPanel basic_info_inner_panel = new JPanel();
		basic_info_inner_panel.setLayout(new BoxLayout(basic_info_inner_panel, BoxLayout.Y_AXIS));
		basic_info_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		basic_info_inner_panel.setPreferredSize(new Dimension(450, 320));
		basic_info_inner_panel.setMaximumSize(new Dimension(450, 320));
		basic_info_inner_panel.setAlignmentX(0.0f);
		basic_info_inner_panel.add(upper_outer_panel);
		basic_info_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		basic_info_inner_panel.add(user_attribute_label);
		basic_info_inner_panel.add(user_attribute_table_panel);
		basic_info_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		basic_info_inner_panel.add(main_buttons_panel);
		basic_info_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));

		JPanel basic_info_outer_panel = new JPanel(new GridLayout(0, 1));
		basic_info_outer_panel.setLayout(new BoxLayout(basic_info_outer_panel, BoxLayout.Y_AXIS));
    		basic_info_outer_panel.setBorder(BorderFactory.createTitledBorder("Basic Info"));
		basic_info_outer_panel.setAlignmentX(0.5f);
		basic_info_outer_panel.add(basic_info_inner_panel);

		JPanel basic_info_panel = new JPanel();
		basic_info_panel.setPreferredSize(new Dimension(600, 350));
		basic_info_panel.setMaximumSize(new Dimension(600, 350));
		basic_info_panel.setAlignmentX(0.0f);
		basic_info_panel.add(basic_info_outer_panel);

		// Info page
		info_page.setLayout(new BoxLayout(info_page, BoxLayout.Y_AXIS));
		info_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		info_page.add(basic_info_panel);
	}

	private final void create_access_permission_page()
	{
		// Access permissions
		JLabel access_permission_label = new JLabel("Access Permissions");

		access_permission_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    	access_permission_table_model.setDataVector(null, new Object[] {"Name", "Upload Permission?", 
			"Download Permission?", "Delete Permission?"});

    	access_permission_table = new JTable(access_permission_table_model);
		access_permission_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane access_permission_table_panel = new JScrollPane();
		access_permission_table_panel.setPreferredSize(new Dimension(600, 200));
		access_permission_table_panel.setMaximumSize(new Dimension(600, 200));
		access_permission_table_panel.setAlignmentX(0.0f);
		access_permission_table_panel.getViewport().add(access_permission_table);

		// Access permission buttons
		access_permission_assignment_button.setAlignmentX(0.5f);
		access_permission_editing_button.setAlignmentX(0.5f);
		access_permission_removal_button.setAlignmentX(0.5f);
		access_permission_editing_button.setEnabled(false);
		access_permission_removal_button.setEnabled(false);

		JPanel access_permission_buttons_panel = new JPanel();
		access_permission_buttons_panel.setPreferredSize(new Dimension(600, 30));
		access_permission_buttons_panel.setMaximumSize(new Dimension(600, 30));
		access_permission_buttons_panel.setAlignmentX(0.0f);
		access_permission_buttons_panel.add(access_permission_assignment_button);
		access_permission_buttons_panel.add(access_permission_editing_button);
		access_permission_buttons_panel.add(access_permission_removal_button);

		// Refresh button
		access_permission_page_refresh_info_button.setAlignmentX(0.5f);

		JPanel access_permission_page_refresh_info_button_panel = new JPanel();
		access_permission_page_refresh_info_button_panel.setPreferredSize(new Dimension(600, 30));
		access_permission_page_refresh_info_button_panel.setMaximumSize(new Dimension(600, 30));
		access_permission_page_refresh_info_button_panel.setAlignmentX(0.0f);
		access_permission_page_refresh_info_button_panel.add(access_permission_page_refresh_info_button);

		access_permission_page.setLayout(new BoxLayout(access_permission_page, BoxLayout.Y_AXIS));
		access_permission_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		access_permission_page.add(access_permission_label);
		access_permission_page.add(access_permission_table_panel);
		access_permission_page.add(Box.createRigidArea(new Dimension(0, 10)));
		access_permission_page.add(access_permission_buttons_panel);
		access_permission_page.add(Box.createRigidArea(new Dimension(0, 10)));
		access_permission_page.add(access_permission_page_refresh_info_button_panel);
	}

	private final void create_phr_management_page()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
	
		phr_owner_authority_name_combobox = new JComboBox();
		phr_owner_authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setMaximumSize(new Dimension(60, 25));
		init_phr_owner_authority_name_combobox();

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield    = new JTextField(TEXTFIELD_LENGTH);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.add(phr_owner_authority_name_label);
		upper_inner_panel.add(phr_owner_authority_name_combobox);
		upper_inner_panel.add(phr_owner_name_label);
		upper_inner_panel.add(phr_owner_name_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(400, 80));
		upper_outer_panel.setMaximumSize(new Dimension(400, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// Transaction type
        	transaction_type_radio_buttons[0] = new JRadioButton(phr_uploading_type);
        	transaction_type_radio_buttons[0].setActionCommand(phr_uploading_type);
		transaction_type_radio_buttons[0].setSelected(false);

		transaction_type_radio_buttons[1] = new JRadioButton(phr_downloading_type);
        	transaction_type_radio_buttons[1].setActionCommand(phr_downloading_type);
		transaction_type_radio_buttons[1].setSelected(false);

		transaction_type_radio_buttons[2] = new JRadioButton(phr_deletion_type);
        	transaction_type_radio_buttons[2].setActionCommand(phr_deletion_type);
		transaction_type_radio_buttons[2].setSelected(false);

		transaction_type_group = new ButtonGroup();
            	transaction_type_group.add(transaction_type_radio_buttons[0]);
		transaction_type_group.add(transaction_type_radio_buttons[1]);
		transaction_type_group.add(transaction_type_radio_buttons[2]);

		// Transaction type panel
		JPanel transaction_type_inner_panel = new JPanel();
		transaction_type_inner_panel.setLayout(new BoxLayout(transaction_type_inner_panel, BoxLayout.Y_AXIS));
		transaction_type_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		transaction_type_inner_panel.setPreferredSize(new Dimension(230, 100));
		transaction_type_inner_panel.setMaximumSize(new Dimension(230, 100));
		transaction_type_inner_panel.setAlignmentX(0.0f);
		transaction_type_inner_panel.add(transaction_type_radio_buttons[0]);
		transaction_type_inner_panel.add(transaction_type_radio_buttons[1]);
		transaction_type_inner_panel.add(transaction_type_radio_buttons[2]);

		JPanel transaction_type_outer_panel = new JPanel(new GridLayout(0, 1));
		transaction_type_outer_panel.setLayout(new BoxLayout(transaction_type_outer_panel, BoxLayout.Y_AXIS));
    		transaction_type_outer_panel.setBorder(BorderFactory.createTitledBorder("Transaction"));
		transaction_type_outer_panel.setAlignmentX(0.5f);
		transaction_type_outer_panel.add(transaction_type_inner_panel);

		// Search PHR owner button
		search_phr_owner_button.setAlignmentX(0.5f);	

		JPanel search_phr_owner_button_panel = new JPanel();
		search_phr_owner_button_panel.setPreferredSize(new Dimension(400, 30));
		search_phr_owner_button_panel.setMaximumSize(new Dimension(400, 30));
		search_phr_owner_button_panel.setAlignmentX(0.0f);
		search_phr_owner_button_panel.add(search_phr_owner_button);

		JPanel phr_management_inner_panel = new JPanel();
		phr_management_inner_panel.setPreferredSize(new Dimension(420, 250));
		phr_management_inner_panel.setMaximumSize(new Dimension(420, 250));
		phr_management_inner_panel.setAlignmentX(0.5f);
		phr_management_inner_panel.add(upper_outer_panel);
		phr_management_inner_panel.add(transaction_type_outer_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_management_inner_panel.add(search_phr_owner_button_panel);	

		phr_management_outer_panel.setLayout(new BoxLayout(phr_management_outer_panel, BoxLayout.Y_AXIS));
		phr_management_outer_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		phr_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 50)));
		phr_management_outer_panel.add(phr_management_inner_panel);
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private final void create_emergency_access_management_outer_panel()
	{
		// ------------------- Your Trusted Users ----------------------
		JLabel ea_trusted_user_label = new JLabel("Your Trusted Users");

		ea_trusted_user_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1513582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		ea_trusted_user_table_model.setDataVector(null, new Object[] {"Name"});

    		ea_trusted_user_table = new JTable(ea_trusted_user_table_model);
		ea_trusted_user_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane ea_trusted_user_table_panel = new JScrollPane();
		ea_trusted_user_table_panel.setPreferredSize(new Dimension(330, 200));
		ea_trusted_user_table_panel.setMaximumSize(new Dimension(330, 200));
		ea_trusted_user_table_panel.setAlignmentX(0.0f);
		ea_trusted_user_table_panel.getViewport().add(ea_trusted_user_table);

		// EA Trusted user management buttons
		ea_trusted_user_add_button.setAlignmentX(0.5f);
		ea_trusted_user_removal_button.setAlignmentX(0.5f);
		ea_trusted_user_removal_button.setEnabled(false);

		JPanel ea_trusted_user_management_buttons_panel = new JPanel();
		ea_trusted_user_management_buttons_panel.setPreferredSize(new Dimension(230, 30));
		ea_trusted_user_management_buttons_panel.setMaximumSize(new Dimension(230, 30));
		ea_trusted_user_management_buttons_panel.setAlignmentX(0.0f);
		ea_trusted_user_management_buttons_panel.add(ea_trusted_user_add_button);
		ea_trusted_user_management_buttons_panel.add(ea_trusted_user_removal_button);

		// EA Trusted user refresh button
		ea_trusted_user_refresh_info_button.setAlignmentX(0.5f);

		JPanel ea_trusted_user_refresh_info_button_panel = new JPanel();
		ea_trusted_user_refresh_info_button_panel.setPreferredSize(new Dimension(230, 30));
		ea_trusted_user_refresh_info_button_panel.setMaximumSize(new Dimension(230, 30));
		ea_trusted_user_refresh_info_button_panel.setAlignmentX(0.0f);
		ea_trusted_user_refresh_info_button_panel.add(ea_trusted_user_refresh_info_button);

		JPanel ea_trusted_user_buttons_outer_panel = new JPanel();
		ea_trusted_user_buttons_outer_panel.setLayout(new BoxLayout(ea_trusted_user_buttons_outer_panel, BoxLayout.Y_AXIS));
		ea_trusted_user_buttons_outer_panel.add(Box.createRigidArea(new Dimension(0, 70)));
		ea_trusted_user_buttons_outer_panel.add(ea_trusted_user_management_buttons_panel);
		ea_trusted_user_buttons_outer_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		ea_trusted_user_buttons_outer_panel.add(ea_trusted_user_refresh_info_button_panel);

		JPanel ea_trusted_user_inner_panel = new JPanel(new SpringLayout());
		ea_trusted_user_inner_panel.add(ea_trusted_user_table_panel);
		ea_trusted_user_inner_panel.add(ea_trusted_user_buttons_outer_panel);

		SpringUtilities.makeCompactGrid(ea_trusted_user_inner_panel, 1, 2, 0, 0, 0, 0);

		// EA Trusted user outer panel
		JPanel ea_trusted_user_outer_panel = new JPanel();
		ea_trusted_user_outer_panel.setLayout(new BoxLayout(ea_trusted_user_outer_panel, BoxLayout.X_AXIS));
		ea_trusted_user_outer_panel.setPreferredSize(new Dimension(555, 200));
		ea_trusted_user_outer_panel.setMaximumSize(new Dimension(555, 200));
		ea_trusted_user_outer_panel.setAlignmentX(0.0f);
		ea_trusted_user_outer_panel.add(ea_trusted_user_inner_panel);

		// ------------------- PHR owners ----------------------
		JLabel ea_phr_owner_label = new JLabel("PHR Owners Who Delegate You As Their Trusted User");

		ea_phr_owner_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1613582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		ea_phr_owner_table_model.setDataVector(null, new Object[] {"Name"});

    		ea_phr_owner_table = new JTable(ea_phr_owner_table_model);
		ea_phr_owner_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane ea_phr_owner_table_panel = new JScrollPane();
		ea_phr_owner_table_panel.setPreferredSize(new Dimension(330, 200));
		ea_phr_owner_table_panel.setMaximumSize(new Dimension(330, 200));
		ea_phr_owner_table_panel.setAlignmentX(0.0f);
		ea_phr_owner_table_panel.getViewport().add(ea_phr_owner_table);

		// EA PHR owner management buttons
		ea_phr_owner_declination_button.setAlignmentX(0.5f);
		ea_phr_owner_refresh_info_button.setAlignmentX(0.5f);
		ea_phr_owner_declination_button.setEnabled(false);

		JPanel ea_phr_owner_declination_button_panel = new JPanel();
		ea_phr_owner_declination_button_panel.setPreferredSize(new Dimension(230, 30));
		ea_phr_owner_declination_button_panel.setMaximumSize(new Dimension(230, 30));
		ea_phr_owner_declination_button_panel.setAlignmentX(0.0f);
		ea_phr_owner_declination_button_panel.add(ea_phr_owner_declination_button);

		JPanel ea_phr_owner_refresh_info_button_panel = new JPanel();
		ea_phr_owner_refresh_info_button_panel.setPreferredSize(new Dimension(230, 30));
		ea_phr_owner_refresh_info_button_panel.setMaximumSize(new Dimension(230, 30));
		ea_phr_owner_refresh_info_button_panel.setAlignmentX(0.0f);
		ea_phr_owner_refresh_info_button_panel.add(ea_phr_owner_refresh_info_button);

		JPanel ea_phr_owner_buttons_outer_panel = new JPanel();
		ea_phr_owner_buttons_outer_panel.setLayout(new BoxLayout(ea_phr_owner_buttons_outer_panel, BoxLayout.Y_AXIS));
		ea_phr_owner_buttons_outer_panel.add(Box.createRigidArea(new Dimension(0, 70)));
		ea_phr_owner_buttons_outer_panel.add(ea_phr_owner_declination_button_panel);
		ea_phr_owner_buttons_outer_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		ea_phr_owner_buttons_outer_panel.add(ea_phr_owner_refresh_info_button_panel);

		JPanel ea_phr_owner_inner_panel = new JPanel(new SpringLayout());
		ea_phr_owner_inner_panel.add(ea_phr_owner_table_panel);
		ea_phr_owner_inner_panel.add(ea_phr_owner_buttons_outer_panel);

		SpringUtilities.makeCompactGrid(ea_phr_owner_inner_panel, 1, 2, 0, 0, 0, 0);

		// EA PHR owner outer panel
		JPanel ea_phr_owner_outer_panel = new JPanel();
		ea_phr_owner_outer_panel.setLayout(new BoxLayout(ea_phr_owner_outer_panel, BoxLayout.X_AXIS));
		ea_phr_owner_outer_panel.setPreferredSize(new Dimension(555, 200));
		ea_phr_owner_outer_panel.setMaximumSize(new Dimension(555, 200));
		ea_phr_owner_outer_panel.setAlignmentX(0.0f);
		ea_phr_owner_outer_panel.add(ea_phr_owner_inner_panel);

		// ------------------- Restricted PHR Access Requests ----------------------
		JLabel ea_restricted_phr_access_request_label = new JLabel("Restricted-Level PHR Access Requests");

		ea_restricted_phr_access_request_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1413582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		ea_restricted_phr_access_request_table_model.setDataVector(null, new Object[] {"Requestor", "PHR owner", 
			"Data description", "Approvals/Threshold value", "Request status", "PHR id"});

    		ea_restricted_phr_access_request_table = new JTable(ea_restricted_phr_access_request_table_model);
		ea_restricted_phr_access_request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		ea_restricted_phr_access_request_table.removeColumn(ea_restricted_phr_access_request_table.getColumnModel().getColumn(5));

		JScrollPane ea_restricted_phr_access_request_table_panel = new JScrollPane();
		ea_restricted_phr_access_request_table_panel.setPreferredSize(new Dimension(555, 200));
		ea_restricted_phr_access_request_table_panel.setMaximumSize(new Dimension(555, 200));
		ea_restricted_phr_access_request_table_panel.setAlignmentX(0.0f);
		ea_restricted_phr_access_request_table_panel.getViewport().add(ea_restricted_phr_access_request_table);

		// EA PHR owner desc buttons
		JLabel ea_phr_owner_desc_buttons_label = new JLabel("PHR owner: ", JLabel.RIGHT);
		ea_phr_owner_request_cancel_button.setAlignmentX(0.0f);
		ea_phr_owner_request_cancel_button.setEnabled(false);

		JPanel ea_phr_owner_buttons_panel = new JPanel();
		ea_phr_owner_buttons_panel.setPreferredSize(new Dimension(225, 30));
		ea_phr_owner_buttons_panel.setMaximumSize(new Dimension(225, 30));
		ea_phr_owner_buttons_panel.setAlignmentX(0.0f);
		ea_phr_owner_buttons_panel.add(ea_phr_owner_request_cancel_button);
		ea_phr_owner_buttons_panel.add(Box.createRigidArea(new Dimension(55, 0)));

		// EA trusted user desc buttons
		JLabel ea_trusted_user_desc_buttons_label = new JLabel("Trusted user: ", JLabel.RIGHT);
		ea_trusted_user_approval_button.setAlignmentX(0.0f);
		ea_trusted_user_no_approval_button.setAlignmentX(0.0f);
		ea_trusted_user_approval_button.setEnabled(false);
		ea_trusted_user_no_approval_button.setEnabled(false);

		JPanel ea_trusted_user_buttons_panel = new JPanel();
		ea_trusted_user_buttons_panel.setPreferredSize(new Dimension(225, 30));
		ea_trusted_user_buttons_panel.setMaximumSize(new Dimension(225, 30));
		ea_trusted_user_buttons_panel.setAlignmentX(0.0f);
		ea_trusted_user_buttons_panel.add(ea_trusted_user_approval_button);
		ea_trusted_user_buttons_panel.add(ea_trusted_user_no_approval_button);

		JPanel ea_restricted_phr_access_buttons_inner_panel = new JPanel(new SpringLayout());
		ea_restricted_phr_access_buttons_inner_panel.add(ea_phr_owner_desc_buttons_label);
		ea_restricted_phr_access_buttons_inner_panel.add(ea_phr_owner_buttons_panel);
		ea_restricted_phr_access_buttons_inner_panel.add(ea_trusted_user_desc_buttons_label);
		ea_restricted_phr_access_buttons_inner_panel.add(ea_trusted_user_buttons_panel);

		SpringUtilities.makeCompactGrid(ea_restricted_phr_access_buttons_inner_panel, 2, 2, 5, 5, 5, 10);

		// EA restricted PHR access buttons panel
		JPanel ea_restricted_phr_access_buttons_outer_panel = new JPanel();
		ea_restricted_phr_access_buttons_outer_panel.setLayout(new BoxLayout(ea_restricted_phr_access_buttons_outer_panel, BoxLayout.X_AXIS));
		ea_restricted_phr_access_buttons_outer_panel.setPreferredSize(new Dimension(350, 80));
		ea_restricted_phr_access_buttons_outer_panel.setMaximumSize(new Dimension(350, 80));
		ea_restricted_phr_access_buttons_outer_panel.setAlignmentX(0.5f);
		ea_restricted_phr_access_buttons_outer_panel.add(ea_restricted_phr_access_buttons_inner_panel);

		JPanel ea_restricted_phr_access_buttons_panel = new JPanel();
		ea_restricted_phr_access_buttons_panel.setPreferredSize(new Dimension(555, 80));
		ea_restricted_phr_access_buttons_panel.setMaximumSize(new Dimension(555, 80));
		ea_restricted_phr_access_buttons_panel.setAlignmentX(0.0f);
		ea_restricted_phr_access_buttons_panel.add(ea_restricted_phr_access_buttons_outer_panel);

		// EA restricted PHR access request refresh button
		ea_restricted_phr_access_request_refresh_info_button.setAlignmentX(0.5f);

		JPanel ea_restricted_phr_access_request_refresh_info_button_panel = new JPanel();
		ea_restricted_phr_access_request_refresh_info_button_panel.setPreferredSize(new Dimension(555, 30));
		ea_restricted_phr_access_request_refresh_info_button_panel.setMaximumSize(new Dimension(555, 30));
		ea_restricted_phr_access_request_refresh_info_button_panel.setAlignmentX(0.0f);
		ea_restricted_phr_access_request_refresh_info_button_panel.add(ea_restricted_phr_access_request_refresh_info_button);

		emergency_access_management_outer_panel.setLayout(new BoxLayout(emergency_access_management_outer_panel, BoxLayout.Y_AXIS));
		emergency_access_management_outer_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		emergency_access_management_outer_panel.add(ea_trusted_user_label);
		emergency_access_management_outer_panel.add(ea_trusted_user_outer_panel);
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_access_management_outer_panel.add(new JSeparator(SwingConstants.HORIZONTAL));
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_access_management_outer_panel.add(ea_phr_owner_label);
		emergency_access_management_outer_panel.add(ea_phr_owner_outer_panel);
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_access_management_outer_panel.add(new JSeparator(SwingConstants.HORIZONTAL));
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_access_management_outer_panel.add(ea_restricted_phr_access_request_label);
		emergency_access_management_outer_panel.add(ea_restricted_phr_access_request_table_panel);
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		emergency_access_management_outer_panel.add(ea_restricted_phr_access_buttons_panel);
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		emergency_access_management_outer_panel.add(ea_restricted_phr_access_request_refresh_info_button_panel);
		emergency_access_management_outer_panel.add(Box.createRigidArea(new Dimension(0, 30)));
	}

	private final void create_transaction_auditing_page()
	{
		// Transaction log type
        	transaction_log_type_radio_buttons[0] = new JRadioButton(transaction_login_log_type);
        	transaction_log_type_radio_buttons[0].setActionCommand(transaction_login_log_type);
		transaction_log_type_radio_buttons[0].setSelected(false);

		transaction_log_type_radio_buttons[1] = new JRadioButton(transaction_event_log_type);
        	transaction_log_type_radio_buttons[1].setActionCommand(transaction_event_log_type);
		transaction_log_type_radio_buttons[1].setSelected(false);

		transaction_log_type_group = new ButtonGroup();
            	transaction_log_type_group.add(transaction_log_type_radio_buttons[0]);
		transaction_log_type_group.add(transaction_log_type_radio_buttons[1]);

		// Transaction log type panel
		JPanel transaction_log_type_inner_panel = new JPanel();
		transaction_log_type_inner_panel.setLayout(new BoxLayout(transaction_log_type_inner_panel, BoxLayout.Y_AXIS));
		transaction_log_type_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		transaction_log_type_inner_panel.setPreferredSize(new Dimension(230, 75));
		transaction_log_type_inner_panel.setMaximumSize(new Dimension(230, 75));
		transaction_log_type_inner_panel.setAlignmentX(0.0f);
		transaction_log_type_inner_panel.add(transaction_log_type_radio_buttons[0]);
		transaction_log_type_inner_panel.add(transaction_log_type_radio_buttons[1]);

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
						NewPasswordChanging new_passwd_changing_dialog = new NewPasswordChanging(main_panel, false, passwd);
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
						EmailAddressChanging email_address_changing_dialog = new EmailAddressChanging(main_panel, false, email_address, passwd);
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

		// Access permission table
		access_permission_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							access_permission_editing_button.setEnabled(true);
							access_permission_removal_button.setEnabled(true);
						}
					});
				}
			}
		});

		// Access permission assignment button
		access_permission_assignment_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						access_permission_assignment_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							access_permission_assignment_button.setEnabled(true);
							return;
						}

						// Call access permission management object
						AccessPermissionManagement access_permission_assignment_dialog;
						access_permission_assignment_dialog = new AccessPermissionManagement(
							main_panel, authority_name, username, authority_name_list);

						access_permission_assignment_dialog.setVisible(true);

						// If the permissions are registered then update the access permission list
						if(access_permission_assignment_dialog.get_result())
						{
							// Call to C function
							update_assigned_access_permission_list_main();
						}

						working_lock.unlock();
						access_permission_assignment_button.setEnabled(true);
					}
				});
            		}
        	});
	
		// Access permission editing button
		access_permission_editing_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						access_permission_editing_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							access_permission_editing_button.setEnabled(true);
							return;
						}

						int row = access_permission_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							access_permission_editing_button.setEnabled(false);
							access_permission_removal_button.setEnabled(false);
							return;
						}

						String  full_username            = access_permission_table.getModel().getValueAt(row, 0).toString();
						boolean upload_permission_flag   = access_permission_table.getModel().getValueAt(row, 1).toString().equals("true");
						boolean download_permission_flag = access_permission_table.getModel().getValueAt(row, 2).toString().equals("true");
						boolean delete_permission_flag   = access_permission_table.getModel().getValueAt(row, 3).toString().equals("true");

						String  authority_name           = full_username.substring(0, full_username.indexOf("."));
						String  username                 = full_username.substring(full_username.indexOf(".") + 1);

						// Call access permission management object
						AccessPermissionManagement access_permission_editing_dialog;
						access_permission_editing_dialog = new AccessPermissionManagement(main_panel, authority_name, username, 
							upload_permission_flag, download_permission_flag, delete_permission_flag);

						access_permission_editing_dialog.setVisible(true);

						// If the permissions are edited then update the access permission list
						if(access_permission_editing_dialog.get_result())
						{
							// Call to C function
							update_assigned_access_permission_list_main();

							working_lock.unlock();
							access_permission_editing_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							access_permission_editing_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// Access permission removal button
		access_permission_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						access_permission_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							access_permission_removal_button.setEnabled(true);
							return;
						}

						int row = access_permission_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							access_permission_editing_button.setEnabled(false);
							access_permission_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to remove this access permission set?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							access_permission_removal_button.setEnabled(true);
							return;
						}

						String full_username  = access_permission_table.getModel().getValueAt(row, 0).toString();
						String authority_name = full_username.substring(0, full_username.indexOf("."));
						String username       = full_username.substring(full_username.indexOf(".") + 1);

						// Call to C functions
						if(remove_access_permission_main(authority_name, username))
						{
							// If the permission is successfully moved then update the access permission list
							update_assigned_access_permission_list_main();

							working_lock.unlock();
							access_permission_removal_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							access_permission_removal_button.setEnabled(true);
						}
					}
				});
            	}
        	});

		// Access permission page refresh info button
		access_permission_page_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						access_permission_page_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							access_permission_page_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C functions
						update_authority_list_main();
						reinit_phr_owner_authority_name_combobox();
						update_assigned_access_permission_list_main();

						working_lock.unlock();
						access_permission_page_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// Search PHR owner button
		search_phr_owner_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						search_phr_owner_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							search_phr_owner_button.setEnabled(true);
							return;
						}

						if(validate_phr_owner_search_input(phr_owner_authority_name_combobox.getSelectedIndex(), username)) 
						{
							int    index                    = phr_owner_authority_name_combobox.getSelectedIndex();
							String phr_owner_authority_name = authority_name;
							String phr_owner_name           = username;
							String transaction_type         = transaction_type_group.getSelection().getActionCommand();

							// Call to C function
							if(transaction_type.equals(phr_uploading_type) && verify_upload_permission_main(
								phr_owner_name, phr_owner_authority_name))
							{
								is_phr_uploaded_by_its_owner = (phr_owner_name.equals(username) 
									&& phr_owner_authority_name.equals(authority_name));

								init_ui_for_phr_uploading_mode();
								setup_actions_for_phr_uploading_mode();
							}
							else if(transaction_type.equals(phr_downloading_type) && verify_download_permission_main(
								phr_owner_name, phr_owner_authority_name))
							{
								init_ui_for_phr_downloading_mode();
								setup_actions_for_phr_downloading_mode();
		
								// Call to C function
								load_downloading_authorized_phr_list_main(phr_owner_name, phr_owner_authority_name);
							}
							else if(transaction_type.equals(phr_deletion_type) && verify_delete_permission_main(
								phr_owner_name, phr_owner_authority_name))
							{
								init_ui_for_phr_deletion_mode();
								setup_actions_for_phr_deletion_mode();

								// Call to C function
								load_deletion_authorized_phr_list_main(phr_owner_name, phr_owner_authority_name);
							}
							else
							{
								working_lock.unlock();
							}
						}
						else
						{
							working_lock.unlock();
						}

						search_phr_owner_button.setEnabled(true);
		    		}
				});
			}
		});

		// ea_trusted_user_table

		// EA trusted user add button
		ea_trusted_user_add_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						ea_trusted_user_add_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							ea_trusted_user_add_button.setEnabled(true);
							return;
						}

						// Call emergency trusted user adding object
						EmergencyTrustedUserAdding emergency_trusted_user_adding_dialog;
						emergency_trusted_user_adding_dialog = new EmergencyTrustedUserAdding(
							main_panel, authority_name, username, authority_name_list);

						emergency_trusted_user_adding_dialog.setVisible(true);

						// If the emergency trusted user is added then update the emergency trusted user list
						if(emergency_trusted_user_adding_dialog.get_result())
						{
							// Call to C function
							update_emergency_trusted_user_list_main();
						}

						working_lock.unlock();
						ea_trusted_user_add_button.setEnabled(true);
					}
				});
            		}
        	});

		// ea_trusted_user_removal_button

		// EA trusted user refresh info button
		ea_trusted_user_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						ea_trusted_user_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							ea_trusted_user_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C function
						update_emergency_trusted_user_list_main();

						working_lock.unlock();
						ea_trusted_user_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// ea_phr_owner_table
		// ea_phr_owner_declination_button (must update 2 tables: update_emergency_phr_owner_list_main() and update_restricted_phr_access_request_list_main())

		// EA PHR owner refresh info button
		ea_phr_owner_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						ea_phr_owner_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							ea_phr_owner_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C functions
						update_emergency_phr_owner_list_main();
						update_restricted_phr_access_request_list_main();

						working_lock.unlock();
						ea_phr_owner_refresh_info_button.setEnabled(true);
					}
				});
            		}
        	});

		// EA restricted PHR access request table
		ea_restricted_phr_access_request_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							int    row                = ea_restricted_phr_access_request_table.getSelectedRow();
							String full_phr_ownername = ea_restricted_phr_access_request_table.getModel().getValueAt(row, 1).toString();

							if(full_phr_ownername.equals(authority_name + "." + username))  // PHR owner
							{
								ea_phr_owner_request_cancel_button.setEnabled(true);
								ea_trusted_user_approval_button.setEnabled(false);
								ea_trusted_user_no_approval_button.setEnabled(false);
							}
							else  // Trusted user
							{
								ea_phr_owner_request_cancel_button.setEnabled(false);
								ea_trusted_user_approval_button.setEnabled(true);
								ea_trusted_user_no_approval_button.setEnabled(true);
							}
						}
					});
				}
			}
		});

		// EA trusted user approval button
		ea_trusted_user_approval_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						ea_trusted_user_approval_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							ea_trusted_user_approval_button.setEnabled(true);
							return;
						}

						int row = ea_restricted_phr_access_request_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							ea_phr_owner_request_cancel_button.setEnabled(false);
							ea_trusted_user_approval_button.setEnabled(false);
							ea_trusted_user_no_approval_button.setEnabled(false);
							return;
						}

						String full_emergency_staff_name = ea_restricted_phr_access_request_table.getModel().getValueAt(row, 0).toString();
						String full_phr_ownername        = ea_restricted_phr_access_request_table.getModel().getValueAt(row, 1).toString();
						String phr_description           = ea_restricted_phr_access_request_table.getModel().getValueAt(row, 2).toString();
						int    phr_id = Integer.parseInt(ea_restricted_phr_access_request_table.getModel().getValueAt(row, 5).toString());

						String emergency_unit_name       = full_emergency_staff_name.substring(0, full_emergency_staff_name.indexOf("."));
						String emergency_staff_name      = full_emergency_staff_name.substring(full_emergency_staff_name.indexOf(".") + 1);

						String phr_owner_authority_name  = full_phr_ownername.substring(0, full_phr_ownername.indexOf("."));
						String phr_ownername             = full_phr_ownername.substring(full_phr_ownername.indexOf(".") + 1);

						// If the approval succeeded then update the restricted PHR access request list
						if(approve_restricted_phr_access_request_main(phr_ownername, phr_owner_authority_name, 
							phr_id, phr_description, emergency_staff_name, emergency_unit_name))
						{
							// Call to C function
							update_restricted_phr_access_request_list_main();

							working_lock.unlock();
							ea_trusted_user_approval_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							ea_trusted_user_approval_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// ea_trusted_user_no_approval_button

		// EA restricted PHR access request refresh info button
		ea_restricted_phr_access_request_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						ea_restricted_phr_access_request_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							ea_restricted_phr_access_request_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C function
						update_restricted_phr_access_request_list_main();

						working_lock.unlock();
						ea_restricted_phr_access_request_refresh_info_button.setEnabled(true);
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
							audit_all_transaction_logs((transaction_log_type.equals(
								transaction_login_log_type)) ? TransactionLogType.USER_LOGIN_LOG : TransactionLogType.USER_EVENT_LOG);
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
							audit_some_period_time_transaction_logs((transaction_log_type.equals(transaction_login_log_type)) ? 
								TransactionLogType.USER_LOGIN_LOG : TransactionLogType.USER_EVENT_LOG, start_year_index, start_month_index, 
								start_day_index, start_hour_index, start_minute_index, end_year_index, end_month_index, end_day_index, 
								end_hour_index, end_minute_index);
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

				// Invisible UserMain frame and destroy it
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

	private void reinit_phr_owner_authority_name_combobox()
	{
		phr_owner_authority_name_combobox.removeAllItems();	
		init_phr_owner_authority_name_combobox();
	}

	private void init_phr_owner_authority_name_combobox()
	{
		int list_size = authority_name_list.size();
		for(int i=0; i < list_size; i++)
			phr_owner_authority_name_combobox.addItem(authority_name_list.get(i));

		phr_owner_authority_name_combobox.setSelectedIndex(-1);
	}

	private boolean validate_phr_owner_search_input(int index, String phr_owner_name)
	{
		Pattern p;
		Matcher m;
		// int     index;

		// Validate PHR owner authority name
		// index = phr_owner_authority_name_combobox.getSelectedIndex();
		if(index == -1)
		{
			JOptionPane.showMessageDialog(this, "Please select the authority name");
			return false;
		}

		// Validate PHR owner name
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(phr_owner_name);
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the PHR ownername");
			return false;
		}
 
		// Validate transaction type
		for(Enumeration<AbstractButton> buttons = transaction_type_group.getElements(); buttons.hasMoreElements();)
		{
			AbstractButton button = buttons.nextElement();
			if(button.isSelected())
				return true;
		}

		JOptionPane.showMessageDialog(this, "Please select your desired transaction");
		return false;
	}

	private boolean validate_user_adding_input()
	{
		Pattern p;
		Matcher m;
		int     index;

		// Validate authority name
		index = user_authority_name_combobox.getSelectedIndex();
		if(index == -1)
		{
			JOptionPane.showMessageDialog(this, "Please select the authority name");
			return false;
		}

		// Validate username
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(username_for_access_policy_textfield.getText());
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the username");
			return false;
		}

		return true;
	}

	private final void init_ui_for_phr_uploading_mode()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setMaximumSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		// PHR upload from path
		JLabel phr_upload_from_path_label = new JLabel("Upload from: ", JLabel.RIGHT);
		phr_upload_from_path_textfield    = new JTextField(TEXTFIELD_LENGTH);
		browse_phr_upload_from_path_button.setPreferredSize(new Dimension(90, 20));
		browse_phr_upload_from_path_button.setMaximumSize(new Dimension(90, 20));

		// Data description
		JLabel data_description_label = new JLabel("Data description: ", JLabel.RIGHT);

		data_description_textarea   = new JTextArea();
		data_description_scrollpane = new JScrollPane(data_description_textarea);
		data_description_scrollpane.setPreferredSize(new Dimension(350, 70));
		data_description_scrollpane.setMaximumSize(new Dimension(350, 70));

		data_description_textarea.setLineWrap(true);
		data_description_textarea.setWrapStyleWord(true);
		data_description_textarea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.setPreferredSize(new Dimension(500, 200));
		upper_inner_panel.setMaximumSize(new Dimension(500, 200));

		upper_inner_panel.add(phr_owner_authority_name_label);
		upper_inner_panel.add(phr_owner_authority_name_combobox);
		upper_inner_panel.add(new JLabel(""));

		upper_inner_panel.add(phr_owner_name_label);
		upper_inner_panel.add(phr_owner_name_textfield);
		upper_inner_panel.add(new JLabel(""));

		upper_inner_panel.add(phr_upload_from_path_label);
		upper_inner_panel.add(phr_upload_from_path_textfield);
		upper_inner_panel.add(browse_phr_upload_from_path_button);

		upper_inner_panel.add(data_description_label);
		upper_inner_panel.add(data_description_scrollpane);
		upper_inner_panel.add(new JLabel(""));

		SpringUtilities.makeCompactGrid(upper_inner_panel, 4, 3, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(555, 200));
		upper_outer_panel.setMaximumSize(new Dimension(555, 200));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		JPanel confidentiality_level_top_panel = new JPanel();
		if(is_phr_uploaded_by_its_owner)
		{
			// Confidentiality level
			confidentiality_level_radio_buttons[0] = new JRadioButton(phr_exclusive_level);
			confidentiality_level_radio_buttons[0].setActionCommand(phr_exclusive_level);
			confidentiality_level_radio_buttons[0].setSelected(true);

			confidentiality_level_radio_buttons[1] = new JRadioButton(phr_restricted_level);
			confidentiality_level_radio_buttons[1].setActionCommand(phr_restricted_level);
			confidentiality_level_radio_buttons[1].setSelected(false);

			// Disable the restricted level button if the number of trusted users less than or equal to 0
			if(ea_trusted_user_table.getRowCount() > 0) confidentiality_level_radio_buttons[1].setEnabled(true);
			else confidentiality_level_radio_buttons[1].setEnabled(false);

			confidentiality_level_radio_buttons[2] = new JRadioButton(phr_secure_level);
			confidentiality_level_radio_buttons[2].setActionCommand(phr_secure_level);
			confidentiality_level_radio_buttons[2].setSelected(false);

			confidentiality_level_group = new ButtonGroup();
		    	confidentiality_level_group.add(confidentiality_level_radio_buttons[0]);
			confidentiality_level_group.add(confidentiality_level_radio_buttons[1]);
			confidentiality_level_group.add(confidentiality_level_radio_buttons[2]);

			// Threshold value
			JLabel threshold_value_label = new JLabel("Threshold value: ", JLabel.RIGHT);
			threshold_value_textfield    = new JTextField(TEXTFIELD_LENGTH);
			threshold_value_textfield.setEnabled(false);

			// No. of trusted users
			JLabel no_trusted_users_label = new JLabel("No. of trusted users: ", JLabel.RIGHT);
			no_trusted_users_textfield    = new JTextField(TEXTFIELD_LENGTH);
			no_trusted_users_textfield.setEnabled(false);
			no_trusted_users_textfield.setText(Integer.toString(ea_trusted_user_table.getRowCount()));

			JPanel restricted_level_params_inner_panel = new JPanel(new SpringLayout());
			restricted_level_params_inner_panel.setPreferredSize(new Dimension(320, 68));
			restricted_level_params_inner_panel.setMaximumSize(new Dimension(320, 68));

			restricted_level_params_inner_panel.add(new JLabel("  "));
			restricted_level_params_inner_panel.add(threshold_value_label);
			restricted_level_params_inner_panel.add(threshold_value_textfield);

			restricted_level_params_inner_panel.add(new JLabel("  "));
			restricted_level_params_inner_panel.add(no_trusted_users_label);
			restricted_level_params_inner_panel.add(no_trusted_users_textfield);

			SpringUtilities.makeCompactGrid(restricted_level_params_inner_panel, 2, 3, 5, 5, 10, 5);

			JPanel restricted_level_params_outer_panel = new JPanel();
			restricted_level_params_outer_panel.setLayout(new BoxLayout(restricted_level_params_outer_panel, BoxLayout.X_AXIS));
			restricted_level_params_outer_panel.setPreferredSize(new Dimension(350, 78));
			restricted_level_params_outer_panel.setMaximumSize(new Dimension(350, 78));
			restricted_level_params_outer_panel.setAlignmentX(0.0f);
			restricted_level_params_outer_panel.add(restricted_level_params_inner_panel);

			// Confidentiality level panel
			JPanel confidentiality_level_inner_panel = new JPanel();
			confidentiality_level_inner_panel.setLayout(new BoxLayout(confidentiality_level_inner_panel, BoxLayout.Y_AXIS));
			confidentiality_level_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
			confidentiality_level_inner_panel.setPreferredSize(new Dimension(380, 175));
			confidentiality_level_inner_panel.setMaximumSize(new Dimension(380, 175));
			confidentiality_level_inner_panel.setAlignmentX(0.0f);
			confidentiality_level_inner_panel.add(confidentiality_level_radio_buttons[0]);
			confidentiality_level_inner_panel.add(confidentiality_level_radio_buttons[1]);
			confidentiality_level_inner_panel.add(restricted_level_params_outer_panel);
			confidentiality_level_inner_panel.add(confidentiality_level_radio_buttons[2]);

			JPanel confidentiality_level_outer_panel = new JPanel(new GridLayout(0, 1));
			confidentiality_level_outer_panel.setLayout(new BoxLayout(confidentiality_level_outer_panel, BoxLayout.Y_AXIS));
	    		confidentiality_level_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR confidentiality level"));
			confidentiality_level_outer_panel.setAlignmentX(0.0f);
			confidentiality_level_outer_panel.add(confidentiality_level_inner_panel);

			confidentiality_level_top_panel = new JPanel();
			confidentiality_level_top_panel.setLayout(new BoxLayout(confidentiality_level_top_panel, BoxLayout.Y_AXIS));
			confidentiality_level_top_panel.setPreferredSize(new Dimension(545, phr_uploading_confidentiality_interface_preferred_size));
			confidentiality_level_top_panel.setMaximumSize(new Dimension(545, phr_uploading_confidentiality_interface_preferred_size));
			confidentiality_level_top_panel.setAlignmentX(0.0f);
			confidentiality_level_top_panel.add(confidentiality_level_outer_panel);
			confidentiality_level_top_panel.add(Box.createRigidArea(new Dimension(0, 5)));
		}

		// Access policy
		JLabel access_policy_label = new JLabel("Access Policy");
		access_policy_label.setPreferredSize(new Dimension(535, 15));
		access_policy_label.setMaximumSize(new Dimension(535, 15));
		access_policy_label.setAlignmentX(0.0f);

		access_policy_tree = new AccessPolicyTree();
		access_policy_tree.setPreferredSize(new Dimension(535, 180));
		access_policy_tree.setMaximumSize(new Dimension(535, 180));
		access_policy_tree.setAlignmentX(0.0f);

		// Edit/delete attribute buttons
		edit_attribute_button.setAlignmentX(0.5f);
		edit_attribute_button.setEnabled(false);
		delete_attribute_button.setAlignmentX(0.5f);
		delete_attribute_button.setEnabled(false);

		JPanel edit_delete_access_policy_buttons_panel = new JPanel();
		edit_delete_access_policy_buttons_panel.setPreferredSize(new Dimension(535, 30));
		edit_delete_access_policy_buttons_panel.setMaximumSize(new Dimension(535, 30));
		edit_delete_access_policy_buttons_panel.setAlignmentX(0.0f);
		edit_delete_access_policy_buttons_panel.add(edit_attribute_button);
		edit_delete_access_policy_buttons_panel.add(delete_attribute_button);

		JPanel access_policy_panel = new JPanel();
		access_policy_panel.setPreferredSize(new Dimension(535, 250));
		access_policy_panel.setMaximumSize(new Dimension(535, 250));
		access_policy_panel.setAlignmentX(0.0f);
		access_policy_panel.add(access_policy_label);
		access_policy_panel.add(access_policy_tree);
		access_policy_panel.add(edit_delete_access_policy_buttons_panel);

		// Attribute's authority name
		JLabel attribute_authority_name_label = new JLabel("Authority name: ");
	
		attribute_authority_name_combobox = new JComboBox();
		attribute_authority_name_combobox.setPreferredSize(new Dimension(252, 25));
		attribute_authority_name_combobox.setMaximumSize(new Dimension(252, 25));
		attribute_authority_name_combobox.setAlignmentX(0.5f);

		init_attribute_authority_name_combobox();

		JPanel attribute_authority_name_panel = new JPanel();
		attribute_authority_name_panel.setPreferredSize(new Dimension(380, 30));
		attribute_authority_name_panel.setMaximumSize(new Dimension(380, 30));
		attribute_authority_name_panel.setAlignmentX(0.0f);
		attribute_authority_name_panel.add(attribute_authority_name_label);
		attribute_authority_name_panel.add(attribute_authority_name_combobox);

		// Attributes
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
		attribute_table_panel.setPreferredSize(new Dimension(525, 180));
		attribute_table_panel.setMaximumSize(new Dimension(525, 180));
		attribute_table_panel.setAlignmentX(0.0f);
		attribute_table_panel.getViewport().add(attribute_table);

		// Add attribute button
		add_attribute_button.setAlignmentX(0.5f);
		add_attribute_button.setEnabled(false);	

		JPanel add_access_policy_button_panel = new JPanel();
		add_access_policy_button_panel.setPreferredSize(new Dimension(525, 30));
		add_access_policy_button_panel.setMaximumSize(new Dimension(525, 30));
		add_access_policy_button_panel.setAlignmentX(0.0f);
		add_access_policy_button_panel.add(add_attribute_button);

		// Attributes panel
		JPanel attributes_inner_panel = new JPanel();
		attributes_inner_panel.setLayout(new BoxLayout(attributes_inner_panel, BoxLayout.Y_AXIS));
		attributes_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		attributes_inner_panel.setPreferredSize(new Dimension(525, 255));
		attributes_inner_panel.setMaximumSize(new Dimension(525, 255));
		attributes_inner_panel.setAlignmentX(0.0f);
		attributes_inner_panel.add(attribute_authority_name_panel);
		attributes_inner_panel.add(Box.createRigidArea(new Dimension(0, 15)));
		attributes_inner_panel.add(attribute_table_panel);
		attributes_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		attributes_inner_panel.add(add_access_policy_button_panel);

		JPanel attributes_outer_panel = new JPanel(new GridLayout(0, 1));
		attributes_outer_panel.setLayout(new BoxLayout(attributes_outer_panel, BoxLayout.Y_AXIS));
    		attributes_outer_panel.setBorder(BorderFactory.createTitledBorder("Attributes"));
		attributes_outer_panel.setAlignmentX(0.5f);
		attributes_outer_panel.add(attributes_inner_panel);

		JPanel attributes_panel = new JPanel();
		attributes_panel.setPreferredSize(new Dimension(545, 285));
		attributes_panel.setMaximumSize(new Dimension(545, 285));
		attributes_panel.setAlignmentX(0.0f);
		attributes_panel.add(attributes_outer_panel);

		// User's authority name
		JLabel user_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
	
		user_authority_name_combobox = new JComboBox();
		user_authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		user_authority_name_combobox.setMaximumSize(new Dimension(60, 25));
		init_user_authority_name_combobox();

		// Username
		JLabel username_for_access_policy_label = new JLabel("Username: ", JLabel.RIGHT);
		username_for_access_policy_textfield = new JTextField(TEXTFIELD_LENGTH);

		JPanel username_for_access_policy_inner_panel = new JPanel(new SpringLayout());
		username_for_access_policy_inner_panel.add(user_authority_name_label);
		username_for_access_policy_inner_panel.add(user_authority_name_combobox);
		username_for_access_policy_inner_panel.add(username_for_access_policy_label);
		username_for_access_policy_inner_panel.add(username_for_access_policy_textfield);

		SpringUtilities.makeCompactGrid(username_for_access_policy_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel username_for_access_policy_outer_panel = new JPanel();
		username_for_access_policy_outer_panel.setLayout(new BoxLayout(username_for_access_policy_outer_panel, BoxLayout.X_AXIS));
		username_for_access_policy_outer_panel.setPreferredSize(new Dimension(400, 83));
		username_for_access_policy_outer_panel.setMaximumSize(new Dimension(400, 83));
		username_for_access_policy_outer_panel.setAlignmentX(0.0f);
		username_for_access_policy_outer_panel.add(username_for_access_policy_inner_panel);

		// Add user button
		add_user_button.setAlignmentX(0.5f);	

		JPanel add_user_button_panel = new JPanel();
		add_user_button_panel.setPreferredSize(new Dimension(525, 30));
		add_user_button_panel.setMaximumSize(new Dimension(525, 30));
		add_user_button_panel.setAlignmentX(0.0f);
		add_user_button_panel.add(add_user_button);

		// Users panel
		JPanel users_inner_panel = new JPanel();
		users_inner_panel.setLayout(new BoxLayout(users_inner_panel, BoxLayout.Y_AXIS));
		users_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		users_inner_panel.setPreferredSize(new Dimension(525, 140));
		users_inner_panel.setMaximumSize(new Dimension(525, 140));
		users_inner_panel.setAlignmentX(0.0f);
		users_inner_panel.add(username_for_access_policy_outer_panel);
		users_inner_panel.add(add_user_button_panel);

		JPanel users_outer_panel = new JPanel(new GridLayout(0, 1));
		users_outer_panel.setLayout(new BoxLayout(users_outer_panel, BoxLayout.Y_AXIS));
    		users_outer_panel.setBorder(BorderFactory.createTitledBorder("User"));
		users_outer_panel.setAlignmentX(0.5f);
		users_outer_panel.add(users_inner_panel);

		JPanel users_panel = new JPanel();
		users_panel.setPreferredSize(new Dimension(545, 170));
		users_panel.setMaximumSize(new Dimension(545, 170));
		users_panel.setAlignmentX(0.0f);
		users_panel.add(users_outer_panel);

		// Upload and quit buttons
		upload_phr_button.setAlignmentX(0.5f);	
		quit_phr_uploading_button.setAlignmentX(0.5f);

		JPanel main_buttons_panel = new JPanel();
		main_buttons_panel.setPreferredSize(new Dimension(535, 30));
		main_buttons_panel.setMaximumSize(new Dimension(535, 30));
		main_buttons_panel.setAlignmentX(0.0f);
		main_buttons_panel.add(upload_phr_button);
		main_buttons_panel.add(quit_phr_uploading_button);

		JPanel phr_management_inner_panel = new JPanel();
		
		phr_management_inner_panel.setPreferredSize(new Dimension(555, 1205 - ((is_phr_uploaded_by_its_owner) ? 
			0 : phr_uploading_confidentiality_interface_preferred_size)));

		phr_management_inner_panel.setMaximumSize(new Dimension(555, 1205 - ((is_phr_uploaded_by_its_owner) ? 
			0 : phr_uploading_confidentiality_interface_preferred_size)));

		phr_management_inner_panel.setAlignmentX(0.0f);
		phr_management_inner_panel.add(upper_outer_panel);

		if(is_phr_uploaded_by_its_owner)
		{
			phr_management_inner_panel.add(confidentiality_level_top_panel);
		}

		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_management_inner_panel.add(access_policy_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_management_inner_panel.add(attributes_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_management_inner_panel.add(users_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(555, 10)));
		phr_management_inner_panel.add(main_buttons_panel);

		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.add(phr_management_inner_panel);
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();

		// Set focus
		phr_upload_from_path_textfield.requestFocus(true); 
	}

	private final void uninit_ui_for_phr_uploading_mode()
	{
		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private void init_attribute_authority_name_combobox()
	{
		int list_size = authority_name_list.size();
		for(int i=0; i < list_size; i++)
		{
			attribute_authority_name_combobox.addItem(authority_name_list.get(i));
		}

		attribute_authority_name_combobox.setSelectedIndex(-1);
	}

	private void init_user_authority_name_combobox()
	{
		int list_size = authority_name_list.size();
		for(int i=0; i < list_size; i++)
		{
			user_authority_name_combobox.addItem(authority_name_list.get(i));
		}

		user_authority_name_combobox.setSelectedIndex(-1);
	}

	private void init_actions_for_phr_uploading_mode()
	{
		// Browse PHR upload from path button
		browse_phr_upload_from_path_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						browse_phr_upload_from_path_button.setEnabled(false);

						JFileChooser phr_upload_from_path_filechooser = new JFileChooser();
						phr_upload_from_path_filechooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);

						int ret = phr_upload_from_path_filechooser.showDialog(main_panel, "Choose a PHR");
						if(ret == JFileChooser.APPROVE_OPTION)
						{
							String phr_upload_from_path = phr_upload_from_path_filechooser.getSelectedFile().getAbsolutePath();
							phr_upload_from_path_textfield.setText(phr_upload_from_path);
						}

						browse_phr_upload_from_path_button.setEnabled(true);
		    			}
				});
			}
		};

		// Confidentiality level radio buttons
		confidentiality_level_radio_buttons_actionlistener = new ActionListener()
		{
			public void actionPerformed(final ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						JRadioButton button = (JRadioButton)event.getSource();
						if(button.getText().equals(phr_restricted_level))
						{
							threshold_value_textfield.setEnabled(true);
						}
						else
						{
							threshold_value_textfield.setEnabled(false);
						}
		    			}
				});
			}
		};

		// Access policy tree
		access_policy_tree_mouselistener = new MouseAdapter()
    		{
			public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							if(access_policy_tree.is_selected_node_editable_attribute())
								edit_attribute_button.setEnabled(true);
							else
								edit_attribute_button.setEnabled(false);

							if(access_policy_tree.is_selected_node_removable())
								delete_attribute_button.setEnabled(true);
							else
								delete_attribute_button.setEnabled(false);
						}
					});
				}
			}
    		};

		// Edit attribute button
		edit_attribute_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						edit_attribute_button.setEnabled(false);

						String selected_numberical_attribute = access_policy_tree.get_selected_node_to_string();
						if(selected_numberical_attribute == null)
						{
							edit_attribute_button.setEnabled(true);
							return;
						}

						ComparisonOperation                comparision_operation;
						String                             authority_name;
						String                             attribute_name;
						int                                attribute_value;
						NumericalAttributeInformationEntry editing_dialog;

						if(selected_numberical_attribute.indexOf(" " + ComparisonOperation.MORETHAN.toString() + " ") > 0)
							comparision_operation = ComparisonOperation.MORETHAN;
						else if(selected_numberical_attribute.indexOf(" " + ComparisonOperation.MORETHAN_OR_EQUAL.toString() + " ") > 0)
							comparision_operation = ComparisonOperation.MORETHAN_OR_EQUAL;
						else if(selected_numberical_attribute.indexOf(" " + ComparisonOperation.LESSTHAN.toString() + " ") > 0)
							comparision_operation = ComparisonOperation.LESSTHAN;
						else if(selected_numberical_attribute.indexOf(" " + ComparisonOperation.LESSTHAN_OR_EQUAL.toString() + " ") > 0)
							comparision_operation = ComparisonOperation.LESSTHAN_OR_EQUAL;
						else
							comparision_operation = ComparisonOperation.EQUAL;

						authority_name  = selected_numberical_attribute.substring("Attribute: ".length(), 
							selected_numberical_attribute.indexOf("."));

						attribute_name  = selected_numberical_attribute.substring(selected_numberical_attribute.indexOf(".") 
							+ 1, selected_numberical_attribute.indexOf(" " + comparision_operation.toString() + " "));

						attribute_value = Integer.parseInt(selected_numberical_attribute.substring(
							selected_numberical_attribute.indexOf(" " + comparision_operation.toString() + " ") + 
							(" " + comparision_operation.toString() + " ").length()));

						// Call numerical attribute information entry object
						editing_dialog = new NumericalAttributeInformationEntry(main_panel, 
							authority_name, attribute_name, attribute_value, comparision_operation);

						// Show a dialog
						editing_dialog.setVisible(true);
						if(editing_dialog.get_result())
						{
							access_policy_tree.change_numerical_attribute_information_at_selected_node(authority_name, attribute_name, 
								editing_dialog.get_comparison_operation(), editing_dialog.get_attribute_value());
						}

						edit_attribute_button.setEnabled(true);
		    			}
				});
			}
		};

		// Delete attribute button
		delete_attribute_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						delete_attribute_button.setEnabled(false);
						edit_attribute_button.setEnabled(false);
						access_policy_tree.remove_selected_attribute_and_sub_attributes();
		    			}
				});
			}
		};

		// Attribute authority name combobox
		attribute_authority_name_combobox_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						attribute_authority_name_combobox.setEnabled(false);

						int    index          = attribute_authority_name_combobox.getSelectedIndex();
						String authority_name = authority_name_list.get(index);

						System.out.println("AUTHORITY NAME" + authority_name);

						// Call to C function
						update_attribute_list_main(authority_name);

						attribute_authority_name_combobox.setEnabled(true);
		    			}
				});
			}
		};

		// Attribute table
		attribute_table_mouseadapter = new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							add_attribute_button.setEnabled(true);
						}
					});
				}
			}
		};

		// Add attribute button
		add_attribute_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						add_attribute_button.setEnabled(false);

						int row = attribute_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");
							add_attribute_button.setEnabled(true);
							return;
						}

						String  full_attribute_name    = attribute_table.getModel().getValueAt(row, 0).toString();
						boolean is_numerical_attribute = attribute_table.getModel().getValueAt(row, 1).toString().equals("true");

						String  authority_name         = full_attribute_name.substring(0, full_attribute_name.indexOf("."));
						String  attribute_name         = full_attribute_name.substring(full_attribute_name.indexOf(".") + 1);

						if(is_numerical_attribute)
						{
							NumericalAttributeInformationEntry adding_dialog;

							// Call numerical attribute information entry object
							adding_dialog = new NumericalAttributeInformationEntry(main_panel, authority_name, attribute_name);
							adding_dialog.setVisible(true);
							if(adding_dialog.get_result())
							{
								// Add a numerical attribute to the access policy tree
								access_policy_tree.add_attribute_to_selected_branch(authority_name, attribute_name, 
									adding_dialog.get_comparison_operation(), adding_dialog.get_attribute_value());
							}
						}
						else
						{
							// Add a non-numerical attribute to the access policy tree
							access_policy_tree.add_attribute_to_selected_branch(authority_name, attribute_name);
						}

						add_attribute_button.setEnabled(true);
		    			}
				});
			}
		};

		// Add user button
		add_user_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						add_user_button.setEnabled(false);

						if(validate_user_adding_input())
						{
							int    index          = user_authority_name_combobox.getSelectedIndex();
							String authority_name = authority_name_list.get(index);
							String username       = username_for_access_policy_textfield.getText();

							// Call to C function
							if(check_user_existence_main(authority_name, username))
							{
								// Add a user to the access policy tree
								access_policy_tree.add_user_to_selected_branch(authority_name, username);
							}
						}

						add_user_button.setEnabled(true);
		    			}
				});
			}
		};

		// Upload PHR button
		upload_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						upload_phr_button.setEnabled(false);

						if(validate_phr_uploading_input())
						{
							int    index                    = phr_owner_authority_name_combobox.getSelectedIndex();
							String phr_owner_authority_name = authority_name_list.get(index);
							String phr_owner_name           = phr_owner_name_textfield.getText();
							String phr_upload_from_path     = phr_upload_from_path_textfield.getText();
							String data_description         = data_description_textarea.getText();
							String access_policy            = access_policy_tree.transform_tree_to_access_policy();
							String confidentiality_level    = (is_phr_uploaded_by_its_owner) ? confidentiality_level_group.
								getSelection().getActionCommand() : phr_exclusive_level;

							System.out.println("ACCESS POLICY 1 : " + access_policy);

							// Add the PHR owner's attribute identity into an access policy so that the PHR owner can decrypt the encrypted PHR
							access_policy = add_phr_owner_attribute_to_access_policy(access_policy, phr_owner_name, phr_owner_authority_name);

							System.out.println("ACCESS POLICY 2 : " + access_policy);


							uninit_ui_for_phr_uploading_mode();
							release_actions_for_phr_uploading_mode();
							init_ui_for_phr_uploading_transaction_mode();
							setup_actions_for_phr_uploading_transaction_mode();

							// Run background tasks
							run_phr_uploading_background_task(phr_owner_name, phr_owner_authority_name, 
								phr_upload_from_path, data_description, confidentiality_level, access_policy);
						}

						upload_phr_button.setEnabled(true);
		    			}
				});
			}
		};

		// Quit PHR uploading button
		quit_phr_uploading_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						quit_phr_uploading_button.setEnabled(false);

						uninit_ui_for_phr_uploading_mode();
						release_actions_for_phr_uploading_mode();
						create_phr_management_page();

						working_lock.unlock();

						quit_phr_uploading_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_phr_uploading_mode()
	{
		// Browse PHR upload from path button
		browse_phr_upload_from_path_button.addActionListener(browse_phr_upload_from_path_button_actionlistener);

		if(is_phr_uploaded_by_its_owner)
		{
			// Confidentiality level radio buttons
			confidentiality_level_radio_buttons[0].addActionListener(confidentiality_level_radio_buttons_actionlistener);
			confidentiality_level_radio_buttons[1].addActionListener(confidentiality_level_radio_buttons_actionlistener);
			confidentiality_level_radio_buttons[2].addActionListener(confidentiality_level_radio_buttons_actionlistener);
		}

		// Access policy tree
		access_policy_tree.get_tree().addMouseListener(access_policy_tree_mouselistener);

		// Edit attribute button
		edit_attribute_button.addActionListener(edit_attribute_button_actionlistener);

		// Delete attribute button
		delete_attribute_button.addActionListener(delete_attribute_button_actionlistener);

		// Attribute authority name combobox
		attribute_authority_name_combobox.addActionListener(attribute_authority_name_combobox_actionlistener);

		// Attribute table
		attribute_table.addMouseListener(attribute_table_mouseadapter);

		// Add attribute button
		add_attribute_button.addActionListener(add_attribute_button_actionlistener);

		// Add user button
		add_user_button.addActionListener(add_user_button_actionlistener);

		// Upload PHR button
		upload_phr_button.addActionListener(upload_phr_button_actionlistener);

		// Quit PHR uploading button
		quit_phr_uploading_button.addActionListener(quit_phr_uploading_button_actionlistener);
	}

	private void release_actions_for_phr_uploading_mode()
	{
		// Browse PHR upload from path button
		browse_phr_upload_from_path_button.removeActionListener(browse_phr_upload_from_path_button_actionlistener);

		if(is_phr_uploaded_by_its_owner)
		{
			// Confidentiality level radio buttons
			confidentiality_level_radio_buttons[0].removeActionListener(confidentiality_level_radio_buttons_actionlistener);
			confidentiality_level_radio_buttons[1].removeActionListener(confidentiality_level_radio_buttons_actionlistener);
			confidentiality_level_radio_buttons[2].removeActionListener(confidentiality_level_radio_buttons_actionlistener);
		}

		// Access policy tree
		access_policy_tree.get_tree().removeMouseListener(access_policy_tree_mouselistener);

		// Edit attribute button
		edit_attribute_button.removeActionListener(edit_attribute_button_actionlistener);

		// Delete attribute button
		delete_attribute_button.removeActionListener(delete_attribute_button_actionlistener);

		// Attribute authority name combobox
		attribute_authority_name_combobox.removeActionListener(attribute_authority_name_combobox_actionlistener);

		// Attribute table
		attribute_table.removeMouseListener(attribute_table_mouseadapter);

		// Add attribute button
		add_attribute_button.removeActionListener(add_attribute_button_actionlistener);

		// Add user button
		add_user_button.removeActionListener(add_user_button_actionlistener);

		// Upload PHR button
		upload_phr_button.removeActionListener(upload_phr_button_actionlistener);

		// Quit PHR uploading button
		quit_phr_uploading_button.removeActionListener(quit_phr_uploading_button_actionlistener);		
	}

	private boolean validate_phr_uploading_input()
	{
		String  phr_upload_from_path;
		File    phr_file_object;
		Pattern p;
		Matcher m;

		// Validate a PHR upload from path
		phr_upload_from_path = phr_upload_from_path_textfield.getText();
		if(phr_upload_from_path.equals(""))
		{
			JOptionPane.showMessageDialog(this, "Please specify a PHR file/directory path");
			return false;
		}

		phr_file_object = new File(phr_upload_from_path);
	  	if(!phr_file_object.exists())
		{
			JOptionPane.showMessageDialog(this, "The PHR file/directory does not exist");
			return false;
		}

		// Validate a data description
		p = Pattern.compile("\\S");       // Input at least 1 non-white space

		m = p.matcher(data_description_textarea.getText());
		if(!m.find())
		{
			JOptionPane.showMessageDialog(this, "Please input at least 1 non-white space for the data description");
			return false;
		}

		if(is_phr_uploaded_by_its_owner)
		{
			// Validate confidentiality level
			for(Enumeration<AbstractButton> buttons = confidentiality_level_group.getElements(); buttons.hasMoreElements();)
			{
				AbstractButton button = buttons.nextElement();
				if(button.isSelected())
				{
					if(button.getText().equals(phr_restricted_level))
					{
						// Check for the user input of a threshold value
						String threshold_value  = threshold_value_textfield.getText();
						String no_trusted_users = no_trusted_users_textfield.getText();

						// Validate a threshold value
						p = Pattern.compile("^[0-9]+");
						m = p.matcher(threshold_value);

						if(!m.matches())
						{
							JOptionPane.showMessageDialog(this, "Please input the positive integer for the threshold value");
							return false;
						}

						if(Integer.parseInt(threshold_value) <= 0 || Integer.parseInt(threshold_value) > Integer.parseInt(no_trusted_users))
						{
							JOptionPane.showMessageDialog(this, "The threshold value must be between 1 and " + 
								Integer.parseInt(no_trusted_users) + "(No. of trusted users)");

							return false;
						}
					}

					break;
				}
			}
		}

		// Validate access policy
		if(!access_policy_tree.did_user_specified_access_policy())
		{
			JOptionPane.showMessageDialog(this, "Please specify an access policy");
			return false;
		}

		return true;
	}

	private final void init_ui_for_phr_uploading_transaction_mode()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		// PHR upload from path
		JLabel phr_upload_from_path_label = new JLabel("Upload from: ", JLabel.RIGHT);
		phr_upload_from_path_textfield.setEnabled(false);

		// Data description
		JLabel data_description_label = new JLabel("Data description: ", JLabel.RIGHT);
		data_description_textarea.setEnabled(false);

		// Upper panel
		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.setPreferredSize(new Dimension(400, 200));
		upper_inner_panel.setMaximumSize(new Dimension(400, 200));

		upper_inner_panel.add(phr_owner_authority_name_label);
		upper_inner_panel.add(phr_owner_authority_name_combobox);

		upper_inner_panel.add(phr_owner_name_label);
		upper_inner_panel.add(phr_owner_name_textfield);

		upper_inner_panel.add(phr_upload_from_path_label);
		upper_inner_panel.add(phr_upload_from_path_textfield);

		upper_inner_panel.add(data_description_label);
		upper_inner_panel.add(data_description_scrollpane);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 4, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(535, 200));
		upper_outer_panel.setMaximumSize(new Dimension(535, 200));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		JPanel confidentiality_level_outer_panel = new JPanel();
		if(is_phr_uploaded_by_its_owner)
		{
			// Confidentiality level
			confidentiality_level_radio_buttons[0].setEnabled(false);
			confidentiality_level_radio_buttons[1].setEnabled(false);
			confidentiality_level_radio_buttons[2].setEnabled(false);

			JLabel threshold_value_label = new JLabel("Threshold value: ", JLabel.RIGHT);
			JLabel no_trusted_users_label = new JLabel("No. of trusted users: ", JLabel.RIGHT);

			threshold_value_textfield.setEnabled(false);
			no_trusted_users_textfield.setEnabled(false);

			JPanel restricted_level_params_inner_panel = new JPanel(new SpringLayout());
			restricted_level_params_inner_panel.setPreferredSize(new Dimension(320, 68));
			restricted_level_params_inner_panel.setMaximumSize(new Dimension(320, 68));

			restricted_level_params_inner_panel.add(new JLabel("  "));
			restricted_level_params_inner_panel.add(threshold_value_label);
			restricted_level_params_inner_panel.add(threshold_value_textfield);

			restricted_level_params_inner_panel.add(new JLabel("  "));
			restricted_level_params_inner_panel.add(no_trusted_users_label);
			restricted_level_params_inner_panel.add(no_trusted_users_textfield);

			SpringUtilities.makeCompactGrid(restricted_level_params_inner_panel, 2, 3, 5, 5, 10, 5);

			JPanel restricted_level_params_outer_panel = new JPanel();
			restricted_level_params_outer_panel.setLayout(new BoxLayout(restricted_level_params_outer_panel, BoxLayout.X_AXIS));
			restricted_level_params_outer_panel.setPreferredSize(new Dimension(350, 78));
			restricted_level_params_outer_panel.setMaximumSize(new Dimension(350, 78));
			restricted_level_params_outer_panel.setAlignmentX(0.0f);
			restricted_level_params_outer_panel.add(restricted_level_params_inner_panel);

			// Confidentiality level panel
			JPanel confidentiality_level_inner_panel = new JPanel();
			confidentiality_level_inner_panel.setLayout(new BoxLayout(confidentiality_level_inner_panel, BoxLayout.Y_AXIS));
			confidentiality_level_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
			confidentiality_level_inner_panel.setPreferredSize(new Dimension(380, 175));
			confidentiality_level_inner_panel.setMaximumSize(new Dimension(380, 175));
			confidentiality_level_inner_panel.setAlignmentX(0.0f);
			confidentiality_level_inner_panel.add(confidentiality_level_radio_buttons[0]);
			confidentiality_level_inner_panel.add(confidentiality_level_radio_buttons[1]);
			confidentiality_level_inner_panel.add(restricted_level_params_outer_panel);
			confidentiality_level_inner_panel.add(confidentiality_level_radio_buttons[2]);

			confidentiality_level_outer_panel = new JPanel(new GridLayout(0, 1));
			confidentiality_level_outer_panel.setLayout(new BoxLayout(confidentiality_level_outer_panel, BoxLayout.Y_AXIS));
	    		confidentiality_level_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR confidentiality level"));
			confidentiality_level_outer_panel.setAlignmentX(0.0f);
			confidentiality_level_outer_panel.add(confidentiality_level_inner_panel);
		}

		// Access policy
		JLabel access_policy_label = new JLabel("Access Policy");
		access_policy_label.setPreferredSize(new Dimension(495, 15));
		access_policy_label.setMaximumSize(new Dimension(495, 15));
		access_policy_label.setAlignmentX(0.0f);

		access_policy_tree.setPreferredSize(new Dimension(495, 160));
		access_policy_tree.setMaximumSize(new Dimension(495, 160));
		access_policy_tree.setAlignmentX(0.0f);
		access_policy_tree.setEnabled(false);

		JPanel access_policy_panel = new JPanel();
		access_policy_panel.setPreferredSize(new Dimension(495, 230));
		access_policy_panel.setMaximumSize(new Dimension(495, 230));
		access_policy_panel.setAlignmentX(0.0f);
		access_policy_panel.add(access_policy_label);
		access_policy_panel.add(access_policy_tree);

		// PHR info panel
		JPanel phr_info_inner_panel = new JPanel();
		phr_info_inner_panel.setLayout(new BoxLayout(phr_info_inner_panel, BoxLayout.Y_AXIS));
		phr_info_inner_panel.setBorder(new EmptyBorder(new Insets(10, 20, 10, 20)));
		phr_info_inner_panel.setPreferredSize(new Dimension(535, 625 - ((is_phr_uploaded_by_its_owner) ? 
			0 : phr_uploading_confidentiality_interface_preferred_size)));

		phr_info_inner_panel.setMaximumSize(new Dimension(535, 625 - ((is_phr_uploaded_by_its_owner) ? 
			0 : phr_uploading_confidentiality_interface_preferred_size)));

		phr_info_inner_panel.setAlignmentX(0.0f);
		phr_info_inner_panel.add(upper_outer_panel);
		
		if(is_phr_uploaded_by_its_owner)
		{
			phr_info_inner_panel.add(confidentiality_level_outer_panel);
		}

		phr_info_inner_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_info_inner_panel.add(access_policy_panel);

		JPanel phr_info_outer_panel = new JPanel(new GridLayout(0, 1));
		phr_info_outer_panel.setLayout(new BoxLayout(phr_info_outer_panel, BoxLayout.Y_AXIS));
    		phr_info_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR Info"));
		phr_info_outer_panel.setAlignmentX(0.5f);
		phr_info_outer_panel.add(phr_info_inner_panel);

		// PHR encrypting progressbar
		JLabel phr_encrypting_label = new JLabel("Encrypting the PHR");
		phr_encrypting_label.setPreferredSize(new Dimension(350, 20));
		phr_encrypting_label.setMaximumSize(new Dimension(350, 20));
		phr_encrypting_label.setAlignmentX(0.0f);

		phr_encrypting_progressbar = new JProgressBar(0, 100);
		phr_encrypting_progressbar.setIndeterminate(true);
		phr_encrypting_progressbar.setStringPainted(false);
		phr_encrypting_progressbar.setMaximumSize(new Dimension(350, 25));
		phr_encrypting_progressbar.setMinimumSize(new Dimension(350, 25));
		phr_encrypting_progressbar.setPreferredSize(new Dimension(350, 25));
		phr_encrypting_progressbar.setAlignmentX(0.0f);

		JPanel phr_encrypting_progressbar_panel = new JPanel();
		phr_encrypting_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		phr_encrypting_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		phr_encrypting_progressbar_panel.setAlignmentX(0.0f);
		phr_encrypting_progressbar_panel.add(phr_encrypting_label);
		phr_encrypting_progressbar_panel.add(phr_encrypting_progressbar);

		// PHR uploading progressbar
		JLabel phr_uploading_label = new JLabel("Uploading the encrypted PHR");
		phr_uploading_label.setPreferredSize(new Dimension(350, 20));
		phr_uploading_label.setMaximumSize(new Dimension(350, 20));
		phr_uploading_label.setAlignmentX(0.0f);

		phr_uploading_progressbar = new JProgressBar(0, 100);
		phr_uploading_progressbar.setValue(0);
		phr_uploading_progressbar.setIndeterminate(false);
		phr_uploading_progressbar.setStringPainted(true);
		phr_uploading_progressbar.setMaximumSize(new Dimension(350, 25));
		phr_uploading_progressbar.setMinimumSize(new Dimension(350, 25));
		phr_uploading_progressbar.setPreferredSize(new Dimension(350, 25));
		phr_uploading_progressbar.setAlignmentX(0.0f);

		JPanel phr_uploading_progressbar_panel = new JPanel();
		phr_uploading_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		phr_uploading_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		phr_uploading_progressbar_panel.setAlignmentX(0.0f);
		phr_uploading_progressbar_panel.add(phr_uploading_label);
		phr_uploading_progressbar_panel.add(phr_uploading_progressbar);

		// Cancel PHR uploading transaction button
		cancel_phr_uploading_transaction_button.setAlignmentX(0.5f);	

		JPanel cancel_button_panel = new JPanel();
		cancel_button_panel.setPreferredSize(new Dimension(535, 30));
		cancel_button_panel.setMaximumSize(new Dimension(535, 30));
		cancel_button_panel.setAlignmentX(0.0f);
		cancel_button_panel.add(cancel_phr_uploading_transaction_button);

		JPanel phr_management_inner_panel = new JPanel();
		phr_management_inner_panel.setPreferredSize(new Dimension(555, 850 - ((is_phr_uploaded_by_its_owner) ? 
			0 : phr_uploading_confidentiality_interface_preferred_size)));

		phr_management_inner_panel.setMaximumSize(new Dimension(555, 850 - ((is_phr_uploaded_by_its_owner) ? 
			0 : phr_uploading_confidentiality_interface_preferred_size)));

		phr_management_inner_panel.setAlignmentX(0.5f);
		phr_management_inner_panel.add(phr_info_outer_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		phr_management_inner_panel.add(phr_encrypting_progressbar_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		phr_management_inner_panel.add(phr_uploading_progressbar_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		phr_management_inner_panel.add(cancel_button_panel);

		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.add(phr_management_inner_panel);
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private final void uninit_ui_for_phr_uploading_transaction_mode()
	{
		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private void init_actions_for_phr_uploading_transaction_mode()
	{
		// Cancel PHR uploading transaction button
		cancel_phr_uploading_transaction_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						cancel_phr_uploading_transaction_button.setEnabled(false);  

						set_cancel_phr_uploading(true);
						if(get_phr_encrypting_state())
						{
							// Call to C function
							cancel_phr_encrypting_main();
						}
						else if(get_phr_uploading_state())
						{
							// Call to C function
							cancel_phr_uploading_main();
						}

						cancel_phr_uploading_transaction_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_phr_uploading_transaction_mode()
	{
		// Cancel PHR uploading transaction button
		cancel_phr_uploading_transaction_button.addActionListener(cancel_phr_uploading_transaction_button_actionlistener);	
	}

	private void release_actions_for_phr_uploading_transaction_mode()
	{
		// Cancel PHR uploading transaction button
		cancel_phr_uploading_transaction_button.removeActionListener(cancel_phr_uploading_transaction_button_actionlistener);		
	}

	private String add_phr_owner_attribute_to_access_policy(String access_policy, String phr_owner_name, String phr_owner_authority_name)
	{
		// Add the PHR owner's attribute identity into an access policy so that the PHR owner can decrypt the encrypted PHR
		return access_policy.concat(" or (UsernameNode__SUB__" + phr_owner_authority_name + "__SUB__" + phr_owner_name + ")");
	}

	private void set_phr_encrypting_state(boolean flag)
	{
		phr_encrypting_state_flag = flag;
	}

	private boolean get_phr_encrypting_state()
	{
		return phr_encrypting_state_flag;
	}

	private void set_phr_uploading_state(boolean flag)
	{
		phr_uploading_state_flag = flag;
	}

	private boolean get_phr_uploading_state()
	{
		return phr_uploading_state_flag;
	}

	private void set_cancel_phr_uploading(boolean flag)
	{
		cancel_phr_uploading_flag = flag;
	}

	private boolean get_cancel_phr_uploading()
	{
		return cancel_phr_uploading_flag;
	}

	private void set_phr_encrypting_progressbar_value(final int percent)
	{
		// Set progressbar from indeterminate mode to default mode and set its value to "percent"
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
/*				phr_encrypting_progressbar.setValue(percent);
				phr_encrypting_progressbar.setStringPainted(true);
				phr_encrypting_progressbar.setIndeterminate(false);*/
			}
		});
	}

	private String get_phr_confidentiality_level_flag(final String confidentiality_level)
	{
		if(confidentiality_level.equals(phr_secure_level))
		{
			return PHR_SECURE_LEVEL_FLAG;
		}
		else if(confidentiality_level.equals(phr_restricted_level))
		{
			return PHR_RESTRICTED_LEVEL_FLAG;
		}
		else
		{
			return PHR_EXCLUSIVE_LEVEL_FLAG;
		}
	}

	private String add_ems_key_attribute_to_access_policy(String access_policy)
	{
		// Add the Emergency Server's attribute identity into an access policy so that the Emergency Server can decrypt the secure-level encrypted PHR
		return access_policy.concat(" or (SpecialNode__SUB__" + authority_name + "__SUB__EmS)");
	}

	private String generate_random_unique_emergency_key_attribute(int string_length)
	{
		return RandomStringUtils.random(string_length, "0123456789abcdefghijklmnopqrstuvwxyz");
	}

	private BigInteger generate_random_unique_emergency_key_passwd(int digit_length)
	{
		return new BigInteger(RandomStringUtils.random(digit_length, "0123456789"));
	}

	private String add_unique_emergency_key_attribute_to_access_policy(String access_policy, String unique_emergency_attribute)
	{
		// Add the unique emergency attribute identity into an access policy so that the Emergency Server can decrypt 
		// the restricted-level encrypted PHR if the number of approvals more than or equal to the threshold value
		return access_policy.concat(" or (SpecialNode__SUB__" + authority_name + "__SUB__unique_emergency_key_" + unique_emergency_attribute + ")");
	}

	private void serialize_threshold_secret_key(int i, PaillierPrivateThresholdKey secret_key)
	{
		try{
			FileOutputStream   out = new FileOutputStream(CACHE_DIRECTORY_NAME + "/" + PTHRESHOLD_PREFIX_NAME + i + SERIALIZABLE_OBJ_EXTENSION);
			ObjectOutputStream os  = new ObjectOutputStream(out);

			os.writeObject(secret_key);
			os.flush();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private Paillier generate_threshold_secret_keys(int threshold_value, int no_trusted_users)
	{
		Random                        rnd;
		PaillierPrivateThresholdKey[] secret_keys;

		rnd         = new Random();
		secret_keys = KeyGen.PaillierThresholdKey(128, no_trusted_users, threshold_value, rnd.nextLong());

		for(int i=0; i < no_trusted_users; i++)
		{
			// Serialize each threshold secret key onto the disk
			serialize_threshold_secret_key(i, secret_keys[i]);
		}

		return new Paillier(secret_keys[0].getPublicKey());
	}

	private void encrypt_and_serialize_unique_emergency_key_passwd(BigInteger unique_emergency_key_passwd, Paillier threshold_encryptor)
	{
		// Encrypt the unique emergency key password using the threshold cryptosystem
		BigInteger enc_unique_emergency_key_passwd = threshold_encryptor.encrypt(unique_emergency_key_passwd);

		// Serialize the encrypted unique emergency key password onto the disk
		try{
			FileOutputStream   out = new FileOutputStream(CACHE_DIRECTORY_NAME + "/" + ENC_THRESHOLD_MSG + SERIALIZABLE_OBJ_EXTENSION);
			ObjectOutputStream os  = new ObjectOutputStream(out);

			os.writeObject(enc_unique_emergency_key_passwd);
			os.flush();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private String[] converse_ea_trusted_user_table_to_list()
	{
		int      no_trusted_user      = ea_trusted_user_table_model.getRowCount();
		String[] ea_trusted_user_list = new String[no_trusted_user];

		for(int i=0; i < no_trusted_user; i++)
		{
			ea_trusted_user_list[i] = (String)ea_trusted_user_table_model.getValueAt(i, 0);
		}

		return ea_trusted_user_list;
	}

	// Run background tasks on another thread
	private boolean run_phr_uploading_background_task(final String phr_owner_name, final String phr_owner_authority_name, 
		final String phr_upload_from_path, final String data_description, final String confidentiality_level, final String access_policy)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				perform_phr_uploading_transaction(phr_owner_name, phr_owner_authority_name, 
					phr_upload_from_path, data_description, confidentiality_level, access_policy);

				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						/*uninit_ui_for_phr_uploading_transaction_mode();
						release_actions_for_phr_uploading_transaction_mode();
						create_phr_management_page();*/

					//	working_lock.unlock();
					}
				});
			}
		};

		thread.start();

		try{
			thread.join();
		}catch(InterruptedException e){

		}
		System.out.println("Finsih RUN UPLOAD");

		return true;
	}

	private void perform_phr_uploading_transaction(String phr_owner_name, String phr_owner_authority_name, 
		String phr_upload_from_path, String data_description, String confidentiality_level, String access_policy)
	{
		set_cancel_phr_uploading(false);
		set_phr_encrypting_state(false);
		set_phr_uploading_state(false);

		System.out.println("JAVA phr_owner_name: "+ phr_owner_name);
		System.out.println("JAVA phr_owner_authority_name: "+ phr_owner_authority_name);
		System.out.println("JAVA phr_upload_from_path: "+ phr_upload_from_path);
		System.out.println("JAVA data_description: "+ data_description);
		System.out.println("JAVA confidentiality_level: "+ confidentiality_level);
		System.out.println("JAVA access_policy: "+ access_policy);


		if(confidentiality_level.equals(phr_secure_level))
		{
			// Add the Emergency Server's attribute identity into an access policy so that the Emergency Server can decrypt the secure-level encrypted PHR
			access_policy = add_ems_key_attribute_to_access_policy(access_policy);
		}
		else if(confidentiality_level.equals(phr_restricted_level))
		{
			int        threshold_value;
			int        no_trusted_users;
			String     unique_emergency_key_attribute;
			BigInteger unique_emergency_key_passwd;
			Paillier   threshold_encryptor;
			String[]   ea_trusted_user_list;

			/*threshold_value  = Integer.parseInt(threshold_value_textfield.getText());
			no_trusted_users = Integer.parseInt(no_trusted_users_textfield.getText());*/

			threshold_value  = Integer.parseInt(m_threshold_value);
			no_trusted_users = Integer.parseInt(m_no_trusted_users);

			// Generate the unique emergency attribute identity for the unique emergency key and password for encrypting the unique emergency key
			unique_emergency_key_attribute = generate_random_unique_emergency_key_attribute(8);
			unique_emergency_key_passwd    = generate_random_unique_emergency_key_passwd(16);    // For 3DES

			// Add the unique emergency attribute identity into an access policy so that the Emergency Server can decrypt 
			// the restricted-level encrypted PHR if the number of approvals more than or equal to the threshold value
			access_policy = add_unique_emergency_key_attribute_to_access_policy(access_policy, unique_emergency_key_attribute);

			// Generate the threshold environment and threshold secret keys associated with 
			// the number of 'no_trusted_users' and serialize secret keys onto the disk
			threshold_encryptor = generate_threshold_secret_keys(threshold_value, no_trusted_users);

			// Encrypt the unique emergency key password using the threshold cryptosystem and serialize it onto the disk
			encrypt_and_serialize_unique_emergency_key_passwd(unique_emergency_key_passwd, threshold_encryptor);

			if(get_cancel_phr_uploading())
			{
				set_phr_encrypting_progressbar_value(0);

				// Call to C functions
				remove_all_threshold_parameters_in_cache_main(no_trusted_users);
				record_phr_encrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);

				set_cancel_phr_uploading(false);
				JOptionPane.showMessageDialog(main_panel, "Encrypting the PHR was aborted by a user");
				return;
			}

			// Generate the unique emergency key by invoking the User Authority to do it and encrypt it using 3DES at a client
			// Furthermore, we also generates the recovery emergency key encrypted with the user's SSL public key
			if(!generate_unique_emergency_key_main(unique_emergency_key_attribute, unique_emergency_key_passwd.toString()))  // Call to C function
			{
				set_phr_encrypting_progressbar_value(0);

				// Call to C functions
				remove_all_threshold_parameters_in_cache_main(no_trusted_users);
				record_phr_encrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);

				if(get_cancel_phr_uploading())
				{
					set_cancel_phr_uploading(false);
					//JOptionPane.showMessageDialog(main_panel, "Encrypting the PHR was aborted by a user");
				}

				return;
			}

			ea_trusted_user_list = converse_ea_trusted_user_table_to_list();

			// Encrypt each threshold secret key with the corresponding trusted user's public key
			if(!encrypt_threshold_secret_keys_main(ea_trusted_user_list))  // Call to C function
			{
				set_phr_encrypting_progressbar_value(0);

				// Call to C functions
				remove_all_threshold_parameters_in_cache_main(no_trusted_users);
				record_phr_encrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);

				if(get_cancel_phr_uploading())
				{
					set_cancel_phr_uploading(false);
					//JOptionPane.showMessageDialog(main_panel, "Encrypting the PHR was aborted by a user");
				}

				return;
			}

			if(get_cancel_phr_uploading())
			{
				set_phr_encrypting_progressbar_value(0);

				// Call to C functions
				remove_all_threshold_parameters_in_cache_main(no_trusted_users);
				record_phr_encrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);

				set_cancel_phr_uploading(false);
				//JOptionPane.showMessageDialog(main_panel, "Encrypting the PHR was aborted by a user");
				return;
			}
		}

		set_phr_encrypting_state(true);

		// Call to C function
		if(!encrypt_phr_main(phr_upload_from_path, access_policy))
		{
			set_phr_encrypting_state(false);
			set_phr_encrypting_progressbar_value(0);

			// Call to C functions
			record_phr_encrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			if(confidentiality_level.equals(phr_restricted_level))
			{
				remove_all_threshold_parameters_in_cache_main(Integer.parseInt(no_trusted_users_textfield.getText()));
			}

			if(get_cancel_phr_uploading())
			{
				set_cancel_phr_uploading(false);
				//JOptionPane.showMessageDialog(main_panel, "Encrypting the PHR was aborted by a user");
			}

			return;
		}

		set_phr_encrypting_state(false);
		set_phr_encrypting_progressbar_value(100);

		// Call to C function
		record_phr_encrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, true);

		// Call to C function
		if(!verify_upload_permission_main(phr_owner_name, phr_owner_authority_name))
		{
			// Call to C functions
			record_phr_uploading_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			if(confidentiality_level.equals(phr_restricted_level))
			{
				remove_all_threshold_parameters_in_cache_main(Integer.parseInt(no_trusted_users_textfield.getText()));
			}

			return;
		}

		set_phr_uploading_state(true);

		// Call to C function
		if(!upload_phr_main(phr_owner_name, phr_owner_authority_name, data_description, get_phr_confidentiality_level_flag(confidentiality_level)))
		{
			set_phr_uploading_state(false);

			// Call to C functions
			record_phr_uploading_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			if(confidentiality_level.equals(phr_restricted_level))
			{
				remove_all_threshold_parameters_in_cache_main(Integer.parseInt(no_trusted_users_textfield.getText()));
			}

			if(get_cancel_phr_uploading())
			{
				set_cancel_phr_uploading(false);
				//JOptionPane.showMessageDialog(main_panel, "Uploading the PHR was aborted by a user");
			}

			return;
		}

		set_phr_uploading_state(false);

		// Call to C function
		record_phr_uploading_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, true);

		if(confidentiality_level.equals(phr_restricted_level))
		{
			int      threshold_value      = Integer.parseInt(threshold_value_textfield.getText());
			String[] ea_trusted_user_list = converse_ea_trusted_user_table_to_list();

			// Upload the encrypted unique emergency key and encrypted secret keys to the Emergency Server
			if(!upload_unique_emergency_key_params_main(remote_site_phr_id, threshold_value, ea_trusted_user_list))  // Call to C function
			{
				JOptionPane.showMessageDialog(main_panel, "The restricted-level PHR was uploadded to the PHR server successfully. " + 
					"However, \nwe failed to upload the emergency key parameters to the Emergency server. Therefore, \n" + 
					"we must change the confidentiality level of the PHR from the restricted-level to the exclusive-level.");

				// Call to C function
				remove_all_threshold_parameters_in_cache_main(Integer.parseInt(no_trusted_users_textfield.getText()));

				// Change the confidentiality level of the PHR from the restricted-level to the exclusive-level
				if(!change_restricted_level_phr_to_excusive_level_phr_main(remote_site_phr_id))  // Call to C function
				{
					return;
				}

				// Record a transaction log about the change of PHR confidentiality level
				record_failed_uploading_emergency_key_params_transaction_log_main(phr_owner_name, 
					phr_owner_authority_name, data_description);  // Call to C function

				return;
			}

			// Call to C function
			remove_all_threshold_parameters_in_cache_main(Integer.parseInt(no_trusted_users_textfield.getText()));
		}

		//JOptionPane.showMessageDialog(main_panel, "Uploading the PHR succeeded");

		System.out.println("FROM CLASS UPLOAD SUCCESS");
	}

	private final void init_ui_for_phr_downloading_mode()
	{		
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setMaximumSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.setPreferredSize(new Dimension(400, 80));
		upper_inner_panel.setMaximumSize(new Dimension(400, 80));

		upper_inner_panel.add(phr_owner_authority_name_label);
		upper_inner_panel.add(phr_owner_authority_name_combobox);

		upper_inner_panel.add(phr_owner_name_label);
		upper_inner_panel.add(phr_owner_name_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(570, 80));
		upper_outer_panel.setMaximumSize(new Dimension(570, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// PHR downloading table
		JLabel phr_downloading_label = new JLabel("PHR List");
		phr_downloading_label.setPreferredSize(new Dimension(560, 10));
		phr_downloading_label.setMaximumSize(new Dimension(560, 10));
		phr_downloading_label.setAlignmentX(0.0f);

		phr_downloading_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		phr_downloading_table_model.setDataVector(null, new Object[] {"Data description", "Size", "Confidentiality level", "PHR id"});
    		phr_downloading_table = new JTable(phr_downloading_table_model);
		phr_downloading_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		phr_downloading_table.removeColumn(phr_downloading_table.getColumnModel().getColumn(3));

		JScrollPane phr_downloading_table_inner_panel = new JScrollPane();
		phr_downloading_table_inner_panel.setPreferredSize(new Dimension(560, 180));
		phr_downloading_table_inner_panel.setMaximumSize(new Dimension(560, 180));
		phr_downloading_table_inner_panel.setAlignmentX(0.0f);
		phr_downloading_table_inner_panel.getViewport().add(phr_downloading_table);

		JPanel phr_downloading_table_outer_panel = new JPanel();
		phr_downloading_table_outer_panel.setPreferredSize(new Dimension(570, 210));
		phr_downloading_table_outer_panel.setMaximumSize(new Dimension(570, 210));
		phr_downloading_table_outer_panel.setAlignmentX(0.0f);
		phr_downloading_table_outer_panel.add(phr_downloading_label);
		phr_downloading_table_outer_panel.add(phr_downloading_table_inner_panel);

		// PHR download to path
		JLabel phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		phr_download_to_path_textfield    = new JTextField(TEXTFIELD_LENGTH);
		browse_phr_download_to_path_button.setPreferredSize(new Dimension(90, 20));
		browse_phr_download_to_path_button.setMaximumSize(new Dimension(90, 20));

		JPanel phr_download_to_path_panel = new JPanel(new SpringLayout());
		phr_download_to_path_panel.setPreferredSize(new Dimension(465, 35));
		phr_download_to_path_panel.setMaximumSize(new Dimension(465, 35));

		phr_download_to_path_panel.add(phr_download_to_path_label);
		phr_download_to_path_panel.add(phr_download_to_path_textfield);
		phr_download_to_path_panel.add(browse_phr_download_to_path_button);

		SpringUtilities.makeCompactGrid(phr_download_to_path_panel, 1, 3, 5, 0, 10, 10);

		// Download and quit buttons
		download_phr_button.setAlignmentX(0.5f);	
		quit_phr_downloading_button.setAlignmentX(0.5f);
		download_phr_button.setEnabled(false);

		JPanel main_buttons_panel = new JPanel();
		main_buttons_panel.setPreferredSize(new Dimension(570, 30));
		main_buttons_panel.setMaximumSize(new Dimension(570, 30));
		main_buttons_panel.setAlignmentX(0.0f);
		main_buttons_panel.add(download_phr_button);
		main_buttons_panel.add(quit_phr_downloading_button);

		JPanel phr_management_inner_panel = new JPanel();
		phr_management_inner_panel.setPreferredSize(new Dimension(570, 410));
		phr_management_inner_panel.setMaximumSize(new Dimension(570, 410));
		phr_management_inner_panel.setAlignmentX(0.0f);
		phr_management_inner_panel.add(upper_outer_panel);
		phr_management_inner_panel.add(phr_downloading_table_outer_panel);
		phr_management_inner_panel.add(phr_download_to_path_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 50)));
		phr_management_inner_panel.add(main_buttons_panel);

		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.add(phr_management_inner_panel);
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private final void uninit_ui_for_phr_downloading_mode()
	{
		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}	

	private void init_actions_for_phr_downloading_mode()
	{
		// PHR downloading table
		phr_downloading_table_mouseadapter = new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							download_phr_button.setEnabled(true);
						}
					});
				}
			}
		};

		// Browse PHR download to path button
		browse_phr_download_to_path_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						browse_phr_download_to_path_button.setEnabled(false);

						JFileChooser phr_download_to_path_filechooser = new JFileChooser();
						phr_download_to_path_filechooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

						int ret = phr_download_to_path_filechooser.showDialog(main_panel, "Choose a download path");
						if(ret == JFileChooser.APPROVE_OPTION)
						{
							String phr_download_to_path = phr_download_to_path_filechooser.getSelectedFile().getAbsolutePath();
							phr_download_to_path_textfield.setText(phr_download_to_path);
						}

						browse_phr_download_to_path_button.setEnabled(true);
		    			}
				});
			}
		};

		// Download PHR button
		download_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						download_phr_button.setEnabled(false);

						if(validate_phr_downloading_input())
						{
							int    index                    = phr_owner_authority_name_combobox.getSelectedIndex();
							// String phr_owner_authority_name = authority_name_list.get(index);
							String phr_owner_authority_name = authority_name;
							// String phr_owner_name           = phr_owner_name_textfield.getText();
							String phr_owner_name           = username;

							int    row                      = phr_downloading_table.getSelectedRow();
							String data_description         = phr_downloading_table.getModel().getValueAt(row, 0).toString();
							int    phr_id                   = Integer.parseInt(phr_downloading_table.getModel().getValueAt(row, 3).toString());

							String phr_download_to_path     = phr_download_to_path_textfield.getText();

							uninit_ui_for_phr_downloading_mode();
							release_actions_for_phr_downloading_mode();
							init_ui_for_phr_downloading_transaction_mode();
							setup_actions_for_phr_downloading_transaction_mode();

							// Run background tasks
							run_phr_downloading_background_task(phr_owner_name, phr_owner_authority_name, 
								data_description, phr_id, phr_download_to_path);
						}

						download_phr_button.setEnabled(true);
		    			}
				});
			}
		};

		// Quit PHR downloading button
		quit_phr_downloading_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						quit_phr_downloading_button.setEnabled(false);

						uninit_ui_for_phr_downloading_mode();
						release_actions_for_phr_downloading_mode();
						create_phr_management_page();

						working_lock.unlock();

						quit_phr_downloading_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_phr_downloading_mode()
	{
		// PHR downloading table
		phr_downloading_table.addMouseListener(phr_downloading_table_mouseadapter);

		// Browse PHR download to path button
		browse_phr_download_to_path_button.addActionListener(browse_phr_download_to_path_button_actionlistener);

		// Download PHR button
		download_phr_button.addActionListener(download_phr_button_actionlistener);

		// Quit PHR downloading button
		quit_phr_downloading_button.addActionListener(quit_phr_downloading_button_actionlistener);
	}

	private void release_actions_for_phr_downloading_mode()
	{
		// PHR downloading table
		phr_downloading_table.removeMouseListener(phr_downloading_table_mouseadapter);

		// Browse PHR download to path button
		browse_phr_download_to_path_button.removeActionListener(browse_phr_download_to_path_button_actionlistener);

		// Download PHR button
		download_phr_button.removeActionListener(download_phr_button_actionlistener);

		// Quit PHR downloading button
		quit_phr_downloading_button.removeActionListener(quit_phr_downloading_button_actionlistener);		
	}

	private boolean validate_phr_downloading_input()
	{
		String  phr_download_to_path;
		File    phr_dir_object;

		// Validate the PHR item selection
		if(phr_downloading_table.getSelectedRow() < 0)
		{
			JOptionPane.showMessageDialog(this, "Please select the PHR that you need to download");
			return false;
		}

		// Validate a PHR download to path
		phr_download_to_path = phr_download_to_path_textfield.getText();
		if(phr_download_to_path.equals(""))
		{
			JOptionPane.showMessageDialog(this, "Please specify a PHR download directory path");
			return false;
		}

		phr_dir_object = new File(phr_download_to_path);
	  	if(!phr_dir_object.exists())
		{
			JOptionPane.showMessageDialog(this, "The PHR download directory does not exist");
			return false;
		}

		return true;
	}

	private final void init_ui_for_phr_downloading_transaction_mode()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		// PHR download to path
		JLabel phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		phr_download_to_path_textfield.setEnabled(false);

		// PHR info panel
		JPanel phr_info_inner_panel = new JPanel(new SpringLayout());
		phr_info_inner_panel.setPreferredSize(new Dimension(400, 120));
		phr_info_inner_panel.setMaximumSize(new Dimension(400, 120));

		phr_info_inner_panel.add(phr_owner_authority_name_label);
		phr_info_inner_panel.add(phr_owner_authority_name_combobox);

		phr_info_inner_panel.add(phr_owner_name_label);
		phr_info_inner_panel.add(phr_owner_name_textfield);

		phr_info_inner_panel.add(phr_download_to_path_label);
		phr_info_inner_panel.add(phr_download_to_path_textfield);

		SpringUtilities.makeCompactGrid(phr_info_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel phr_info_outer_panel = new JPanel(new GridLayout(0, 1));
		phr_info_outer_panel.setLayout(new BoxLayout(phr_info_outer_panel, BoxLayout.Y_AXIS));
		phr_info_outer_panel.setPreferredSize(new Dimension(450, 155));
		phr_info_outer_panel.setMaximumSize(new Dimension(450, 155));
    		phr_info_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR Info"));
		phr_info_outer_panel.setAlignmentX(0.5f);
		phr_info_outer_panel.add(phr_info_inner_panel);

		// PHR downloading progressbar
		JLabel phr_downloading_label = new JLabel("Downloading the encrypted PHR");
		phr_downloading_label.setPreferredSize(new Dimension(350, 20));
		phr_downloading_label.setMaximumSize(new Dimension(350, 20));
		phr_downloading_label.setAlignmentX(0.0f);

		phr_downloading_progressbar = new JProgressBar(0, 100);
		phr_downloading_progressbar.setValue(0);
		phr_downloading_progressbar.setIndeterminate(false);
		phr_downloading_progressbar.setStringPainted(true);
		phr_downloading_progressbar.setMaximumSize(new Dimension(350, 25));
		phr_downloading_progressbar.setMinimumSize(new Dimension(350, 25));
		phr_downloading_progressbar.setPreferredSize(new Dimension(350, 25));
		phr_downloading_progressbar.setAlignmentX(0.0f);

		JPanel phr_downloading_progressbar_panel = new JPanel();
		phr_downloading_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		phr_downloading_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		phr_downloading_progressbar_panel.setAlignmentX(0.0f);
		phr_downloading_progressbar_panel.add(phr_downloading_label);
		phr_downloading_progressbar_panel.add(phr_downloading_progressbar);

		// PHR decrypting progressbar
		JLabel phr_decrypting_label = new JLabel("Decrypting the encrypted PHR");
		phr_decrypting_label.setPreferredSize(new Dimension(350, 20));
		phr_decrypting_label.setMaximumSize(new Dimension(350, 20));
		phr_decrypting_label.setAlignmentX(0.0f);

		phr_decrypting_progressbar = new JProgressBar(0, 100);
		phr_decrypting_progressbar.setValue(0);
		phr_decrypting_progressbar.setIndeterminate(false);
		phr_decrypting_progressbar.setStringPainted(true);
		phr_decrypting_progressbar.setMaximumSize(new Dimension(350, 25));
		phr_decrypting_progressbar.setMinimumSize(new Dimension(350, 25));
		phr_decrypting_progressbar.setPreferredSize(new Dimension(350, 25));
		phr_decrypting_progressbar.setAlignmentX(0.0f);

		JPanel phr_decrypting_progressbar_panel = new JPanel();
		phr_decrypting_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		phr_decrypting_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		phr_decrypting_progressbar_panel.setAlignmentX(0.0f);
		phr_decrypting_progressbar_panel.add(phr_decrypting_label);
		phr_decrypting_progressbar_panel.add(phr_decrypting_progressbar);

		// Cancel PHR downloading transaction button
		cancel_phr_downloading_transaction_button.setAlignmentX(0.5f);	

		JPanel cancel_button_panel = new JPanel();
		cancel_button_panel.setPreferredSize(new Dimension(535, 30));
		cancel_button_panel.setMaximumSize(new Dimension(535, 30));
		cancel_button_panel.setAlignmentX(0.0f);
		cancel_button_panel.add(cancel_phr_downloading_transaction_button);

		JPanel phr_management_inner_panel = new JPanel();
		phr_management_inner_panel.setPreferredSize(new Dimension(555, 350));
		phr_management_inner_panel.setMaximumSize(new Dimension(555, 350));
		phr_management_inner_panel.setAlignmentX(0.5f);
		phr_management_inner_panel.add(phr_info_outer_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		phr_management_inner_panel.add(phr_downloading_progressbar_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		phr_management_inner_panel.add(phr_decrypting_progressbar_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		phr_management_inner_panel.add(cancel_button_panel);

		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.add(phr_management_inner_panel);
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private final void uninit_ui_for_phr_downloading_transaction_mode()
	{
		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private void init_actions_for_phr_downloading_transaction_mode()
	{
		// Cancel PHR downloading transaction button
		cancel_phr_downloading_transaction_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						cancel_phr_downloading_transaction_button.setEnabled(false);

						set_cancel_phr_downloading(true);
						if(get_phr_downloading_state())
						{
							// Call to C function
							cancel_phr_downloading_main();
						}
						else if(get_phr_decrypting_state())
						{
							// Call to C function
							cancel_phr_decrypting_main();
						}

						cancel_phr_downloading_transaction_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_phr_downloading_transaction_mode()
	{
		// Cancel PHR downloading transaction button
		cancel_phr_downloading_transaction_button.addActionListener(cancel_phr_downloading_transaction_button_actionlistener);	
	}

	private void release_actions_for_phr_downloading_transaction_mode()
	{
		// Cancel PHR downloading transaction button
		cancel_phr_downloading_transaction_button.removeActionListener(cancel_phr_downloading_transaction_button_actionlistener);		
	}

	private void set_phr_downloading_state(boolean flag)
	{
		phr_downloading_state_flag = flag;
	}

	private boolean get_phr_downloading_state()
	{
		return phr_downloading_state_flag;
	}

	private void set_phr_decrypting_state(boolean flag)
	{
		phr_decrypting_state_flag = flag;
	}

	private boolean get_phr_decrypting_state()
	{
		return phr_decrypting_state_flag;
	}

	private void set_cancel_phr_downloading(boolean flag)
	{
		cancel_phr_downloading_flag = flag;
	}

	private boolean get_cancel_phr_downloading()
	{
		return cancel_phr_downloading_flag;
	}

	private void set_indeterminate_mode_phr_decrypting_progressbar()
	{
		// Set progressbar from default mode to indeterminate mode
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				// phr_decrypting_progressbar.setIndeterminate(true);
				// phr_decrypting_progressbar.setStringPainted(false);
			}
		});
	}

	private void set_phr_decrypting_progressbar_value(final int percent)
	{
		// Set progressbar from indeterminate mode to default mode and set its value to "percent"
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				// phr_decrypting_progressbar.setValue(percent);
				// phr_decrypting_progressbar.setStringPainted(true);
				// phr_decrypting_progressbar.setIndeterminate(false);
			}
		});
	}

	// Run background tasks on another thread
	private boolean run_phr_downloading_background_task(final String phr_owner_name, final String phr_owner_authority_name, 
		final String data_description, final int phr_id, final String phr_download_to_path)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				
				m_result_download = perform_phr_downloading_transaction(phr_owner_name, phr_owner_authority_name, data_description, phr_id, phr_download_to_path);

				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
/*						uninit_ui_for_phr_downloading_transaction_mode();
						release_actions_for_phr_downloading_transaction_mode();
						create_phr_management_page();*/

					//	working_lock.unlock();
					}
				});

				System.out.println("FINSHI Thread");
			}
		};

		thread.start();
		try{
			thread.join();
		}catch(InterruptedException e){

		}
		System.out.println("Finsih RUN DOWNLOAD");

		return m_result_download;
	}

	private boolean perform_phr_downloading_transaction(String phr_owner_name, String phr_owner_authority_name, String data_description, 
		int phr_id, String phr_download_to_path)
	{
		set_cancel_phr_downloading(false);
		set_phr_downloading_state(false);
		set_phr_decrypting_state(false);

		// Call to C function
		if(!verify_download_permission_main(phr_owner_name, phr_owner_authority_name))
		{
			// Call to C function
			record_phr_downloading_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			return false;
		}

		set_phr_downloading_state(true);

		// Call to C function
		if(!download_phr_main(phr_owner_name, phr_owner_authority_name, phr_id))
		{
			set_phr_downloading_state(false);

			// Call to C function
			record_phr_downloading_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			if(get_cancel_phr_downloading())
			{
				set_cancel_phr_downloading(false);
			//	JOptionPane.showMessageDialog(main_panel, "Downloading the PHR was aborted by a user");
			}

			return false;
		}

		set_phr_downloading_state(false);

		// Call to C function
		record_phr_downloading_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, true);

		set_indeterminate_mode_phr_decrypting_progressbar();
		set_phr_decrypting_state(true);

		// Call to C function
		if(!decrypt_phr_main(phr_download_to_path))
		{
			set_phr_decrypting_state(false);
			set_phr_decrypting_progressbar_value(0);

			// Call to C function
			record_phr_decrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);

			if(get_cancel_phr_downloading())
			{
				set_cancel_phr_downloading(false);
				//JOptionPane.showMessageDialog(main_panel, "Decrypting the PHR was aborted by a user");
			}

			System.out.println("Decrypting failled");

			return false;
		}

		set_phr_decrypting_state(false);
		set_phr_decrypting_progressbar_value(100);

		// Call to C function
		record_phr_decrypting_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, true);
		
		//JOptionPane.showMessageDialog(main_panel, "Downloading the PHR succeeded");
		System.out.println("FROM CLASS DOWNLOAD SUCCESS");

/*		m_isFinish = true;
*/
		return true;
	}

	private final void init_ui_for_phr_deletion_mode()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setMaximumSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		JPanel upper_inner_panel = new JPanel(new SpringLayout());
		upper_inner_panel.setPreferredSize(new Dimension(400, 80));
		upper_inner_panel.setMaximumSize(new Dimension(400, 80));

		upper_inner_panel.add(phr_owner_authority_name_label);
		upper_inner_panel.add(phr_owner_authority_name_combobox);

		upper_inner_panel.add(phr_owner_name_label);
		upper_inner_panel.add(phr_owner_name_textfield);

		SpringUtilities.makeCompactGrid(upper_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel upper_outer_panel = new JPanel();
		upper_outer_panel.setLayout(new BoxLayout(upper_outer_panel, BoxLayout.X_AXIS));
		upper_outer_panel.setPreferredSize(new Dimension(570, 80));
		upper_outer_panel.setMaximumSize(new Dimension(570, 80));
		upper_outer_panel.setAlignmentX(0.0f);
		upper_outer_panel.add(upper_inner_panel);

		// PHR deletion table
		JLabel phr_deletion_label = new JLabel("PHR List");
		phr_deletion_label.setPreferredSize(new Dimension(560, 10));
		phr_deletion_label.setMaximumSize(new Dimension(560, 10));
		phr_deletion_label.setAlignmentX(0.0f);

		phr_deletion_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		phr_deletion_table_model.setDataVector(null, new Object[] {"Data description", "Size", "Confidentiality level", "PHR id"});
    		phr_deletion_table = new JTable(phr_deletion_table_model);
		phr_deletion_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		phr_deletion_table.removeColumn(phr_deletion_table.getColumnModel().getColumn(3));

		JScrollPane phr_deletion_table_inner_panel = new JScrollPane();
		phr_deletion_table_inner_panel.setPreferredSize(new Dimension(560, 180));
		phr_deletion_table_inner_panel.setMaximumSize(new Dimension(560, 180));
		phr_deletion_table_inner_panel.setAlignmentX(0.0f);
		phr_deletion_table_inner_panel.getViewport().add(phr_deletion_table);

		JPanel phr_deletion_table_outer_panel = new JPanel();
		phr_deletion_table_outer_panel.setPreferredSize(new Dimension(570, 210));
		phr_deletion_table_outer_panel.setMaximumSize(new Dimension(570, 210));
		phr_deletion_table_outer_panel.setAlignmentX(0.0f);
		phr_deletion_table_outer_panel.add(phr_deletion_label);
		phr_deletion_table_outer_panel.add(phr_deletion_table_inner_panel);

		// Delete and quit buttons
		delete_phr_button.setAlignmentX(0.5f);	
		quit_phr_deletion_button.setAlignmentX(0.5f);
		delete_phr_button.setEnabled(false);

		JPanel main_buttons_panel = new JPanel();
		main_buttons_panel.setPreferredSize(new Dimension(570, 30));
		main_buttons_panel.setMaximumSize(new Dimension(570, 30));
		main_buttons_panel.setAlignmentX(0.0f);
		main_buttons_panel.add(delete_phr_button);
		main_buttons_panel.add(quit_phr_deletion_button);

		JPanel phr_management_inner_panel = new JPanel();
		phr_management_inner_panel.setPreferredSize(new Dimension(570, 365));
		phr_management_inner_panel.setMaximumSize(new Dimension(570, 365));
		phr_management_inner_panel.setAlignmentX(0.0f);
		phr_management_inner_panel.add(upper_outer_panel);
		phr_management_inner_panel.add(phr_deletion_table_outer_panel);
		phr_management_inner_panel.add(Box.createRigidArea(new Dimension(0, 50)));
		phr_management_inner_panel.add(main_buttons_panel);

		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.add(phr_management_inner_panel);
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}

	private final void uninit_ui_for_phr_deletion_mode()
	{
		phr_management_outer_panel.removeAll();
		phr_management_outer_panel.revalidate();
		phr_management_outer_panel.repaint();
	}	

	private void init_actions_for_phr_deletion_mode()
	{
		// PHR deletion table
		phr_deletion_table_mouseadapter = new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							delete_phr_button.setEnabled(true);
						}
					});
				}
			}
		};

		// Delete PHR button
		delete_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						delete_phr_button.setEnabled(false);

						if(validate_phr_deletion_input())
						{

							int     index                    = phr_owner_authority_name_combobox.getSelectedIndex();
							String  phr_owner_authority_name = authority_name_list.get(index);
							String  phr_owner_name           = phr_owner_name_textfield.getText();

							int     row                      = phr_deletion_table.getSelectedRow();
							String  data_description         = phr_deletion_table.getModel().getValueAt(row, 0).toString();
							int     phr_id                   = Integer.parseInt(phr_deletion_table.getModel().getValueAt(row, 3).toString());

							boolean is_restricted_level_phr_flag = phr_deletion_table.getModel(
								).getValueAt(row, 2).toString().equals("restricted");

							int    confirm_result = JOptionPane.showConfirmDialog(main_panel, 
								"Are you sure to delete this PHR?", "Delete Confirmation", JOptionPane.YES_NO_OPTION);

							if(confirm_result == JOptionPane.YES_OPTION)
							{
								perform_phr_deletion_transaction(phr_owner_name, phr_owner_authority_name, 
									data_description, phr_id, is_restricted_level_phr_flag);

								uninit_ui_for_phr_deletion_mode();
								release_actions_for_phr_deletion_mode();
								create_phr_management_page();

								working_lock.unlock();
							}
						}

						delete_phr_button.setEnabled(true);
		    			}
				});
			}
		};

		// Quit PHR deletion button
		quit_phr_deletion_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						quit_phr_deletion_button.setEnabled(false);

						uninit_ui_for_phr_deletion_mode();
						release_actions_for_phr_deletion_mode();
						create_phr_management_page();

						working_lock.unlock();

						quit_phr_deletion_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_phr_deletion_mode()
	{
		// PHR deletion table
		phr_deletion_table.addMouseListener(phr_deletion_table_mouseadapter);

		// Delete PHR button
		delete_phr_button.addActionListener(delete_phr_button_actionlistener);

		// Quit PHR deletion button
		quit_phr_deletion_button.addActionListener(quit_phr_deletion_button_actionlistener);
	}

	private void release_actions_for_phr_deletion_mode()
	{
		// PHR deletion table
		phr_deletion_table.removeMouseListener(phr_deletion_table_mouseadapter);

		// Delete PHR button
		delete_phr_button.removeActionListener(delete_phr_button_actionlistener);

		// Quit PHR deletion button
		quit_phr_deletion_button.removeActionListener(quit_phr_deletion_button_actionlistener);		
	}

	private boolean validate_phr_deletion_input()
	{
		// Validate the PHR item selection
		if(phr_deletion_table.getSelectedRow() < 0)
		{
			JOptionPane.showMessageDialog(this, "Please select the PHR that you need to delete");
			return false;
		}

		return true;
	}

	private boolean remove_selected_row_from_phr_deletion_table()
	{
		int row = phr_deletion_table.getSelectedRow();
		if(row < 0)
			return false;

		phr_deletion_table_model.removeRow(row);
		return true;
	}

	private void perform_phr_deletion_transaction(String phr_owner_name, String phr_owner_authority_name, 
		String data_description, int phr_id, boolean is_restricted_level_phr_flag)
	{
		// Call to C function
		if(!verify_delete_permission_main(phr_owner_name, phr_owner_authority_name))
		{
			// Call to C function
			record_phr_deletion_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			return;
		}

		// Call to C function
		if(!delete_phr_main(phr_owner_name, phr_owner_authority_name, phr_id))
		{
			// Call to C function
			record_phr_deletion_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, false);
			return;					
		}

	/**/	remove_selected_row_from_phr_deletion_table();

		// Call to C function
		record_phr_deletion_transaction_log_main(phr_owner_name, phr_owner_authority_name, data_description, true);

		if(is_restricted_level_phr_flag)
		{
			// Call to C function
			if(!remove_restricted_level_phr_key_params_main(phr_owner_name, phr_owner_authority_name, phr_id))
			{
				JOptionPane.showMessageDialog(main_panel, "The restricted-level PHR was removed " + 
					"successfully but \nwe failed to remove the emergency key parameters");

				return;
			}
		}

		JOptionPane.showMessageDialog(main_panel, "Deleting the PHR succeeded");
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
				ConfirmSignal           confirm_dialg_exiting        = new ConfirmSignal();
				UserTransactionAuditing transaction_auditing_dialog;

				// Call transaction auditing object
				transaction_auditing_dialog = new UserTransactionAuditing(main_panel, transaction_log_type, confirm_dialg_exiting);
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
				ConfirmSignal           confirm_dialg_exiting        = new ConfirmSignal();
				UserTransactionAuditing transaction_auditing_dialog;

				// Call transaction auditing object
				transaction_auditing_dialog = new UserTransactionAuditing(main_panel, transaction_log_type, start_year_index, start_month_index, 
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
		if(get_phr_encrypting_state())
		{
			set_phr_encrypting_progressbar_value(0);
		}
		else if(get_phr_decrypting_state())
		{
			set_phr_decrypting_progressbar_value(0);
		}

		JOptionPane.showMessageDialog(main_panel, alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Notify alert message to user and then terminate the application
		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}

	private synchronized void add_numerical_user_attribute_to_table_callback_handler(final String attribute_name, final String authority_name, final int attribute_value)
	{
		user_attribute_table_model.insertRow(user_attribute_table.getRowCount(), new Object[] {
			authority_name + "." + attribute_name + " = " + Integer.toString(attribute_value)});
	}

	private synchronized void add_non_numerical_user_attribute_to_table_callback_handler(final String attribute_name, final String authority_name)
	{
		user_attribute_table_model.insertRow(user_attribute_table.getRowCount(), new Object[] {authority_name + "." + attribute_name});	
	}

	private synchronized void clear_authority_list_callback_handler()
	{
		authority_name_list.clear();
	}

	private synchronized void add_authority_to_list_callback_handler(final String authority_name)
	{
		authority_name_list.add(authority_name);
	}

	private synchronized void clear_access_permission_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				access_permission_editing_button.setEnabled(false);
				access_permission_removal_button.setEnabled(false);
			
				access_permission_table_model.getDataVector().removeAllElements();
				access_permission_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_access_permission_to_table_callback_handler(final String assigned_username, final String assigned_user_authority_name, 
		final boolean upload_permission_flag, final boolean download_permission_flag, final boolean delete_permission_flag)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				access_permission_table_model.insertRow(access_permission_table.getRowCount(), new Object[] {assigned_user_authority_name + 
					"." + assigned_username, (upload_permission_flag) ? "true" : "false", (download_permission_flag) ? "true" : "false", 
					(delete_permission_flag) ? "true" : "false"});
			}
		});
	}

	private synchronized void clear_attribute_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				add_attribute_button.setEnabled(false);
			
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

				String authority_name = m_authority_name_node_js;
	
				attribute_table_model.insertRow(attribute_table.getRowCount(), new Object[] {authority_name + 
					"." + attribute_name, (is_numerical_attribute_flag) ? "true" : "false"});
			}
		});
	}

	private synchronized void update_phr_sent_progression_callback_handler(final int percent)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
		        	// phr_uploading_progressbar.setValue(percent);
			}
		});
	}

	private synchronized void update_remote_site_phr_id_callback_handler(final int remote_site_phr_id)
	{
		this.remote_site_phr_id = remote_site_phr_id;
	}

	private synchronized void add_downloading_authorized_phr_list_to_table_callback_handler(
		final String data_description, final String file_size, final String phr_conf_level, final int phr_id)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				phr_downloading_table_model.insertRow(phr_downloading_table.getRowCount(), 
					new Object[] {data_description, file_size, phr_conf_level, Integer.toString(phr_id)});
			}
		});
	}

	private synchronized void add_deletion_authorized_phr_list_to_table_callback_handler(
		final String data_description, final String file_size, final String phr_conf_level, final int phr_id)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				phr_deletion_table_model.insertRow(phr_deletion_table.getRowCount(), 
					new Object[] {data_description, file_size, phr_conf_level, Integer.toString(phr_id)});
			}
		});
	}

	private synchronized void update_phr_received_progression_callback_handler(final int percent)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
		        	//phr_downloading_progressbar.setValue(percent);
			}
		});
	}

	private synchronized void clear_emergency_trusted_user_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				ea_trusted_user_removal_button.setEnabled(false);
			
				ea_trusted_user_table_model.getDataVector().removeAllElements();
				ea_trusted_user_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_emergency_trusted_user_to_table_callback_handler(final String trusted_username, final String trusted_user_authority_name)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				ea_trusted_user_table_model.insertRow(ea_trusted_user_table.getRowCount(), new Object[] {
					trusted_user_authority_name + "." + trusted_username});
			}
		});
	}

	private synchronized void clear_emergency_phr_owner_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				ea_phr_owner_declination_button.setEnabled(false);
			
				ea_phr_owner_table_model.getDataVector().removeAllElements();
				ea_phr_owner_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_emergency_phr_owner_to_table_callback_handler(final String phr_owner_name, final String phr_owner_authority_name)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				ea_phr_owner_table_model.insertRow(ea_phr_owner_table.getRowCount(), new Object[] {
					phr_owner_authority_name + "." + phr_owner_name});
			}
		});
	}

	private synchronized void clear_restricted_phr_access_request_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				ea_phr_owner_request_cancel_button.setEnabled(false);
				ea_trusted_user_approval_button.setEnabled(false);
				ea_trusted_user_no_approval_button.setEnabled(false);
			
				ea_restricted_phr_access_request_table_model.getDataVector().removeAllElements();
				ea_restricted_phr_access_request_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_restricted_phr_access_request_to_table_callback_handler(final String full_requestor_name, final String full_phr_ownername, 
		final String data_description, final int approvals, final int threshold_value, final String request_status, final int phr_id)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				ea_restricted_phr_access_request_table_model.insertRow(ea_restricted_phr_access_request_table.getRowCount(), new Object[] 
					{full_requestor_name, full_phr_ownername, data_description, approvals + "/" + threshold_value, request_status, 
					Integer.toString(phr_id)});
			}
		});
	}

	// -------------------------------- WEB FUNCTION --------------------------------

	public String getAuthorityName(){
		return authority_name;
	}

	public String getUsername(){
		return username;
	}

	public String getemailAddress(){
		return email_address;
	}

	public Object getChangePasswdClass(){
		NewPasswordChanging new_passwd_changing_class = new NewPasswordChanging(main_panel, false, passwd);
		return new_passwd_changing_class;
	}

	public void updateNewPasswd(String passwd){
		this.passwd = passwd;
	}

	public Object getChangeEmailClass(){
		EmailAddressChanging email_address_changing_class = new EmailAddressChanging(main_panel, false, email_address, passwd);
		return email_address_changing_class;
	}

	public void updateNewEmail(String email_address){
		this.email_address = email_address;
		System.out.println(this.email_address);
	}

	public String[] getAuthorityNameList(){
		String[] authority_name_list_array = new String[authority_name_list.size()];
		authority_name_list.toArray(authority_name_list_array);
		return authority_name_list_array;
	}

	public Object[][] getTableUserAttribute () {
	    DefaultTableModel dtm = (DefaultTableModel) user_attribute_table.getModel();
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	// UPLOAD WEB 
	public boolean initTableAttributePHR(String authority_name)
	{		

		m_authority_name_node_js = authority_name;

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

    		update_attribute_list_main(authority_name);

    	return true;
    	
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

	public void setThresholdValue(String threshold_value){
		m_threshold_value = threshold_value;
	}

	public void setNoTrustedUsers(String no_trusted_users){
		m_no_trusted_users = no_trusted_users;
	}

	public boolean uploadSelfPHR(String phr_owner_name, String phr_owner_authority_name, 
		String phr_upload_from_path, String data_description, String confidentiality_level, String access_policy)
	{
		boolean res;

		res = run_phr_uploading_background_task(phr_owner_name, phr_owner_authority_name, 
								phr_upload_from_path, data_description, confidentiality_level, access_policy);
		
		return res;
	}

	public boolean verifyUploadPermissionMain(String phr_owner_name, String phr_owner_authority_name){
		boolean res = false;

		System.out.println("PHR OWNER NAME : " + phr_owner_name);
		System.out.println("PHR OWNER Authority NAME : " + phr_owner_authority_name);


		res  = verify_upload_permission_main(phr_owner_name, phr_owner_authority_name);
		System.out.println("RESULT VERIFY : " + res);

		return res;
	}

	public boolean checkUserExist(String authority_name, String username){
		return check_user_existence_main(authority_name, username);
	}

	// DOWNLOAD SELF WEB

	public boolean initDownloadSelfPHR(String phr_owner_authority_name, String phr_owner_name){
		boolean result =false;

		//String phr_owner_authority_name = authority_name;
		//String phr_owner_name           = username;
			
		if(verify_download_permission_main(phr_owner_name, phr_owner_authority_name))
		{
			System.out.println("ENTER DOWNLOAD MODE");
			initTableDownloadPHR();
		//	setup_actions_for_phr_downloading_mode();
			
			result = true;

			System.out.println("USER IN DOWNLOAD : " + phr_owner_name);
			System.out.println("Authority IN DOWNLOAD : " + phr_owner_authority_name);

			// Call to C function
			load_downloading_authorized_phr_list_main(phr_owner_name, phr_owner_authority_name);
		}

		return result;
	}

	public Object[][] getTableDownloadPHR() {

	    DefaultTableModel dtm = phr_downloading_table_model;
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();

	    System.out.println("ROW : " + nRow);

	    System.out.println("Col : " + nCol);

	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++){
	            tableData[i][j] = phr_downloading_table_model.getValueAt(i,j);
	            System.out.println(tableData[i][j]);
	        }

	    System.out.println(tableData);
	    return tableData;
	}

	private final void initTableDownloadPHR()
	{		
		// PHR downloading table

		phr_downloading_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    	phr_downloading_table_model.setDataVector(null, new Object[] {"Data description", "Size", "Confidentiality level", "PHR id"});
    	phr_downloading_table = new JTable(phr_downloading_table_model);
		phr_downloading_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		phr_downloading_table.removeColumn(phr_downloading_table.getColumnModel().getColumn(3));
	}

	public boolean downloadPHR(String phr_owner_authority_name, String phr_owner_name, String data_description, int phr_id, String phr_download_to_path){
		
			boolean isFinish = false;
		// if(validate_phr_downloading_input())
		// {
			int    index                    = phr_owner_authority_name_combobox.getSelectedIndex();

			// String phr_owner_authority_name = authority_name;

			// String phr_owner_name           = username;

			int    row                      = phr_downloading_table.getSelectedRow();

			boolean result;
			// Run background tasks
			isFinish = run_phr_downloading_background_task(phr_owner_name, phr_owner_authority_name, 
			data_description, phr_id, phr_download_to_path);
		// }
			return isFinish;
	}


	// Delete
	public boolean initDeleteSelfPHR(){
		boolean result =false;

		String phr_owner_authority_name = authority_name;
		String phr_owner_name           = username;
			
		if(verify_delete_permission_main(phr_owner_name, phr_owner_authority_name))
		{
			System.out.println("DELETE MODE");

			result = true;

			initTableDeletePHR();

			// Call to C function
			load_deletion_authorized_phr_list_main(phr_owner_name, phr_owner_authority_name);
		}

		return result;
	}

	public Object[][] getTableDeletePHR() {

	    DefaultTableModel dtm = phr_deletion_table_model;
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	private final void initTableDeletePHR()
	{		
		phr_deletion_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    	phr_deletion_table_model.setDataVector(null, new Object[] {"Data description", "Size", "Confidentiality level", "PHR id"});
    	phr_deletion_table = new JTable(phr_deletion_table_model);
		phr_deletion_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		phr_deletion_table.removeColumn(phr_deletion_table.getColumnModel().getColumn(3));
	}

	public boolean deletePHR(String data_description, int phr_id, String restricted_level_phr_flag){

		//if(validate_phr_deletion_input())
		//{
			int     index                    = phr_owner_authority_name_combobox.getSelectedIndex();
			String  phr_owner_authority_name = authority_name;
			String  phr_owner_name           = username;

			boolean is_restricted_level_phr_flag = restricted_level_phr_flag.equals("restricted");

			perform_phr_deletion_transaction(phr_owner_name, phr_owner_authority_name, 
			data_description, phr_id, is_restricted_level_phr_flag);

		//	uninit_ui_for_phr_deletion_mode();
		//	release_actions_for_phr_deletion_mode();
			
			return true;

	}

	// ACCESS PERMISSION MANAGER

	public boolean initTableAccessPermissionPHR()
	{		

		update_authority_list_main();

		access_permission_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    	access_permission_table_model.setDataVector(null, new Object[] {"Name", "Upload Permission?", 
			"Download Permission?", "Delete Permission?"});

    	access_permission_table = new JTable(access_permission_table_model);

    	update_assigned_access_permission_list_main();

    	return true;
    	
	}

	public Object[][] getTableAccessPermissionPHR() {

	    DefaultTableModel dtm = access_permission_table_model;
	    int nRow = dtm.getRowCount(), nCol = dtm.getColumnCount();
	    Object[][] tableData = new Object[nRow][nCol];
	    for (int i = 0 ; i < nRow ; i++)
	        for (int j = 0 ; j < nCol ; j++)
	            tableData[i][j] = dtm.getValueAt(i,j);
	    return tableData;
	}

	public Object getClassAccessPermissionManagementEdit(int row){
		String  full_username            = access_permission_table.getModel().getValueAt(row, 0).toString();
		boolean upload_permission_flag   = access_permission_table.getModel().getValueAt(row, 1).toString().equals("true");
		boolean download_permission_flag = access_permission_table.getModel().getValueAt(row, 2).toString().equals("true");
		boolean delete_permission_flag   = access_permission_table.getModel().getValueAt(row, 3).toString().equals("true");

		String  authority_name           = full_username.substring(0, full_username.indexOf("."));
		String  username                 = full_username.substring(full_username.indexOf(".") + 1);

		System.out.println("Full_username : " + full_username);	


		AccessPermissionManagement access_permission_editing = new AccessPermissionManagement(authority_name, username, 
							upload_permission_flag, download_permission_flag, delete_permission_flag);

		return access_permission_editing;
	}

	public void update_assigned_access_permission_list(){
		update_assigned_access_permission_list_main();
	}

	public Object getClassAccessPermissionManagementAssign(){
		AccessPermissionManagement access_permission_assignment_dialog;
		access_permission_assignment_dialog = new AccessPermissionManagement(authority_name, username, authority_name_list);
		return access_permission_assignment_dialog;
	}

	public boolean removeAccessPermission(String full_username){
		String authority_name = full_username.substring(0, full_username.indexOf("."));
		String username       = full_username.substring(full_username.indexOf(".") + 1);
		remove_access_permission_main(authority_name, username);

		return true;
	}

	public boolean setCancelDownload(){
		set_cancel_phr_downloading(true);
		if(get_phr_downloading_state())
		{
			// Call to C function
			cancel_phr_downloading_main();
		}
		else if(get_phr_decrypting_state())
		{
			// Call to C function
			cancel_phr_decrypting_main();
		}

		return true;
	}

	public boolean setCancelUpload(){
		set_cancel_phr_uploading(true);
		if(get_phr_encrypting_state())
		{
			// Call to C function
			cancel_phr_encrypting_main();
		}
		else if(get_phr_uploading_state())
		{
			// Call to C function
			cancel_phr_uploading_main();
		}
		return true;
	}
}


