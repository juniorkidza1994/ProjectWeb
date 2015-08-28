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

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;
import java.math.*;

public class EmU_AdminMain extends JFrame implements ConstantVars
{
	private static final long serialVersionUID = -1513582265865921788L;

	// Declaration of the Native C functions
	private native void init_backend();
	private native void store_variables_to_backend(String ssl_cert_hash, String username, String authority_name, String passwd, String emergency_staff_auth_ip_addr);
	private native void update_user_list_main();
	private native void update_admin_list_main();
	private native void update_phr_authority_list_main();
	private native boolean reset_user_passwd_main(boolean is_admin_flag, String username);
	private native boolean remove_user_main(boolean is_admin_flag, String username);
	private native boolean remove_phr_authority_main(String phr_authority_name);

	// Variables
	private JPanel            main_panel                              = new JPanel();
	private ReentrantLock     working_lock                            = new ReentrantLock();
	private EmU_ShutdownHook  shutdown_hooker;

	// Info page
	private JPanel            info_page                        	  = new JPanel();

	private JTextField        email_address_textfield                 = new JTextField(TEXTFIELD_LENGTH);

	private JButton           change_passwd_button                    = new JButton("Change a password");
	private JButton           change_email_address_button             = new JButton("Change an e-mail address");

	private JTextField        mail_server_url_textfield               = new JTextField(TEXTFIELD_LENGTH);
	private JTextField        authority_email_address_textfield       = new JTextField(TEXTFIELD_LENGTH);

	private JButton           change_mail_server_configuration_button = new JButton("Change configuration");

	// User page
	private JPanel            user_page                               = new JPanel();
	private DefaultTableModel user_table_model;
	private JTable            user_table;

	private JButton           user_registration_button                = new JButton("Register a user");
	private JButton           user_editing_button                     = new JButton("Edit");
	private JButton           user_passwd_resetting_button            = new JButton("Reset a password");
	private JButton           user_removal_button                     = new JButton("Remove");
	private JButton           user_page_refresh_info_button           = new JButton("Refresh");

	// Admin page
	private JPanel            admin_page                              = new JPanel();
	private DefaultTableModel admin_table_model;
	private JTable            admin_table;

	private JButton           admin_registration_button               = new JButton("Register an admin");
	private JButton           admin_editing_button                    = new JButton("Edit");
	private JButton           admin_passwd_resetting_button           = new JButton("Reset a password");
	private JButton           admin_removal_button                    = new JButton("Remove");
	private JButton           admin_page_refresh_info_button          = new JButton("Refresh");

	// PHR authority page
	private JPanel            phr_authority_page                      = new JPanel();
	private DefaultTableModel phr_authority_table_model;
	private JTable            phr_authority_table;

	private JButton           phr_authority_registration_button       = new JButton("Register a PHR authority");
	private JButton           phr_authority_removal_button            = new JButton("Remove");
	private JButton           phr_authority_editing_button            = new JButton("Edit");
	private JButton           phr_authority_page_refresh_info_button  = new JButton("Refresh");

	// Statusbar
	private JLabel            statusbar_label                         = new JLabel("");

	// Derive from EmU_Login object 
	private String            username;
	private String            passwd;
	private String            email_address;
	private String            authority_name;
	private String            emergency_staff_auth_ip_addr;
	private String            mail_server_url;
	private String            authority_email_address;
	private String            authority_email_passwd;

	public EmU_AdminMain(String username, String passwd, String email_address, String authority_name, String emergency_staff_auth_ip_addr, 
		String mail_server_url, String authority_email_address, String authority_email_passwd, String ssl_cert_hash)
	{
		super("Emergency unit: Admin Main");

		this.username                     = username;
		this.email_address                = email_address;
		this.passwd                       = passwd;
		this.authority_name               = authority_name;
		this.emergency_staff_auth_ip_addr = emergency_staff_auth_ip_addr;
		this.mail_server_url              = mail_server_url;
		this.authority_email_address      = authority_email_address;
		this.authority_email_passwd       = authority_email_passwd;
		
		// Load JNI backend library
		System.loadLibrary("PHRapp_EmU_Admin_JNI");

		working_lock.lock();

		// Call to C functions
		init_backend();
		store_variables_to_backend(ssl_cert_hash, username, authority_name, passwd, emergency_staff_auth_ip_addr);

		init_ui();
		setup_actions();

		// Call to C functions
		update_user_list_main();
		update_admin_list_main();
		update_phr_authority_list_main();

		working_lock.unlock();

		automatic_relogin();
	}

	private final void init_ui()
	{
		main_panel.setLayout(new BorderLayout());

		create_info_page();
		create_user_page();
		create_admin_page();
		create_phr_authority_page();

		JTabbedPane tabbed_pane = new JTabbedPane();
		tabbed_pane.addTab("Info", info_page);
		tabbed_pane.addTab("User Management", user_page);
		tabbed_pane.addTab("Admin Management", admin_page);
		tabbed_pane.addTab("PHR Authority Management", phr_authority_page);
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
		username_textfield.setText(username + "(EmU's admin privilege)");
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
		basic_info_panel.setPreferredSize(new Dimension(580, 230));
		basic_info_panel.setMaximumSize(new Dimension(580, 230));
		basic_info_panel.setAlignmentX(0.0f);
		basic_info_panel.add(basic_info_outer_panel);

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
		mail_server_configuration_panel.setPreferredSize(new Dimension(580, 195));
		mail_server_configuration_panel.setMaximumSize(new Dimension(580, 195));
		mail_server_configuration_panel.setAlignmentX(0.0f);
		mail_server_configuration_panel.add(mail_server_configuration_outer_panel);

		// Info page
		info_page.setLayout(new BoxLayout(info_page, BoxLayout.Y_AXIS));
		info_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		info_page.add(basic_info_panel);
		info_page.add(mail_server_configuration_panel);
	}

	private final void create_user_page()
	{
		// Users
		JLabel user_label = new JLabel("Users");

		user_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1133582265865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		user_table_model.setDataVector(null, new Object[] {"Username", "E-mail address"});
    		user_table = new JTable(user_table_model);
		user_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane user_table_panel = new JScrollPane();
		user_table_panel.setPreferredSize(new Dimension(600, 200));
		user_table_panel.setMaximumSize(new Dimension(600, 200));
		user_table_panel.setAlignmentX(0.0f);
		user_table_panel.getViewport().add(user_table);

		// User buttons
		user_registration_button.setAlignmentX(0.5f);
		user_editing_button.setAlignmentX(0.5f);
		user_passwd_resetting_button.setAlignmentX(0.5f);
		user_removal_button.setAlignmentX(0.5f);
		user_editing_button.setEnabled(false);
		user_passwd_resetting_button.setEnabled(false);
		user_removal_button.setEnabled(false);

		JPanel user_buttons_panel = new JPanel();
		user_buttons_panel.setPreferredSize(new Dimension(600, 30));
		user_buttons_panel.setMaximumSize(new Dimension(600, 30));
		user_buttons_panel.setAlignmentX(0.0f);
		user_buttons_panel.add(user_registration_button);
		user_buttons_panel.add(user_editing_button);
		user_buttons_panel.add(user_passwd_resetting_button);
		user_buttons_panel.add(user_removal_button);

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
		user_page.add(user_table_panel);
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
			private static final long serialVersionUID = -1123582265865921793L;

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

	private final void create_phr_authority_page()
	{
		// PHR authorities
		JLabel phr_authority_label = new JLabel("PHR Authorities");

		phr_authority_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582265805921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		phr_authority_table_model.setDataVector(null, new Object[] {"Authority name", "IP address"});
    		phr_authority_table = new JTable(phr_authority_table_model);
		phr_authority_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane phr_authority_table_panel = new JScrollPane();
		phr_authority_table_panel.setPreferredSize(new Dimension(600, 200));
		phr_authority_table_panel.setMaximumSize(new Dimension(600, 200));
		phr_authority_table_panel.setAlignmentX(0.0f);
		phr_authority_table_panel.getViewport().add(phr_authority_table);

		// PHR authority buttons
		phr_authority_registration_button.setAlignmentX(0.5f);
		phr_authority_editing_button.setAlignmentX(0.5f);
		phr_authority_editing_button.setEnabled(false);
		phr_authority_removal_button.setAlignmentX(0.5f);
		phr_authority_removal_button.setEnabled(false);
	
		JPanel phr_authority_buttons_panel = new JPanel();
		phr_authority_buttons_panel.setPreferredSize(new Dimension(600, 30));
		phr_authority_buttons_panel.setMaximumSize(new Dimension(600, 30));
		phr_authority_buttons_panel.setAlignmentX(0.0f);
		phr_authority_buttons_panel.add(phr_authority_registration_button);
		phr_authority_buttons_panel.add(phr_authority_editing_button);
		phr_authority_buttons_panel.add(phr_authority_removal_button);

		// Refresh button
		phr_authority_page_refresh_info_button.setAlignmentX(0.5f);

		JPanel phr_authority_page_refresh_info_button_panel = new JPanel();
		phr_authority_page_refresh_info_button_panel.setPreferredSize(new Dimension(600, 30));
		phr_authority_page_refresh_info_button_panel.setMaximumSize(new Dimension(600, 30));
		phr_authority_page_refresh_info_button_panel.setAlignmentX(0.0f);
		phr_authority_page_refresh_info_button_panel.add(phr_authority_page_refresh_info_button);

		phr_authority_page.setLayout(new BoxLayout(phr_authority_page, BoxLayout.Y_AXIS));
		phr_authority_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		phr_authority_page.add(phr_authority_label);
		phr_authority_page.add(phr_authority_table_panel);
		phr_authority_page.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_authority_page.add(phr_authority_buttons_panel);
		phr_authority_page.add(Box.createRigidArea(new Dimension(0, 10)));
		phr_authority_page.add(phr_authority_page_refresh_info_button_panel);		
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
		shutdown_hooker = new EmU_ShutdownHook();
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

		// User table
		user_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							user_editing_button.setEnabled(true);
							user_passwd_resetting_button.setEnabled(true);
							user_removal_button.setEnabled(true);
						}
					});
				}
			}
		});

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
						EmU_UserAndAdminManagement user_registration_dialog = new EmU_UserAndAdminManagement(main_panel, false);
						user_registration_dialog.setVisible(true);

						// If a new user is registered then update the user list
						if(user_registration_dialog.get_result())
						{
							// Call to C function
							update_user_list_main();
						}

						working_lock.unlock();
						user_registration_button.setEnabled(true);
					}
				});
            		}
        	});

		// User editing button
		user_editing_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_editing_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_editing_button.setEnabled(true);
							return;
						}

						int row = user_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							user_editing_button.setEnabled(false);
							user_passwd_resetting_button.setEnabled(false);
							user_removal_button.setEnabled(false);
							return;
						}

						String username      = user_table.getModel().getValueAt(row, 0).toString();
						String email_address = user_table.getModel().getValueAt(row, 1).toString();

						// Call user management object
						EmU_UserAndAdminManagement user_editing_dialog = new EmU_UserAndAdminManagement(main_panel, false, username, email_address);
						user_editing_dialog.setVisible(true);

						// If a user's e-mail address is edited then update the user list
						if(user_editing_dialog.get_result())
						{
							// Call to C function
							update_user_list_main();

							working_lock.unlock();
							user_editing_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							user_editing_button.setEnabled(true);
						}
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

						int row = user_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							user_editing_button.setEnabled(false);
							user_passwd_resetting_button.setEnabled(false);
							user_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, "Are you sure to reset a password for this user?", 
							"Reset Password Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							user_passwd_resetting_button.setEnabled(true);
							return;
						}

						String username = user_table.getModel().getValueAt(row, 0).toString();

						// Call to C functions
						if(reset_user_passwd_main(false, username))
						{
							update_user_list_main();
							JOptionPane.showMessageDialog(main_panel, "The new user's password " + 
								"was sent to the user's e-mail address already");

							working_lock.unlock();
							user_passwd_resetting_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							user_passwd_resetting_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// User removal button
		user_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						user_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							user_removal_button.setEnabled(true);
							return;
						}

						int row = user_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							user_editing_button.setEnabled(false);
							user_passwd_resetting_button.setEnabled(false);
							user_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to remove this user?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							user_removal_button.setEnabled(true);
							return;
						}

						String username = user_table.getModel().getValueAt(row, 0).toString();

						// Call to C functions
						if(remove_user_main(false, username))
						{
							update_user_list_main();

							working_lock.unlock();
							user_removal_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							user_removal_button.setEnabled(true);
						}
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

						// Call to C function
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
						EmU_UserAndAdminManagement admin_registration_dialog = new EmU_UserAndAdminManagement(main_panel, true);
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
						EmU_UserAndAdminManagement admin_editing_dialog = new EmU_UserAndAdminManagement(main_panel, true, username, email_address);
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
						if(reset_user_passwd_main(true, username))
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
						if(remove_user_main(true, username))
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

		// PHR authority table
		phr_authority_table.addMouseListener(new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							int row = phr_authority_table.getSelectedRow();
							if(row == -1)
							{
								JOptionPane.showMessageDialog(main_panel, "No any row selected");
								phr_authority_editing_button.setEnabled(false);
								phr_authority_removal_button.setEnabled(false);
								return;
							}

							phr_authority_editing_button.setEnabled(true);
							phr_authority_removal_button.setEnabled(true);
						}
					});
				}
			}
		});

		// PHR authority registration button
		phr_authority_registration_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						phr_authority_registration_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							phr_authority_registration_button.setEnabled(true);
							return;
						}

						// Call PHR authority management object
						EmU_PHRAuthorityManagement phr_authority_registration_dialog = new EmU_PHRAuthorityManagement(main_panel);
						phr_authority_registration_dialog.setVisible(true);

						// If a new PHR authority is registered then update the PHR authority list
						if(phr_authority_registration_dialog.get_result())
						{
							// Call to C function
							update_phr_authority_list_main();
						}

						working_lock.unlock();
						phr_authority_registration_button.setEnabled(true);
					}
				});
            		}
        	});

		// PHR authority editing button
		phr_authority_editing_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						phr_authority_editing_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							phr_authority_editing_button.setEnabled(true);
							return;
						}

						int row = phr_authority_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							phr_authority_editing_button.setEnabled(false);
							phr_authority_removal_button.setEnabled(false);
							return;
						}

						String phr_authority_name = phr_authority_table.getModel().getValueAt(row, 0).toString();
						String ip_address         = phr_authority_table.getModel().getValueAt(row, 1).toString();

						// Call PHR authority management object
						EmU_PHRAuthorityManagement phr_authority_editing_dialog = new EmU_PHRAuthorityManagement(
							main_panel, phr_authority_name, ip_address);

						phr_authority_editing_dialog.setVisible(true);

						// If a PHR authority's ip address is edited then update the PHR authority list
						if(phr_authority_editing_dialog.get_result())
						{
							// Call to C function
							update_phr_authority_list_main();

							working_lock.unlock();
							phr_authority_editing_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							phr_authority_editing_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// PHR authority removal button
		phr_authority_removal_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						phr_authority_removal_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							phr_authority_removal_button.setEnabled(true);
							return;
						}

						int row = phr_authority_table.getSelectedRow();
						if(row == -1)
						{
							JOptionPane.showMessageDialog(main_panel, "No any row selected");

							working_lock.unlock();
							phr_authority_editing_button.setEnabled(false);
							phr_authority_removal_button.setEnabled(false);
							return;
						}

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to remove this authority?", "Remove Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							working_lock.unlock();
							phr_authority_removal_button.setEnabled(true);
							return;
						}

						String phr_authority_name = phr_authority_table.getModel().getValueAt(row, 0).toString();

						// Call to C functions
						if(remove_phr_authority_main(phr_authority_name))
						{
							update_phr_authority_list_main();

							working_lock.unlock();
							phr_authority_removal_button.setEnabled(false);
						}
						else
						{
							working_lock.unlock();
							phr_authority_removal_button.setEnabled(true);
						}
					}
				});
            		}
        	});

		// PHR authority page refresh info button
		phr_authority_page_refresh_info_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
            				public void run()
					{
						phr_authority_page_refresh_info_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							phr_authority_page_refresh_info_button.setEnabled(true);
							return;
						}

						// Call to C function
						update_phr_authority_list_main();

						working_lock.unlock();
						phr_authority_page_refresh_info_button.setEnabled(true);
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

				// Invisible EmU_AdminMain frame and destroy it
				setVisible(false);
				dispose();
				System.gc();

				if(relogin_result == JOptionPane.YES_OPTION)
				{
					// Call EmU_Login object
					EmU_Login login_main = new EmU_Login();
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

	// Callback methods (Returning from C code)
	private void backend_alert_msg_callback_handler(final String alert_msg)
	{
		JOptionPane.showMessageDialog(main_panel, alert_msg);
	}

	private void backend_fatal_alert_msg_callback_handler(final String alert_msg)
	{
		// Notify alert message to user and then terminate the application
		JOptionPane.showMessageDialog(main_panel, alert_msg);
		System.exit(1);
	}

	private synchronized void clear_user_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				user_editing_button.setEnabled(false);
				user_passwd_resetting_button.setEnabled(false);
				user_removal_button.setEnabled(false);

				user_table_model.getDataVector().removeAllElements();
				user_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_user_to_table_callback_handler(final String username, final String email_address)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				user_table_model.insertRow(user_table.getRowCount(), new Object[] {username, email_address});
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

	private synchronized void clear_phr_authority_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				phr_authority_editing_button.setEnabled(false);
				phr_authority_removal_button.setEnabled(false);

				phr_authority_table_model.getDataVector().removeAllElements();
				phr_authority_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_phr_authority_to_table_callback_handler(final String phr_authority_name, final String ip_address)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				phr_authority_table_model.insertRow(phr_authority_table.getRowCount(), new Object[] {phr_authority_name, ip_address});
			}
		});
	}
}



