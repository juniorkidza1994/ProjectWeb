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

public class EmU_UserMain extends JFrame implements ConstantVars
{
	private static final long serialVersionUID = -1913582265865921788L;

	// Declaration of the Native C functions
	private native void init_backend();
	private native void store_variables_to_backend(String ssl_cert_hash, String username, String authority_name, String passwd, String emergency_staff_auth_ip_addr);
	private native void update_phr_authority_list_main();
	private native boolean check_phr_owner_existence_main(String emergency_server_ip_addr, String phr_owner_authority_name, String phr_owner_name);
	private native boolean load_emergency_phr_list_main(String emergency_server_ip_addr, String phr_owner_authority_name, String phr_owner_name);
	private native boolean load_requested_restricted_phr_list_main(String phr_authority_name, String emergency_server_ip_addr);
	private native boolean download_emergency_phr_main(String target_emergency_server_ip_addr, String phr_owner_name, String phr_owner_authority_name, 
		int phr_id, String phr_description, boolean is_restricted_level_phr_flag);
	private native void cancel_emergency_phr_downloading_main();
	private native boolean extract_emergency_phr_main(String phr_download_to_path);
	private native void cancel_emergency_phr_extracting_main();
	private native boolean request_restricted_level_phr_accessing_main(String emergency_server_ip_addr, String phr_owner_authority_name, String phr_owner_name, 
		int phr_id, String phr_description, String emergency_staff_email_address);
	private native boolean cancel_restricted_level_phr_access_request_main(String emergency_server_ip_addr, String phr_owner_authority_name, 
		String phr_owner_name, int phr_id, String phr_description);
	private native boolean update_restricted_phr_list_main(String emergency_server_ip_addr, String phr_owner_authority_name, String phr_owner_name);
	private native boolean update_requested_restricted_phr_list_main(String phr_authority_name, String emergency_server_ip_addr);

	// Variables
	private JPanel                      main_panel                                                              = new JPanel();
	private ReentrantLock               working_lock                                                            = new ReentrantLock();
	private EmU_ShutdownHook            shutdown_hooker;

	// Info page
	private JPanel                      info_page                                                               = new JPanel();
                
	private JTextField                  email_address_textfield                                                 = new JTextField(TEXTFIELD_LENGTH);

	private JButton                     change_passwd_button                                                    = new JButton("Change a password");
	private JButton                     change_email_address_button                                             = new JButton("Change an e-mail address");

	// Emergency PHR access page
	private JPanel                      emergency_phr_access_outer_panel                                        = new JPanel();
	private JScrollPane                 emergency_phr_access_scollpane_page                                     = new JScrollPane(emergency_phr_access_outer_panel);

	private ArrayList<PHRAuthorityInfo> phr_authority_info_list  		                                    = new ArrayList<PHRAuthorityInfo>();

	private JComboBox                   phr_owner_authority_name_combobox;
	private JTextField                  phr_owner_name_textfield;
  
	private JButton                     search_phr_owner_button                                                 = new JButton("Search");
	private JButton                     track_phr_request_button                                                = new JButton("Track requests");

	private JLabel                      no_any_phr_authority_available_alert_msg_label                          = new JLabel("No any PHR authority available");

	// Emergency PHR downloading mode
	// Secure-level PHR
	private DefaultTableModel           secure_phr_downloading_table_model;
	private JTable                      secure_phr_downloading_table;

	private JTextField                  secure_phr_download_to_path_textfield;
	private JButton                     browse_secure_phr_download_to_path_button                               = new JButton("Browse");

	private JButton                     download_secure_phr_button                                              = new JButton("Download");
	private JButton                     quit_secure_phr_downloading_button                                      = new JButton("Quit");

	private MouseAdapter                secure_phr_downloading_table_mouseadapter;
	private ActionListener              browse_secure_phr_download_to_path_button_actionlistener;
	private ActionListener              download_secure_phr_button_actionlistener;
	private ActionListener              quit_secure_phr_downloading_button_actionlistener;

	// Restricted-level PHR
	private DefaultTableModel           restricted_phr_downloading_table_model;
	private JTable                      restricted_phr_downloading_table;

	private JTextField                  restricted_phr_download_to_path_textfield;
	private JButton                     browse_restricted_phr_download_to_path_button                           = new JButton("Browse");

	private JButton                     request_restricted_phr_button                                           = new JButton("Request for an access");
	private JButton                     cancel_request_restricted_phr_button                                    = new JButton("Cancel a request");
	private JButton                     download_restricted_phr_button                                          = new JButton("Download");
	private JButton                     quit_restricted_phr_downloading_button                                  = new JButton("Quit");
	
	private MouseAdapter                restricted_phr_downloading_table_mouseadapter;
	private ActionListener              browse_restricted_phr_download_to_path_button_actionlistener;
	private ActionListener		    request_restricted_phr_button_actionlistener;
	private ActionListener              cancel_request_restricted_phr_button_actionlistener;
	private ActionListener              download_restricted_phr_button_actionlistener;
	private ActionListener              quit_restricted_phr_downloading_button_actionlistener;

	// These objects use for both the secure-level and restricted-level PHR download transaction
	private boolean                     emergency_phr_ems_side_processing_success_flag;
	private JProgressBar                emergency_phr_ems_side_processing_progressbar;
	private JProgressBar                emergency_phr_downloading_progressbar;
	private JProgressBar                emergency_phr_extracting_progressbar;
	private JButton                     cancel_emergency_phr_downloading_transaction_button                     = new JButton("Cancel");
	private ActionListener              cancel_emergency_phr_downloading_transaction_button_actionlistener;

	private boolean                     emergency_phr_downloading_state_flag;
	private boolean                     emergency_phr_extracting_state_flag;
	private boolean                     cancel_emergency_phr_downloading_flag;

	// Requested restricted-level PHR tracking mode
	private DefaultTableModel           requested_restricted_phr_tracking_table_model;
	private JTable                      requested_restricted_phr_tracking_table;

	private boolean                     no_any_requested_restricted_phr_flag;

	private JTextField                  requested_restricted_phr_download_to_path_textfield;
	private JButton                     browse_requested_restricted_phr_download_to_path_button                 = new JButton("Browse");

	private JButton                     download_requested_restricted_phr_tracking_mode_button                  = new JButton("Download");
	private JButton                     cancel_requested_restricted_phr_tracking_mode_button                    = new JButton("Cancel a request");
	private JButton                     quit_requested_restricted_phr_tracking_mode_button                      = new JButton("Quit");
	
	private MouseAdapter                requested_restricted_phr_tracking_table_mouseadapter;
	private ActionListener              browse_requested_restricted_phr_download_to_path_button_actionlistener;
	private ActionListener              download_requested_restricted_phr_tracking_mode_button_actionlistener;
	private ActionListener              cancel_requested_restricted_phr_tracking_mode_button_actionlistener;
	private ActionListener              quit_requested_restricted_phr_tracking_mode_button_actionlistener;

	// Statusbar
	private JLabel                      statusbar_label                                                         = new JLabel("");

	// Derive from EmU_Login object 
	private String                      username;
	private String                      passwd;
	private String                      email_address;
	private String                      authority_name;
	private String                      emergency_staff_auth_ip_addr;

	public EmU_UserMain(String username, String passwd, String email_address, String authority_name, String emergency_staff_auth_ip_addr, String ssl_cert_hash)
	{
		super("Emergency unit: User Main");

		this.username                     = username;
		this.email_address                = email_address;
		this.passwd                       = passwd;
		this.authority_name               = authority_name;
		this.emergency_staff_auth_ip_addr = emergency_staff_auth_ip_addr;
		
		// Load JNI backend library
		System.loadLibrary("PHRapp_EmU_User_JNI");

		working_lock.lock();

		// Call to C functions
		init_backend();
		store_variables_to_backend(ssl_cert_hash, username, authority_name, passwd, emergency_staff_auth_ip_addr);
		update_phr_authority_list_main();

		init_ui();
		init_actions_for_emergency_phr_downloading_mode();
		init_actions_for_emergency_phr_downloading_transaction_mode();
		init_actions_for_requested_restricted_phr_tracking_mode();
		setup_actions();

		working_lock.unlock();

		automatic_relogin();
	}

	private final void init_ui()
	{
		main_panel.setLayout(new BorderLayout());

		create_info_page();
		create_emergency_phr_access_page();

		JTabbedPane tabbed_pane = new JTabbedPane();
		tabbed_pane.addTab("Info", info_page);
		tabbed_pane.addTab("Emergency PHR Access", emergency_phr_access_scollpane_page);
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
		username_textfield.setText(username + "(EmU's user privilege)");
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

		// Info page
		info_page.setLayout(new BoxLayout(info_page, BoxLayout.Y_AXIS));
		info_page.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		info_page.add(basic_info_panel);
	}

	private final void create_emergency_phr_access_page()
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

		JPanel search_phr_by_user_ui_upper_panel = new JPanel(new SpringLayout());
		search_phr_by_user_ui_upper_panel.add(phr_owner_authority_name_label);
		search_phr_by_user_ui_upper_panel.add(phr_owner_authority_name_combobox);
		search_phr_by_user_ui_upper_panel.add(phr_owner_name_label);
		search_phr_by_user_ui_upper_panel.add(phr_owner_name_textfield);

		SpringUtilities.makeCompactGrid(search_phr_by_user_ui_upper_panel, 2, 2, 5, 10, 10, 10);

		JPanel search_phr_by_user_ui_inner_panel = new JPanel();
		search_phr_by_user_ui_inner_panel.setLayout(new BoxLayout(search_phr_by_user_ui_inner_panel, BoxLayout.X_AXIS));
		search_phr_by_user_ui_inner_panel.setPreferredSize(new Dimension(400, 80));
		search_phr_by_user_ui_inner_panel.setMaximumSize(new Dimension(400, 80));
		search_phr_by_user_ui_inner_panel.setAlignmentX(0.5f);
		search_phr_by_user_ui_inner_panel.add(search_phr_by_user_ui_upper_panel);

		// Search PHR owner button
		search_phr_owner_button.setAlignmentX(0.5f);	

		JPanel search_phr_owner_button_panel = new JPanel();
		search_phr_owner_button_panel.setPreferredSize(new Dimension(440, 30));
		search_phr_owner_button_panel.setMaximumSize(new Dimension(440, 30));
		search_phr_owner_button_panel.setAlignmentX(0.5f);
		search_phr_owner_button_panel.add(search_phr_owner_button);

		JPanel search_phr_by_user_ui_outer_panel = new JPanel(new GridLayout(0, 1));
		search_phr_by_user_ui_outer_panel.setLayout(new BoxLayout(search_phr_by_user_ui_outer_panel, BoxLayout.Y_AXIS));
		search_phr_by_user_ui_outer_panel.setPreferredSize(new Dimension(440, 170));
		search_phr_by_user_ui_outer_panel.setMaximumSize(new Dimension(440, 170));
    		search_phr_by_user_ui_outer_panel.setBorder(BorderFactory.createTitledBorder("Search for emergency PHRs"));
		search_phr_by_user_ui_outer_panel.setAlignmentX(0.5f);
		search_phr_by_user_ui_outer_panel.add(Box.createRigidArea(new Dimension(0, 10)));
		search_phr_by_user_ui_outer_panel.add(search_phr_by_user_ui_inner_panel);
		search_phr_by_user_ui_outer_panel.add(search_phr_owner_button_panel);

		// Track PHR request button
		track_phr_request_button.setAlignmentX(0.5f);	

		JPanel track_phr_request_button_panel = new JPanel();
		track_phr_request_button_panel.setPreferredSize(new Dimension(440, 30));
		track_phr_request_button_panel.setMaximumSize(new Dimension(440, 30));
		track_phr_request_button_panel.setAlignmentX(0.0f);
		track_phr_request_button_panel.add(track_phr_request_button);

		JPanel track_phr_request_outer_panel = new JPanel(new GridLayout(0, 1));
		track_phr_request_outer_panel.setLayout(new BoxLayout(track_phr_request_outer_panel, BoxLayout.Y_AXIS));
		track_phr_request_outer_panel.setPreferredSize(new Dimension(440, 95));
		track_phr_request_outer_panel.setMaximumSize(new Dimension(440, 95));
    		track_phr_request_outer_panel.setBorder(BorderFactory.createTitledBorder("Track requests for the restricted-level PHR"));
		track_phr_request_outer_panel.setAlignmentX(0.5f);
		track_phr_request_outer_panel.add(Box.createRigidArea(new Dimension(0, 15)));
		track_phr_request_outer_panel.add(track_phr_request_button_panel);

		emergency_phr_access_outer_panel.setLayout(new BoxLayout(emergency_phr_access_outer_panel, BoxLayout.Y_AXIS));
		emergency_phr_access_outer_panel.setBorder(new EmptyBorder(new Insets(10, 10, 10, 10)));
		emergency_phr_access_outer_panel.add(Box.createRigidArea(new Dimension(0, 50)));
		emergency_phr_access_outer_panel.add(search_phr_by_user_ui_outer_panel);
		emergency_phr_access_outer_panel.add(Box.createRigidArea(new Dimension(0, 30)));
		emergency_phr_access_outer_panel.add(track_phr_request_outer_panel);
		
		// Alert the message if there is no any PHR authority available
		if(phr_authority_info_list.size() == 0)
		{
			JPanel no_any_phr_authority_available_alert_msg_panel = new JPanel();
			no_any_phr_authority_available_alert_msg_panel.setPreferredSize(new Dimension(440, 30));
			no_any_phr_authority_available_alert_msg_panel.setMaximumSize(new Dimension(440, 30));
			no_any_phr_authority_available_alert_msg_panel.setAlignmentX(0.5f);
			no_any_phr_authority_available_alert_msg_panel.add(no_any_phr_authority_available_alert_msg_label);

			emergency_phr_access_outer_panel.add(Box.createRigidArea(new Dimension(0, 30)));
			emergency_phr_access_outer_panel.add(no_any_phr_authority_available_alert_msg_panel);

			// Run in an another thread
			alert_no_any_phr_authority_available_msg();
		}

		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
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

						if(validate_phr_owner_search_input()) 
						{
							int    index                           = phr_owner_authority_name_combobox.getSelectedIndex();
							String phr_owner_authority_name        = phr_authority_info_list.get(index).get_phr_authority_name();
							String target_emergency_server_ip_addr = phr_authority_info_list.get(index).get_emergency_server_ip_address();
							String phr_owner_name                  = phr_owner_name_textfield.getText();

							// Call to C function
							if(check_phr_owner_existence_main(target_emergency_server_ip_addr, phr_owner_authority_name, phr_owner_name))
							{
								init_ui_for_emergency_phr_downloading_mode();
								setup_actions_for_emergency_phr_downloading_mode();
		
								// Call to C function
								load_emergency_phr_list_main(target_emergency_server_ip_addr, phr_owner_authority_name, phr_owner_name);
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

		// Track PHR request button
		track_phr_request_button.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						track_phr_request_button.setEnabled(false);

						// We could not use tryLock() becuase the SwingUtilities is always the same thread even if
						// we call it manay times. Note that, the tryLock() could not detect the same thead
						if(!working_lock.isLocked())
						{
							working_lock.lock();
						}
						else
						{
							JOptionPane.showMessageDialog(main_panel, "Some task is working, please wait until the task is done");
							track_phr_request_button.setEnabled(true);
							return;
						}

						init_ui_for_requested_restricted_phr_tracking_mode();
						setup_actions_for_requested_restricted_phr_tracking_mode();

						no_any_requested_restricted_phr_flag = false;
						int list_size = phr_authority_info_list.size();
						for(int i=0; i < list_size; i++)
						{
							// Call to C function
							load_requested_restricted_phr_list_main(phr_authority_info_list.get(i).get_phr_authority_name(), 
								phr_authority_info_list.get(i).get_emergency_server_ip_address());
						}

						if(!no_any_requested_restricted_phr_flag)
						{
							JOptionPane.showMessageDialog(main_panel, "Do not have any requests for the restricted-level PHRs");
						}
							
						track_phr_request_button.setEnabled(true);
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

				// Invisible EmU_UserMain frame and destroy it
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

	private void init_phr_owner_authority_name_combobox()
	{
		int list_size = phr_authority_info_list.size();
		for(int i=0; i < list_size; i++)
			phr_owner_authority_name_combobox.addItem(phr_authority_info_list.get(i).get_phr_authority_name());

		phr_owner_authority_name_combobox.setSelectedIndex(-1);
	}

	private void alert_no_any_phr_authority_available_msg()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				phr_owner_name_textfield.setEnabled(false);
				search_phr_owner_button.setEnabled(false);
				track_phr_request_button.setEnabled(false);

				Thread thread = new Thread()
				{
					public void run()
					{
			
						boolean flag = false;
						while(true)
						{
							try{
								flag = !flag;
								no_any_phr_authority_available_alert_msg_label.setForeground((flag) ? Color.black : Color.gray);
								no_any_phr_authority_available_alert_msg_label.setOpaque(true);
								Thread.sleep(1000);
							}
							catch(InterruptedException ex){
								Thread.currentThread().interrupt();
							}
						}
					}
				};

				thread.start();
			}
		});
	}

	private boolean validate_phr_owner_search_input()
	{
		Pattern p;
		Matcher m;
		int     index;

		// Validate PHR owner authority name
		index = phr_owner_authority_name_combobox.getSelectedIndex();
		if(index == -1)
		{
			JOptionPane.showMessageDialog(this, "Please select the authority name");
			return false;
		}

		// Validate PHR owner name
		p = Pattern.compile("^[^-]*[a-zA-Z0-9_]+");

		m = p.matcher(phr_owner_name_textfield.getText());
		if(!m.matches())
		{
			JOptionPane.showMessageDialog(this, "Please input correct format for the PHR ownername");
			return false;
		}
 
		return true;
	}

	private final void init_ui_for_emergency_phr_downloading_mode()
	{		
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setPreferredSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setMaximumSize(new Dimension(60, 25));
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		JPanel phr_owner_info_inner_panel = new JPanel(new SpringLayout());
		phr_owner_info_inner_panel.setPreferredSize(new Dimension(400, 80));
		phr_owner_info_inner_panel.setMaximumSize(new Dimension(400, 80));

		phr_owner_info_inner_panel.add(phr_owner_authority_name_label);
		phr_owner_info_inner_panel.add(phr_owner_authority_name_combobox);

		phr_owner_info_inner_panel.add(phr_owner_name_label);
		phr_owner_info_inner_panel.add(phr_owner_name_textfield);

		SpringUtilities.makeCompactGrid(phr_owner_info_inner_panel, 2, 2, 5, 10, 10, 10);

		JPanel phr_owner_info_outer_panel = new JPanel();
		phr_owner_info_outer_panel.setLayout(new BoxLayout(phr_owner_info_outer_panel, BoxLayout.X_AXIS));
		phr_owner_info_outer_panel.setPreferredSize(new Dimension(555, 80));
		phr_owner_info_outer_panel.setMaximumSize(new Dimension(555, 80));
		phr_owner_info_outer_panel.setAlignmentX(0.0f);
		phr_owner_info_outer_panel.add(phr_owner_info_inner_panel);

		// Secure PHR downloading table
		JLabel secure_phr_downloading_label = new JLabel("Secure-Level PHR List");
		secure_phr_downloading_label.setPreferredSize(new Dimension(545, 10));
		secure_phr_downloading_label.setMaximumSize(new Dimension(545, 10));
		secure_phr_downloading_label.setAlignmentX(0.0f);

		secure_phr_downloading_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582465865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		secure_phr_downloading_table_model.setDataVector(null, new Object[] {"Data description", "Size", "PHR id"});
    		secure_phr_downloading_table = new JTable(secure_phr_downloading_table_model);
		secure_phr_downloading_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		secure_phr_downloading_table.removeColumn(secure_phr_downloading_table.getColumnModel().getColumn(2));

		JScrollPane secure_phr_downloading_table_inner_panel = new JScrollPane();
		secure_phr_downloading_table_inner_panel.setPreferredSize(new Dimension(545, 180));
		secure_phr_downloading_table_inner_panel.setMaximumSize(new Dimension(545, 180));
		secure_phr_downloading_table_inner_panel.setAlignmentX(0.0f);
		secure_phr_downloading_table_inner_panel.getViewport().add(secure_phr_downloading_table);

		JPanel secure_phr_downloading_table_outer_panel = new JPanel();
		secure_phr_downloading_table_outer_panel.setPreferredSize(new Dimension(555, 210));
		secure_phr_downloading_table_outer_panel.setMaximumSize(new Dimension(555, 210));
		secure_phr_downloading_table_outer_panel.setAlignmentX(0.0f);
		secure_phr_downloading_table_outer_panel.add(secure_phr_downloading_label);
		secure_phr_downloading_table_outer_panel.add(secure_phr_downloading_table_inner_panel);

		// Secure PHR download to path
		JLabel secure_phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		secure_phr_download_to_path_textfield    = new JTextField(TEXTFIELD_LENGTH);
		browse_secure_phr_download_to_path_button.setPreferredSize(new Dimension(90, 20));
		browse_secure_phr_download_to_path_button.setMaximumSize(new Dimension(90, 20));

		JPanel secure_phr_download_to_path_panel = new JPanel(new SpringLayout());
		secure_phr_download_to_path_panel.setPreferredSize(new Dimension(450, 35));
		secure_phr_download_to_path_panel.setMaximumSize(new Dimension(450, 35));

		secure_phr_download_to_path_panel.add(secure_phr_download_to_path_label);
		secure_phr_download_to_path_panel.add(secure_phr_download_to_path_textfield);
		secure_phr_download_to_path_panel.add(browse_secure_phr_download_to_path_button);

		SpringUtilities.makeCompactGrid(secure_phr_download_to_path_panel, 1, 3, 5, 0, 10, 10);

		// Secure PHR download and quit buttons
		download_secure_phr_button.setAlignmentX(0.5f);	
		quit_secure_phr_downloading_button.setAlignmentX(0.5f);
		download_secure_phr_button.setEnabled(false);

		JPanel secure_phr_main_buttons_panel = new JPanel();
		secure_phr_main_buttons_panel.setPreferredSize(new Dimension(555, 30));
		secure_phr_main_buttons_panel.setMaximumSize(new Dimension(555, 30));
		secure_phr_main_buttons_panel.setAlignmentX(0.0f);
		secure_phr_main_buttons_panel.add(download_secure_phr_button);
		secure_phr_main_buttons_panel.add(quit_secure_phr_downloading_button);

		// Restricted PHR downloading table
		JLabel restricted_phr_downloading_label = new JLabel("Restricted-Level PHR List");
		restricted_phr_downloading_label.setPreferredSize(new Dimension(545, 10));
		restricted_phr_downloading_label.setMaximumSize(new Dimension(545, 10));
		restricted_phr_downloading_label.setAlignmentX(0.0f);

		restricted_phr_downloading_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582565865921793L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		restricted_phr_downloading_table_model.setDataVector(null, new Object[] {"Data description", 
			"Size", "Approvals/Threshold value", "Request status", "PHR id"});

    		restricted_phr_downloading_table = new JTable(restricted_phr_downloading_table_model);
		restricted_phr_downloading_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		restricted_phr_downloading_table.removeColumn(restricted_phr_downloading_table.getColumnModel().getColumn(4));

		JScrollPane restricted_phr_downloading_table_inner_panel = new JScrollPane();
		restricted_phr_downloading_table_inner_panel.setPreferredSize(new Dimension(545, 180));
		restricted_phr_downloading_table_inner_panel.setMaximumSize(new Dimension(545, 180));
		restricted_phr_downloading_table_inner_panel.setAlignmentX(0.0f);
		restricted_phr_downloading_table_inner_panel.getViewport().add(restricted_phr_downloading_table);

		JPanel restricted_phr_downloading_table_outer_panel = new JPanel();
		restricted_phr_downloading_table_outer_panel.setPreferredSize(new Dimension(555, 210));
		restricted_phr_downloading_table_outer_panel.setMaximumSize(new Dimension(555, 210));
		restricted_phr_downloading_table_outer_panel.setAlignmentX(0.0f);
		restricted_phr_downloading_table_outer_panel.add(restricted_phr_downloading_label);
		restricted_phr_downloading_table_outer_panel.add(restricted_phr_downloading_table_inner_panel);

		// Restricted PHR download to path
		JLabel restricted_phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		restricted_phr_download_to_path_textfield    = new JTextField(TEXTFIELD_LENGTH);
		browse_restricted_phr_download_to_path_button.setPreferredSize(new Dimension(90, 20));
		browse_restricted_phr_download_to_path_button.setMaximumSize(new Dimension(90, 20));

		JPanel restricted_phr_download_to_path_panel = new JPanel(new SpringLayout());
		restricted_phr_download_to_path_panel.setPreferredSize(new Dimension(450, 35));
		restricted_phr_download_to_path_panel.setMaximumSize(new Dimension(450, 35));

		restricted_phr_download_to_path_panel.add(restricted_phr_download_to_path_label);
		restricted_phr_download_to_path_panel.add(restricted_phr_download_to_path_textfield);
		restricted_phr_download_to_path_panel.add(browse_restricted_phr_download_to_path_button);

		SpringUtilities.makeCompactGrid(restricted_phr_download_to_path_panel, 1, 3, 5, 0, 10, 10);

		// Restricted PHR request and cancel buttons
		request_restricted_phr_button.setAlignmentX(0.5f);
		cancel_request_restricted_phr_button.setAlignmentX(0.5f);
		request_restricted_phr_button.setEnabled(false);
		cancel_request_restricted_phr_button.setEnabled(false);

		// Restricted PHR download and quit buttons
		download_restricted_phr_button.setAlignmentX(0.5f);	
		quit_restricted_phr_downloading_button.setAlignmentX(0.5f);
		download_restricted_phr_button.setEnabled(false);

		JPanel restricted_phr_request_main_buttons_panel = new JPanel();
		restricted_phr_request_main_buttons_panel.setPreferredSize(new Dimension(555, 30));
		restricted_phr_request_main_buttons_panel.setMaximumSize(new Dimension(555, 30));
		restricted_phr_request_main_buttons_panel.setAlignmentX(0.0f);
		restricted_phr_request_main_buttons_panel.add(request_restricted_phr_button);
		restricted_phr_request_main_buttons_panel.add(cancel_request_restricted_phr_button);

		JPanel restricted_phr_download_main_buttons_panel = new JPanel();
		restricted_phr_download_main_buttons_panel.setPreferredSize(new Dimension(555, 30));
		restricted_phr_download_main_buttons_panel.setMaximumSize(new Dimension(555, 30));
		restricted_phr_download_main_buttons_panel.setAlignmentX(0.0f);
		restricted_phr_download_main_buttons_panel.add(download_restricted_phr_button);
		restricted_phr_download_main_buttons_panel.add(quit_restricted_phr_downloading_button);

		JPanel h_separator_panel = new JPanel();
		h_separator_panel.setLayout(new BoxLayout(h_separator_panel, BoxLayout.Y_AXIS));
		h_separator_panel.setPreferredSize(new Dimension(555, 5));
		h_separator_panel.setMaximumSize(new Dimension(555, 5));
		h_separator_panel.setAlignmentX(0.0f);
		h_separator_panel.add((new JSeparator(SwingConstants.HORIZONTAL)));

		JPanel emergency_phr_access_inner_panel = new JPanel();
		emergency_phr_access_inner_panel.setPreferredSize(new Dimension(555, 800));
		emergency_phr_access_inner_panel.setMaximumSize(new Dimension(555, 800));
		emergency_phr_access_inner_panel.setAlignmentX(0.0f);
		emergency_phr_access_inner_panel.add(phr_owner_info_outer_panel);
		emergency_phr_access_inner_panel.add(secure_phr_downloading_table_outer_panel);
		emergency_phr_access_inner_panel.add(secure_phr_download_to_path_panel);
		emergency_phr_access_inner_panel.add(secure_phr_main_buttons_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(555, 15)));
		emergency_phr_access_inner_panel.add(h_separator_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(555, 10)));
		emergency_phr_access_inner_panel.add(restricted_phr_downloading_table_outer_panel);
		emergency_phr_access_inner_panel.add(restricted_phr_request_main_buttons_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(555, 20)));
		emergency_phr_access_inner_panel.add(restricted_phr_download_to_path_panel);
		emergency_phr_access_inner_panel.add(restricted_phr_download_main_buttons_panel);

		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.add(emergency_phr_access_inner_panel);
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private final void uninit_ui_for_emergency_phr_downloading_mode()
	{
		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private void init_actions_for_emergency_phr_downloading_mode()
	{
		// Secure PHR downloading table
		secure_phr_downloading_table_mouseadapter = new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							download_secure_phr_button.setEnabled(true);
						}
					});
				}
			}
		};

		// Browse secure PHR download to path button
		browse_secure_phr_download_to_path_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						browse_secure_phr_download_to_path_button.setEnabled(false);

						JFileChooser secure_phr_download_to_path_filechooser = new JFileChooser();
						secure_phr_download_to_path_filechooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

						int ret = secure_phr_download_to_path_filechooser.showDialog(main_panel, "Choose a download path");
						if(ret == JFileChooser.APPROVE_OPTION)
						{
							String secure_phr_download_to_path = secure_phr_download_to_path_filechooser.getSelectedFile().getAbsolutePath();
							secure_phr_download_to_path_textfield.setText(secure_phr_download_to_path);
						}

						browse_secure_phr_download_to_path_button.setEnabled(true);
		    			}
				});
			}
		};

		// Download secure PHR button
		download_secure_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						download_secure_phr_button.setEnabled(false);

						if(validate_secure_phr_downloading_input())
						{
							int    index                           = phr_owner_authority_name_combobox.getSelectedIndex();
							String phr_owner_authority_name        = phr_authority_info_list.get(index).get_phr_authority_name();
							String target_emergency_server_ip_addr = phr_authority_info_list.get(index).get_emergency_server_ip_address();
							String phr_owner_name                  = phr_owner_name_textfield.getText();

							int    row              = secure_phr_downloading_table.getSelectedRow();
							String data_description = secure_phr_downloading_table.getModel().getValueAt(row, 0).toString();
							int    phr_id           = Integer.parseInt(secure_phr_downloading_table.getModel().getValueAt(row, 2).toString());

							String secure_phr_download_to_path = secure_phr_download_to_path_textfield.getText();

							uninit_ui_for_emergency_phr_downloading_mode();
							release_actions_for_emergency_phr_downloading_mode();
							init_ui_for_secure_phr_downloading_transaction_mode();
							setup_actions_for_secure_phr_downloading_transaction_mode();

							// Run background tasks
							run_secure_phr_downloading_background_task(target_emergency_server_ip_addr, phr_owner_name, phr_owner_authority_name, 
								data_description, phr_id, secure_phr_download_to_path);
						}

						download_secure_phr_button.setEnabled(true);
		    			}
				});
			}
		};

		// Quit secure PHR downloading button
		quit_secure_phr_downloading_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						quit_secure_phr_downloading_button.setEnabled(false);

						uninit_ui_for_emergency_phr_downloading_mode();
						release_actions_for_emergency_phr_downloading_mode();
						create_emergency_phr_access_page();

						working_lock.unlock();

						quit_secure_phr_downloading_button.setEnabled(true);
		    			}
				});
			}
		};

		// Restricted PHR downloading table
		restricted_phr_downloading_table_mouseadapter = new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							int    row            = restricted_phr_downloading_table.getSelectedRow();
							String request_status = restricted_phr_downloading_table.getModel().getValueAt(row, 3).toString();

							if(request_status.equals(RESTRICTED_PHR_NO_REQUEST))
							{
								request_restricted_phr_button.setEnabled(true);
								cancel_request_restricted_phr_button.setEnabled(false);
								download_restricted_phr_button.setEnabled(false);
							}
							else if(request_status.equals(RESTRICTED_PHR_REQUEST_PENDING))
							{
								request_restricted_phr_button.setEnabled(false);
								cancel_request_restricted_phr_button.setEnabled(true);
								download_restricted_phr_button.setEnabled(false);
							}
							else if(request_status.equals(RESTRICTED_PHR_REQUEST_APPROVED))
							{
								request_restricted_phr_button.setEnabled(false);
								cancel_request_restricted_phr_button.setEnabled(true);
								download_restricted_phr_button.setEnabled(true);
							}
						}
					});
				}
			}
		};

		// Request restricted PHR button
		request_restricted_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						request_restricted_phr_button.setEnabled(false);

						int    index                           = phr_owner_authority_name_combobox.getSelectedIndex();
						String phr_owner_authority_name        = phr_authority_info_list.get(index).get_phr_authority_name();
						String target_emergency_server_ip_addr = phr_authority_info_list.get(index).get_emergency_server_ip_address();
						String phr_owner_name                  = phr_owner_name_textfield.getText();
						String emergency_staff_email_address   = email_address_textfield.getText();

						int    row             = restricted_phr_downloading_table.getSelectedRow();
						String phr_description = restricted_phr_downloading_table.getModel().getValueAt(row, 0).toString();
						int    phr_id          = Integer.parseInt(restricted_phr_downloading_table.getModel().getValueAt(row, 4).toString());

						// Call to C function
						if(request_restricted_level_phr_accessing_main(target_emergency_server_ip_addr, 
							phr_owner_authority_name, phr_owner_name, phr_id, phr_description, emergency_staff_email_address))
						{
							// Call to C function
							update_restricted_phr_list_main(target_emergency_server_ip_addr, phr_owner_authority_name, phr_owner_name);

							JOptionPane.showMessageDialog(main_panel, "Requesting on the " + 
								"restricted-level PHR succeeded.\nPlease wait for the approvals.");

							request_restricted_phr_button.setEnabled(false);
						}
						else
						{
							request_restricted_phr_button.setEnabled(true);
						}
		    			}
				});
			}
		};

		// Cancel request restricted PHR button
		cancel_request_restricted_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						cancel_request_restricted_phr_button.setEnabled(false);

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to cancel this request?", "Cancel Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							cancel_request_restricted_phr_button.setEnabled(true);
							return;
						}

						int    index                           = phr_owner_authority_name_combobox.getSelectedIndex();
						String phr_owner_authority_name        = phr_authority_info_list.get(index).get_phr_authority_name();
						String target_emergency_server_ip_addr = phr_authority_info_list.get(index).get_emergency_server_ip_address();
						String phr_owner_name                  = phr_owner_name_textfield.getText();

						int    row             = restricted_phr_downloading_table.getSelectedRow();
						String phr_description = restricted_phr_downloading_table.getModel().getValueAt(row, 0).toString();
						int    phr_id          = Integer.parseInt(restricted_phr_downloading_table.getModel().getValueAt(row, 4).toString());

						// Call to C function
						if(cancel_restricted_level_phr_access_request_main(target_emergency_server_ip_addr, 
							phr_owner_authority_name, phr_owner_name, phr_id, phr_description))
						{
							// Call to C function
							update_restricted_phr_list_main(target_emergency_server_ip_addr, phr_owner_authority_name, phr_owner_name);
							cancel_request_restricted_phr_button.setEnabled(false);
						}
						else
						{
							cancel_request_restricted_phr_button.setEnabled(true);
						}
		    			}
				});
			}
		};

		// Browse restricted PHR download to path button
		browse_restricted_phr_download_to_path_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						browse_restricted_phr_download_to_path_button.setEnabled(false);

						JFileChooser restricted_phr_download_to_path_filechooser = new JFileChooser();
						restricted_phr_download_to_path_filechooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

						int ret = restricted_phr_download_to_path_filechooser.showDialog(main_panel, "Choose a download path");
						if(ret == JFileChooser.APPROVE_OPTION)
						{
							String restricted_phr_download_to_path = restricted_phr_download_to_path_filechooser.
								getSelectedFile().getAbsolutePath();

							restricted_phr_download_to_path_textfield.setText(restricted_phr_download_to_path);
						}

						browse_restricted_phr_download_to_path_button.setEnabled(true);
		    			}
				});
			}
		};

		// Download restricted PHR button
		download_restricted_phr_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						download_restricted_phr_button.setEnabled(false);

						if(validate_restricted_phr_downloading_input())
						{
							int    index                           = phr_owner_authority_name_combobox.getSelectedIndex();
							String phr_owner_authority_name        = phr_authority_info_list.get(index).get_phr_authority_name();
							String target_emergency_server_ip_addr = phr_authority_info_list.get(index).get_emergency_server_ip_address();
							String phr_owner_name                  = phr_owner_name_textfield.getText();

							int    row              = restricted_phr_downloading_table.getSelectedRow();
							String data_description = restricted_phr_downloading_table.getModel().getValueAt(row, 0).toString();
							int    phr_id           = Integer.parseInt(restricted_phr_downloading_table.getModel().getValueAt(row, 4).toString());

							String restricted_phr_download_to_path = restricted_phr_download_to_path_textfield.getText();

							uninit_ui_for_emergency_phr_downloading_mode();
							release_actions_for_emergency_phr_downloading_mode();
							init_ui_for_restricted_phr_downloading_transaction_mode();
							setup_actions_for_restricted_phr_downloading_transaction_mode();

							// Run background tasks
							run_restricted_phr_downloading_background_task(target_emergency_server_ip_addr, phr_owner_name, 
								phr_owner_authority_name, data_description, phr_id, restricted_phr_download_to_path);
						}

						download_restricted_phr_button.setEnabled(true);
		    			}
				});
			}
		};

		// Quit restricted PHR downloading button
		quit_restricted_phr_downloading_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						quit_restricted_phr_downloading_button.setEnabled(false);

						uninit_ui_for_emergency_phr_downloading_mode();
						release_actions_for_emergency_phr_downloading_mode();
						create_emergency_phr_access_page();

						working_lock.unlock();

						quit_restricted_phr_downloading_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_emergency_phr_downloading_mode()
	{
		// Secure PHR downloading table
		secure_phr_downloading_table.addMouseListener(secure_phr_downloading_table_mouseadapter);

		// Browse secure PHR download to path button
		browse_secure_phr_download_to_path_button.addActionListener(browse_secure_phr_download_to_path_button_actionlistener);

		// Download secure PHR button
		download_secure_phr_button.addActionListener(download_secure_phr_button_actionlistener);

		// Quit secure PHR downloading button
		quit_secure_phr_downloading_button.addActionListener(quit_secure_phr_downloading_button_actionlistener);

		// Restricted PHR downloading table
		restricted_phr_downloading_table.addMouseListener(restricted_phr_downloading_table_mouseadapter);

		// Browse restricted PHR download to path button
		browse_restricted_phr_download_to_path_button.addActionListener(browse_restricted_phr_download_to_path_button_actionlistener);

		// Request restricted PHR button
		request_restricted_phr_button.addActionListener(request_restricted_phr_button_actionlistener);

		// Cancel request restricted PHR button
		cancel_request_restricted_phr_button.addActionListener(cancel_request_restricted_phr_button_actionlistener);

		// Download restricted PHR button
		download_restricted_phr_button.addActionListener(download_restricted_phr_button_actionlistener);

		// Quit restricted PHR downloading button
		quit_restricted_phr_downloading_button.addActionListener(quit_restricted_phr_downloading_button_actionlistener);
	}

	private void release_actions_for_emergency_phr_downloading_mode()
	{
		// Secure PHR downloading table
		secure_phr_downloading_table.removeMouseListener(secure_phr_downloading_table_mouseadapter);

		// Browse secure PHR download to path button
		browse_secure_phr_download_to_path_button.removeActionListener(browse_secure_phr_download_to_path_button_actionlistener);

		// Download secure PHR button
		download_secure_phr_button.removeActionListener(download_secure_phr_button_actionlistener);

		// Quit secure PHR downloading button
		quit_secure_phr_downloading_button.removeActionListener(quit_secure_phr_downloading_button_actionlistener);	

		// Restricted PHR downloading table
		restricted_phr_downloading_table.removeMouseListener(restricted_phr_downloading_table_mouseadapter);

		// Browse restricted PHR download to path button
		browse_restricted_phr_download_to_path_button.removeActionListener(browse_restricted_phr_download_to_path_button_actionlistener);

		// Request restricted PHR button
		request_restricted_phr_button.removeActionListener(request_restricted_phr_button_actionlistener);

		// Cancel request restricted PHR button
		cancel_request_restricted_phr_button.removeActionListener(cancel_request_restricted_phr_button_actionlistener);

		// Download restricted PHR button
		download_restricted_phr_button.removeActionListener(download_restricted_phr_button_actionlistener);

		// Quit restricted PHR downloading button
		quit_restricted_phr_downloading_button.removeActionListener(quit_restricted_phr_downloading_button_actionlistener);	
	}

	private boolean validate_secure_phr_downloading_input()
	{
		String  secure_phr_download_to_path;
		File    secure_phr_dir_object;

		// Validate the secure PHR item selection
		if(secure_phr_downloading_table.getSelectedRow() < 0)
		{
			JOptionPane.showMessageDialog(this, "Please select the secure-level PHR that you need to download");
			return false;
		}

		// Validate a secure PHR download to path
		secure_phr_download_to_path = secure_phr_download_to_path_textfield.getText();
		if(secure_phr_download_to_path.equals(""))
		{
			JOptionPane.showMessageDialog(this, "Please specify a secure-level PHR download directory path");
			return false;
		}

		secure_phr_dir_object = new File(secure_phr_download_to_path);
	  	if(!secure_phr_dir_object.exists())
		{
			JOptionPane.showMessageDialog(this, "The secure-level PHR download directory does not exist");
			return false;
		}

		return true;
	}

	private final void init_ui_for_secure_phr_downloading_transaction_mode()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		// Secure PHR download to path
		JLabel secure_phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		secure_phr_download_to_path_textfield.setEnabled(false);

		// PHR info panel
		JPanel phr_info_inner_panel = new JPanel(new SpringLayout());
		phr_info_inner_panel.setPreferredSize(new Dimension(400, 120));
		phr_info_inner_panel.setMaximumSize(new Dimension(400, 120));

		phr_info_inner_panel.add(phr_owner_authority_name_label);
		phr_info_inner_panel.add(phr_owner_authority_name_combobox);

		phr_info_inner_panel.add(phr_owner_name_label);
		phr_info_inner_panel.add(phr_owner_name_textfield);

		phr_info_inner_panel.add(secure_phr_download_to_path_label);
		phr_info_inner_panel.add(secure_phr_download_to_path_textfield);

		SpringUtilities.makeCompactGrid(phr_info_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel phr_info_outer_panel = new JPanel(new GridLayout(0, 1));
		phr_info_outer_panel.setLayout(new BoxLayout(phr_info_outer_panel, BoxLayout.Y_AXIS));
		phr_info_outer_panel.setPreferredSize(new Dimension(450, 155));
		phr_info_outer_panel.setMaximumSize(new Dimension(450, 155));
    		phr_info_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR Info"));
		phr_info_outer_panel.setAlignmentX(0.5f);
		phr_info_outer_panel.add(phr_info_inner_panel);

		// Emergency PHR EmS side progressbar
		JLabel emergency_phr_ems_side_processing_label = new JLabel("Processing at an emergency server");
		emergency_phr_ems_side_processing_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_ems_side_processing_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_ems_side_processing_label.setAlignmentX(0.0f);

		emergency_phr_ems_side_processing_progressbar = new JProgressBar(0, 100);
		emergency_phr_ems_side_processing_progressbar.setValue(0);
		emergency_phr_ems_side_processing_progressbar.setIndeterminate(false);
		emergency_phr_ems_side_processing_progressbar.setStringPainted(true);
		emergency_phr_ems_side_processing_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_ems_side_processing_progressbar_panel = new JPanel();
		emergency_phr_ems_side_processing_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_ems_side_processing_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_ems_side_processing_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_ems_side_processing_progressbar_panel.add(emergency_phr_ems_side_processing_label);
		emergency_phr_ems_side_processing_progressbar_panel.add(emergency_phr_ems_side_processing_progressbar);

		// Emergency PHR downloading progressbar
		JLabel emergency_phr_downloading_label = new JLabel("Downloading the secure-level PHR");
		emergency_phr_downloading_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_downloading_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_downloading_label.setAlignmentX(0.0f);

		emergency_phr_downloading_progressbar = new JProgressBar(0, 100);
		emergency_phr_downloading_progressbar.setValue(0);
		emergency_phr_downloading_progressbar.setIndeterminate(false);
		emergency_phr_downloading_progressbar.setStringPainted(true);
		emergency_phr_downloading_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_downloading_progressbar_panel = new JPanel();
		emergency_phr_downloading_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_downloading_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_downloading_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_downloading_progressbar_panel.add(emergency_phr_downloading_label);
		emergency_phr_downloading_progressbar_panel.add(emergency_phr_downloading_progressbar);

		// Emergency PHR extracting progressbar
		JLabel emergency_phr_extracting_label = new JLabel("Extracting the secure-level PHR");
		emergency_phr_extracting_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_extracting_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_extracting_label.setAlignmentX(0.0f);

		emergency_phr_extracting_progressbar = new JProgressBar(0, 100);
		emergency_phr_extracting_progressbar.setValue(0);
		emergency_phr_extracting_progressbar.setIndeterminate(false);
		emergency_phr_extracting_progressbar.setStringPainted(true);
		emergency_phr_extracting_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_extracting_progressbar_panel = new JPanel();
		emergency_phr_extracting_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_extracting_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_extracting_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_extracting_progressbar_panel.add(emergency_phr_extracting_label);
		emergency_phr_extracting_progressbar_panel.add(emergency_phr_extracting_progressbar);

		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.setAlignmentX(0.5f);	

		JPanel cancel_button_panel = new JPanel();
		cancel_button_panel.setPreferredSize(new Dimension(535, 30));
		cancel_button_panel.setMaximumSize(new Dimension(535, 30));
		cancel_button_panel.setAlignmentX(0.0f);
		cancel_button_panel.add(cancel_emergency_phr_downloading_transaction_button);

		JPanel emergency_phr_access_inner_panel = new JPanel();
		emergency_phr_access_inner_panel.setPreferredSize(new Dimension(555, 405));
		emergency_phr_access_inner_panel.setMaximumSize(new Dimension(555, 405));
		emergency_phr_access_inner_panel.setAlignmentX(0.5f);
		emergency_phr_access_inner_panel.add(phr_info_outer_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(emergency_phr_ems_side_processing_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(emergency_phr_downloading_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));		
		emergency_phr_access_inner_panel.add(emergency_phr_extracting_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(cancel_button_panel);

		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.add(emergency_phr_access_inner_panel);
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private final void uninit_ui_for_secure_phr_downloading_transaction_mode()
	{
		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private void init_actions_for_emergency_phr_downloading_transaction_mode()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						cancel_emergency_phr_downloading_transaction_button.setEnabled(false);

						set_cancel_emergency_phr_downloading(true);
						if(get_emergency_phr_downloading_state())
						{
							// Call to C function
							cancel_emergency_phr_downloading_main();
						}
						else if(get_emergency_phr_extracting_state())
						{
							// Call to C function
							cancel_emergency_phr_extracting_main();
						}

						cancel_emergency_phr_downloading_transaction_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_secure_phr_downloading_transaction_mode()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.addActionListener(cancel_emergency_phr_downloading_transaction_button_actionlistener);	
	}

	private void release_actions_for_secure_phr_downloading_transaction_mode()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.removeActionListener(cancel_emergency_phr_downloading_transaction_button_actionlistener);		
	}

	private void set_emergency_phr_downloading_state(boolean flag)
	{
		emergency_phr_downloading_state_flag = flag;
	}

	private boolean get_emergency_phr_downloading_state()
	{
		return emergency_phr_downloading_state_flag;
	}

	private void set_emergency_phr_extracting_state(boolean flag)
	{
		emergency_phr_extracting_state_flag = flag;
	}

	private boolean get_emergency_phr_extracting_state()
	{
		return emergency_phr_extracting_state_flag;
	}

	private void set_cancel_emergency_phr_downloading(boolean flag)
	{
		cancel_emergency_phr_downloading_flag = flag;
	}

	private boolean get_cancel_emergency_phr_downloading()
	{
		return cancel_emergency_phr_downloading_flag;
	}

	private void set_emergency_phr_ems_side_processing_success_state(boolean flag)
	{
		emergency_phr_ems_side_processing_success_flag = flag;
	}

	private boolean get_emergency_phr_ems_side_processing_success_state()
	{
		return emergency_phr_ems_side_processing_success_flag;
	}

	private void set_indeterminate_mode_emergency_phr_ems_side_processing_progressbar()
	{
		// Set progressbar from default mode to indeterminate mode
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				emergency_phr_ems_side_processing_progressbar.setIndeterminate(true);
				emergency_phr_ems_side_processing_progressbar.setStringPainted(false);
			}
		});
	}

	private void set_emergency_phr_ems_side_processing_progressbar_value(final int percent)
	{
		// Set progressbar from indeterminate mode to default mode and set its value to "percent"
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				emergency_phr_ems_side_processing_progressbar.setValue(percent);
				emergency_phr_ems_side_processing_progressbar.setStringPainted(true);
				emergency_phr_ems_side_processing_progressbar.setIndeterminate(false);
			}
		});
	}

	private void set_indeterminate_mode_emergency_phr_extracting_progressbar()
	{
		// Set progressbar from default mode to indeterminate mode
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				emergency_phr_extracting_progressbar.setIndeterminate(true);
				emergency_phr_extracting_progressbar.setStringPainted(false);
			}
		});
	}

	private void set_emergency_phr_extracting_progressbar_value(final int percent)
	{
		// Set progressbar from indeterminate mode to default mode and set its value to "percent"
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				emergency_phr_extracting_progressbar.setValue(percent);
				emergency_phr_extracting_progressbar.setStringPainted(true);
				emergency_phr_extracting_progressbar.setIndeterminate(false);
			}
		});
	}

	// Run background tasks on another thread
	private void run_secure_phr_downloading_background_task(final String target_emergency_server_ip_addr, final String phr_owner_name, 
		final String phr_owner_authority_name, final String data_description, final int phr_id, final String secure_phr_download_to_path)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				perform_secure_phr_downloading_transaction(target_emergency_server_ip_addr, phr_owner_name, phr_owner_authority_name, 
					data_description, phr_id, secure_phr_download_to_path);

				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						uninit_ui_for_secure_phr_downloading_transaction_mode();
						release_actions_for_secure_phr_downloading_transaction_mode();
						create_emergency_phr_access_page();

						working_lock.unlock();
					}
				});
			}
		};

		thread.start();
	}

	private void perform_secure_phr_downloading_transaction(String target_emergency_server_ip_addr, String phr_owner_name, String phr_owner_authority_name, 
		String data_description, int phr_id, String phr_download_to_path)
	{
		set_emergency_phr_ems_side_processing_success_state(false);
		set_cancel_emergency_phr_downloading(false);
		set_emergency_phr_extracting_state(false);

		set_indeterminate_mode_emergency_phr_ems_side_processing_progressbar();
		set_emergency_phr_downloading_state(true);

		// Call to C function
		if(!download_emergency_phr_main(target_emergency_server_ip_addr, phr_owner_name, phr_owner_authority_name, phr_id, data_description, false))
		{
			set_emergency_phr_downloading_state(false);

			if(!get_emergency_phr_ems_side_processing_success_state())     // Waiting processing at an emergency server
			{
				set_emergency_phr_ems_side_processing_progressbar_value(0);
			}

			if(get_cancel_emergency_phr_downloading())
			{
				set_cancel_emergency_phr_downloading(false);
				JOptionPane.showMessageDialog(main_panel, "Downloading the secure-level PHR was aborted by a user");
			}

			return;
		}

		set_emergency_phr_downloading_state(false);

		set_indeterminate_mode_emergency_phr_extracting_progressbar();
		set_emergency_phr_extracting_state(true);

		// Call to C function
		if(!extract_emergency_phr_main(phr_download_to_path))
		{
			set_emergency_phr_extracting_state(false);
			set_emergency_phr_extracting_progressbar_value(0);

			if(get_cancel_emergency_phr_downloading())
			{
				set_cancel_emergency_phr_downloading(false);
				JOptionPane.showMessageDialog(main_panel, "Extracting the secure-level PHR was aborted by a user");
			}

			return;
		}

		set_emergency_phr_extracting_state(false);
		set_emergency_phr_extracting_progressbar_value(100);
		JOptionPane.showMessageDialog(main_panel, "Downloading the secure-level PHR succeeded");
	}

	private boolean validate_restricted_phr_downloading_input()
	{
		String  restricted_phr_download_to_path;
		File    restricted_phr_dir_object;

		// Validate the restricted PHR item selection
		if(restricted_phr_downloading_table.getSelectedRow() < 0)
		{
			JOptionPane.showMessageDialog(this, "Please select the restricted-level PHR that you need to download");
			return false;
		}

		// Validate a restricted PHR download to path
		restricted_phr_download_to_path = restricted_phr_download_to_path_textfield.getText();
		if(restricted_phr_download_to_path.equals(""))
		{
			JOptionPane.showMessageDialog(this, "Please specify a restricted-level PHR download directory path");
			return false;
		}

		restricted_phr_dir_object = new File(restricted_phr_download_to_path);
	  	if(!restricted_phr_dir_object.exists())
		{
			JOptionPane.showMessageDialog(this, "The restricted-level PHR download directory does not exist");
			return false;
		}

		return true;
	}

	private final void init_ui_for_restricted_phr_downloading_transaction_mode()
	{
		// PHR owner authority name
		JLabel phr_owner_authority_name_label = new JLabel("Authority name: ", JLabel.RIGHT);
		phr_owner_authority_name_combobox.setEnabled(false);

		// PHR owner name
		JLabel phr_owner_name_label = new JLabel("PHR ownername: ", JLabel.RIGHT);
		phr_owner_name_textfield.setEnabled(false);

		// Restricted PHR download to path
		JLabel restricted_phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		restricted_phr_download_to_path_textfield.setEnabled(false);

		// PHR info panel
		JPanel phr_info_inner_panel = new JPanel(new SpringLayout());
		phr_info_inner_panel.setPreferredSize(new Dimension(400, 120));
		phr_info_inner_panel.setMaximumSize(new Dimension(400, 120));

		phr_info_inner_panel.add(phr_owner_authority_name_label);
		phr_info_inner_panel.add(phr_owner_authority_name_combobox);

		phr_info_inner_panel.add(phr_owner_name_label);
		phr_info_inner_panel.add(phr_owner_name_textfield);

		phr_info_inner_panel.add(restricted_phr_download_to_path_label);
		phr_info_inner_panel.add(restricted_phr_download_to_path_textfield);

		SpringUtilities.makeCompactGrid(phr_info_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel phr_info_outer_panel = new JPanel(new GridLayout(0, 1));
		phr_info_outer_panel.setLayout(new BoxLayout(phr_info_outer_panel, BoxLayout.Y_AXIS));
		phr_info_outer_panel.setPreferredSize(new Dimension(450, 155));
		phr_info_outer_panel.setMaximumSize(new Dimension(450, 155));
    		phr_info_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR Info"));
		phr_info_outer_panel.setAlignmentX(0.5f);
		phr_info_outer_panel.add(phr_info_inner_panel);

		// Emergency PHR EmS side progressbar
		JLabel emergency_phr_ems_side_processing_label = new JLabel("Processing at an emergency server");
		emergency_phr_ems_side_processing_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_ems_side_processing_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_ems_side_processing_label.setAlignmentX(0.0f);

		emergency_phr_ems_side_processing_progressbar = new JProgressBar(0, 100);
		emergency_phr_ems_side_processing_progressbar.setValue(0);
		emergency_phr_ems_side_processing_progressbar.setIndeterminate(false);
		emergency_phr_ems_side_processing_progressbar.setStringPainted(true);
		emergency_phr_ems_side_processing_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_ems_side_processing_progressbar_panel = new JPanel();
		emergency_phr_ems_side_processing_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_ems_side_processing_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_ems_side_processing_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_ems_side_processing_progressbar_panel.add(emergency_phr_ems_side_processing_label);
		emergency_phr_ems_side_processing_progressbar_panel.add(emergency_phr_ems_side_processing_progressbar);

		// Emergency PHR downloading progressbar
		JLabel emergency_phr_downloading_label = new JLabel("Downloading the restricted-level PHR");
		emergency_phr_downloading_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_downloading_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_downloading_label.setAlignmentX(0.0f);

		emergency_phr_downloading_progressbar = new JProgressBar(0, 100);
		emergency_phr_downloading_progressbar.setValue(0);
		emergency_phr_downloading_progressbar.setIndeterminate(false);
		emergency_phr_downloading_progressbar.setStringPainted(true);
		emergency_phr_downloading_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_downloading_progressbar_panel = new JPanel();
		emergency_phr_downloading_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_downloading_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_downloading_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_downloading_progressbar_panel.add(emergency_phr_downloading_label);
		emergency_phr_downloading_progressbar_panel.add(emergency_phr_downloading_progressbar);

		// Emergency PHR extracting progressbar
		JLabel emergency_phr_extracting_label = new JLabel("Extracting the restricted-level PHR");
		emergency_phr_extracting_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_extracting_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_extracting_label.setAlignmentX(0.0f);

		emergency_phr_extracting_progressbar = new JProgressBar(0, 100);
		emergency_phr_extracting_progressbar.setValue(0);
		emergency_phr_extracting_progressbar.setIndeterminate(false);
		emergency_phr_extracting_progressbar.setStringPainted(true);
		emergency_phr_extracting_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_extracting_progressbar_panel = new JPanel();
		emergency_phr_extracting_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_extracting_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_extracting_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_extracting_progressbar_panel.add(emergency_phr_extracting_label);
		emergency_phr_extracting_progressbar_panel.add(emergency_phr_extracting_progressbar);

		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.setAlignmentX(0.5f);	

		JPanel cancel_button_panel = new JPanel();
		cancel_button_panel.setPreferredSize(new Dimension(535, 30));
		cancel_button_panel.setMaximumSize(new Dimension(535, 30));
		cancel_button_panel.setAlignmentX(0.0f);
		cancel_button_panel.add(cancel_emergency_phr_downloading_transaction_button);

		JPanel emergency_phr_access_inner_panel = new JPanel();
		emergency_phr_access_inner_panel.setPreferredSize(new Dimension(555, 405));
		emergency_phr_access_inner_panel.setMaximumSize(new Dimension(555, 405));
		emergency_phr_access_inner_panel.setAlignmentX(0.5f);
		emergency_phr_access_inner_panel.add(phr_info_outer_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(emergency_phr_ems_side_processing_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(emergency_phr_downloading_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));		
		emergency_phr_access_inner_panel.add(emergency_phr_extracting_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(cancel_button_panel);

		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.add(emergency_phr_access_inner_panel);
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private final void uninit_ui_for_restricted_phr_downloading_transaction_mode()
	{
		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private void setup_actions_for_restricted_phr_downloading_transaction_mode()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.addActionListener(cancel_emergency_phr_downloading_transaction_button_actionlistener);	
	}

	private void release_actions_for_restricted_phr_downloading_transaction_mode()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.removeActionListener(cancel_emergency_phr_downloading_transaction_button_actionlistener);		
	}

	// Run background tasks on another thread
	private void run_restricted_phr_downloading_background_task(final String target_emergency_server_ip_addr, final String phr_owner_name, 
		final String phr_owner_authority_name, final String data_description, final int phr_id, final String restricted_phr_download_to_path)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				perform_restricted_phr_downloading_transaction(target_emergency_server_ip_addr, phr_owner_name, phr_owner_authority_name, 
					data_description, phr_id, restricted_phr_download_to_path);

				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						uninit_ui_for_restricted_phr_downloading_transaction_mode();
						release_actions_for_restricted_phr_downloading_transaction_mode();
						create_emergency_phr_access_page();

						working_lock.unlock();
					}
				});
			}
		};

		thread.start();
	}

	private void perform_restricted_phr_downloading_transaction(String target_emergency_server_ip_addr, String phr_owner_name, String phr_owner_authority_name, 
		String data_description, int phr_id, String phr_download_to_path)
	{
		set_emergency_phr_ems_side_processing_success_state(false);
		set_cancel_emergency_phr_downloading(false);
		set_emergency_phr_extracting_state(false);

		set_indeterminate_mode_emergency_phr_ems_side_processing_progressbar();
		set_emergency_phr_downloading_state(true);

		// Call to C function
		if(!download_emergency_phr_main(target_emergency_server_ip_addr, phr_owner_name, phr_owner_authority_name, phr_id, data_description, true))
		{
			set_emergency_phr_downloading_state(false);

			if(!get_emergency_phr_ems_side_processing_success_state())     // Waiting processing at an emergency server
			{
				set_emergency_phr_ems_side_processing_progressbar_value(0);
			}

			if(get_cancel_emergency_phr_downloading())
			{
				set_cancel_emergency_phr_downloading(false);
				JOptionPane.showMessageDialog(main_panel, "Downloading the restricted-level PHR was aborted by a user");
			}

			return;
		}

		set_emergency_phr_downloading_state(false);

		set_indeterminate_mode_emergency_phr_extracting_progressbar();
		set_emergency_phr_extracting_state(true);

		// Call to C function
		if(!extract_emergency_phr_main(phr_download_to_path))
		{
			set_emergency_phr_extracting_state(false);
			set_emergency_phr_extracting_progressbar_value(0);

			if(get_cancel_emergency_phr_downloading())
			{
				set_cancel_emergency_phr_downloading(false);
				JOptionPane.showMessageDialog(main_panel, "Extracting the restricted-level PHR was aborted by a user");
			}

			return;
		}

		set_emergency_phr_extracting_state(false);
		set_emergency_phr_extracting_progressbar_value(100);
		JOptionPane.showMessageDialog(main_panel, "Downloading the restricted-level PHR succeeded");
	}

	private final void init_ui_for_requested_restricted_phr_tracking_mode()
	{			
		// Requested restricted PHR tracking table
		JLabel requested_restricted_phr_tracking_label = new JLabel("Requested Restricted-Level PHR List");
		requested_restricted_phr_tracking_label.setPreferredSize(new Dimension(560, 13));
		requested_restricted_phr_tracking_label.setMaximumSize(new Dimension(560, 13));
		requested_restricted_phr_tracking_label.setAlignmentX(0.0f);

		requested_restricted_phr_tracking_table_model = new DefaultTableModel()
		{
			private static final long serialVersionUID = -1113582565865921393L;

			@Override
    			public boolean isCellEditable(int row, int column)
			{
       				return false;
    			}
		};

    		requested_restricted_phr_tracking_table_model.setDataVector(null, new Object[] {"PHR owner", "Data description", 
			"Size", "Approvals/Threshold value", "Request status", "PHR id", "Emergency Server IP address"});

    		requested_restricted_phr_tracking_table = new JTable(requested_restricted_phr_tracking_table_model);
		requested_restricted_phr_tracking_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		requested_restricted_phr_tracking_table.removeColumn(requested_restricted_phr_tracking_table.getColumnModel().getColumn(6));
		requested_restricted_phr_tracking_table.removeColumn(requested_restricted_phr_tracking_table.getColumnModel().getColumn(5));

		JScrollPane requested_restricted_phr_tracking_table_inner_panel = new JScrollPane();
		requested_restricted_phr_tracking_table_inner_panel.setPreferredSize(new Dimension(560, 180));
		requested_restricted_phr_tracking_table_inner_panel.setMaximumSize(new Dimension(560, 180));
		requested_restricted_phr_tracking_table_inner_panel.setAlignmentX(0.0f);
		requested_restricted_phr_tracking_table_inner_panel.getViewport().add(requested_restricted_phr_tracking_table);

		JPanel requested_restricted_phr_tracking_table_outer_panel = new JPanel();
		requested_restricted_phr_tracking_table_outer_panel.setPreferredSize(new Dimension(570, 213));
		requested_restricted_phr_tracking_table_outer_panel.setMaximumSize(new Dimension(570, 213));
		requested_restricted_phr_tracking_table_outer_panel.setAlignmentX(0.0f);
		requested_restricted_phr_tracking_table_outer_panel.add(requested_restricted_phr_tracking_label);
		requested_restricted_phr_tracking_table_outer_panel.add(requested_restricted_phr_tracking_table_inner_panel);

		// Requested restricted PHR download to path
		JLabel requested_restricted_phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		requested_restricted_phr_download_to_path_textfield    = new JTextField(TEXTFIELD_LENGTH);
		browse_requested_restricted_phr_download_to_path_button.setPreferredSize(new Dimension(90, 20));
		browse_requested_restricted_phr_download_to_path_button.setMaximumSize(new Dimension(90, 20));

		JPanel requested_restricted_phr_download_to_path_panel = new JPanel(new SpringLayout());
		requested_restricted_phr_download_to_path_panel.setPreferredSize(new Dimension(465, 35));
		requested_restricted_phr_download_to_path_panel.setMaximumSize(new Dimension(465, 35));
		requested_restricted_phr_download_to_path_panel.add(requested_restricted_phr_download_to_path_label);
		requested_restricted_phr_download_to_path_panel.add(requested_restricted_phr_download_to_path_textfield);
		requested_restricted_phr_download_to_path_panel.add(browse_requested_restricted_phr_download_to_path_button);

		SpringUtilities.makeCompactGrid(requested_restricted_phr_download_to_path_panel, 1, 3, 5, 0, 10, 10);

		// Requested restricted PHR request download, cancel and quit buttons
		download_requested_restricted_phr_tracking_mode_button.setAlignmentX(0.5f);
		cancel_requested_restricted_phr_tracking_mode_button.setAlignmentX(0.5f);	
		quit_requested_restricted_phr_tracking_mode_button.setAlignmentX(0.5f);
		download_requested_restricted_phr_tracking_mode_button.setEnabled(false);
		cancel_requested_restricted_phr_tracking_mode_button.setEnabled(false);

		JPanel requested_restricted_phr_main_buttons_panel = new JPanel();
		requested_restricted_phr_main_buttons_panel.setPreferredSize(new Dimension(570, 30));
		requested_restricted_phr_main_buttons_panel.setMaximumSize(new Dimension(570, 30));
		requested_restricted_phr_main_buttons_panel.setAlignmentX(0.0f);
		requested_restricted_phr_main_buttons_panel.add(download_requested_restricted_phr_tracking_mode_button);
		requested_restricted_phr_main_buttons_panel.add(cancel_requested_restricted_phr_tracking_mode_button);
		requested_restricted_phr_main_buttons_panel.add(quit_requested_restricted_phr_tracking_mode_button);

		JPanel emergency_phr_access_inner_panel = new JPanel();
		emergency_phr_access_inner_panel.setPreferredSize(new Dimension(570, 343));
		emergency_phr_access_inner_panel.setMaximumSize(new Dimension(570, 343));
		emergency_phr_access_inner_panel.setAlignmentX(0.0f);
		emergency_phr_access_inner_panel.add(requested_restricted_phr_tracking_table_outer_panel);
		emergency_phr_access_inner_panel.add(requested_restricted_phr_download_to_path_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 50)));
		emergency_phr_access_inner_panel.add(requested_restricted_phr_main_buttons_panel);

		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.add(emergency_phr_access_inner_panel);
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private final void uninit_ui_for_requested_restricted_phr_tracking_mode()
	{
		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private void init_actions_for_requested_restricted_phr_tracking_mode()
	{
		// Requested restricted PHR tracking table
		requested_restricted_phr_tracking_table_mouseadapter = new MouseAdapter()
		{ 
        		public void mouseClicked(MouseEvent me)
			{ 
            			if(me.getModifiers() == 0 || me.getModifiers() == InputEvent.BUTTON1_MASK)
				{
					SwingUtilities.invokeLater(new Runnable()
					{
				    		public void run()
						{
							int    row            = requested_restricted_phr_tracking_table.getSelectedRow();
							String request_status = requested_restricted_phr_tracking_table.getModel().getValueAt(row, 4).toString();

							if(request_status.equals(RESTRICTED_PHR_REQUEST_PENDING))
							{
								download_requested_restricted_phr_tracking_mode_button.setEnabled(false);
								cancel_requested_restricted_phr_tracking_mode_button.setEnabled(true);
							}
							else if(request_status.equals(RESTRICTED_PHR_REQUEST_APPROVED))
							{
								download_requested_restricted_phr_tracking_mode_button.setEnabled(true);
								cancel_requested_restricted_phr_tracking_mode_button.setEnabled(true);
							}
						}
					});
				}
			}
		};

		// Browse requested restricted PHR download to path button
		browse_requested_restricted_phr_download_to_path_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						browse_requested_restricted_phr_download_to_path_button.setEnabled(false);

						JFileChooser requested_restricted_phr_download_to_path_filechooser = new JFileChooser();
						requested_restricted_phr_download_to_path_filechooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

						int ret = requested_restricted_phr_download_to_path_filechooser.showDialog(main_panel, "Choose a download path");
						if(ret == JFileChooser.APPROVE_OPTION)
						{
							String requested_restricted_phr_download_to_path = requested_restricted_phr_download_to_path_filechooser.
								getSelectedFile().getAbsolutePath();

							requested_restricted_phr_download_to_path_textfield.setText(requested_restricted_phr_download_to_path);
						}

						browse_requested_restricted_phr_download_to_path_button.setEnabled(true);
		    			}
				});
			}
		};

		// Download requested restricted PHR tracking mode button
		download_requested_restricted_phr_tracking_mode_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						download_requested_restricted_phr_tracking_mode_button.setEnabled(false);

						if(validate_requested_restricted_phr_tracking_mode_input())
						{
							int    row = requested_restricted_phr_tracking_table.getSelectedRow();

							String full_phr_ownername       = requested_restricted_phr_tracking_table.getModel().getValueAt(row, 0).toString();
							String phr_owner_authority_name = full_phr_ownername.substring(0, full_phr_ownername.indexOf("."));
							String phr_owner_name           = full_phr_ownername.substring(full_phr_ownername.indexOf(".") + 1);

							String data_description = requested_restricted_phr_tracking_table.getModel().getValueAt(row, 1).toString();
							int    phr_id = Integer.parseInt(requested_restricted_phr_tracking_table.getModel().getValueAt(row, 5).toString());

							String target_emergency_server_ip_addr = requested_restricted_phr_tracking_table.getModel(
								).getValueAt(row, 6).toString();

							String requested_restricted_phr_download_to_path = requested_restricted_phr_download_to_path_textfield.getText();

							uninit_ui_for_requested_restricted_phr_tracking_mode();
							release_actions_for_requested_restricted_phr_tracking_mode();
							init_ui_for_requested_restricted_phr_tracking_mode_downloading_transaction(phr_owner_name, phr_owner_authority_name);
							setup_actions_for_requested_restricted_phr_tracking_mode_downloading_transaction();

							// Run background tasks
							run_requested_restricted_phr_tracking_mode_downloading_background_task(target_emergency_server_ip_addr, 
								phr_owner_name, phr_owner_authority_name, data_description, phr_id, requested_restricted_phr_download_to_path);
						}

						download_requested_restricted_phr_tracking_mode_button.setEnabled(true);
		    			}
				});
			}
		};

		// Cancel requested restricted PHR tracking mode button
		cancel_requested_restricted_phr_tracking_mode_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						cancel_requested_restricted_phr_tracking_mode_button.setEnabled(false);

						int confirm_result = JOptionPane.showConfirmDialog(main_panel, 
							"Are you sure to cancel this request?", "Cancel Confirmation", JOptionPane.YES_NO_OPTION);

						if(confirm_result != JOptionPane.YES_OPTION)
						{
							cancel_requested_restricted_phr_tracking_mode_button.setEnabled(true);
							return;
						}

						int    row = requested_restricted_phr_tracking_table.getSelectedRow();

						String full_phr_ownername       = requested_restricted_phr_tracking_table.getModel().getValueAt(row, 0).toString();
						String phr_owner_authority_name = full_phr_ownername.substring(0, full_phr_ownername.indexOf("."));
						String phr_owner_name           = full_phr_ownername.substring(full_phr_ownername.indexOf(".") + 1);

						String phr_description = requested_restricted_phr_tracking_table.getModel().getValueAt(row, 1).toString();
						int    phr_id          = Integer.parseInt(requested_restricted_phr_tracking_table.getModel().getValueAt(row, 5).toString());
						String target_emergency_server_ip_addr = requested_restricted_phr_tracking_table.getModel().getValueAt(row, 6).toString();

						// Call to C function
						if(cancel_restricted_level_phr_access_request_main(target_emergency_server_ip_addr, 
							phr_owner_authority_name, phr_owner_name, phr_id, phr_description))
						{
							int list_size = phr_authority_info_list.size();
							for(int i=0; i < list_size; i++)
							{
								// Call to C function
								update_requested_restricted_phr_list_main(phr_authority_info_list.get(i).get_phr_authority_name(), 
									phr_authority_info_list.get(i).get_emergency_server_ip_address());
							}

							cancel_requested_restricted_phr_tracking_mode_button.setEnabled(false);
						}
						else
						{
							cancel_requested_restricted_phr_tracking_mode_button.setEnabled(true);
						}
		    			}
				});
			}
		};

		// Quit requested restricted PHR tracking mode button
		quit_requested_restricted_phr_tracking_mode_button_actionlistener = new ActionListener()
		{
			public void actionPerformed(ActionEvent event)
			{
				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						quit_requested_restricted_phr_tracking_mode_button.setEnabled(false);

						uninit_ui_for_requested_restricted_phr_tracking_mode();
						release_actions_for_requested_restricted_phr_tracking_mode();
						create_emergency_phr_access_page();

						working_lock.unlock();

						quit_requested_restricted_phr_tracking_mode_button.setEnabled(true);
		    			}
				});
			}
		};
	}

	private void setup_actions_for_requested_restricted_phr_tracking_mode()
	{
		// Requested restricted PHR tracking table
		requested_restricted_phr_tracking_table.addMouseListener(requested_restricted_phr_tracking_table_mouseadapter);

		// Browse requested restricted PHR download to path
		browse_requested_restricted_phr_download_to_path_button.addActionListener(browse_requested_restricted_phr_download_to_path_button_actionlistener);

		// Download requested restricted PHR tracking mode button
		download_requested_restricted_phr_tracking_mode_button.addActionListener(download_requested_restricted_phr_tracking_mode_button_actionlistener);

		// Cancel requested restricted PHR tracking mode button
		cancel_requested_restricted_phr_tracking_mode_button.addActionListener(cancel_requested_restricted_phr_tracking_mode_button_actionlistener);

		// Quit requested restricted PHR tracking mode button
		quit_requested_restricted_phr_tracking_mode_button.addActionListener(quit_requested_restricted_phr_tracking_mode_button_actionlistener);
	}

	private void release_actions_for_requested_restricted_phr_tracking_mode()
	{
		// Requested restricted PHR tracking table
		requested_restricted_phr_tracking_table.removeMouseListener(requested_restricted_phr_tracking_table_mouseadapter);

		// Browse requested restricted PHR download to path
		browse_requested_restricted_phr_download_to_path_button.removeActionListener(browse_requested_restricted_phr_download_to_path_button_actionlistener);

		// Download requested restricted PHR tracking mode button
		download_requested_restricted_phr_tracking_mode_button.removeActionListener(download_requested_restricted_phr_tracking_mode_button_actionlistener);

		// Cancel requested restricted PHR tracking mode button
		cancel_requested_restricted_phr_tracking_mode_button.removeActionListener(cancel_requested_restricted_phr_tracking_mode_button_actionlistener);

		// Quit requested restricted PHR tracking mode button
		quit_requested_restricted_phr_tracking_mode_button.removeActionListener(quit_requested_restricted_phr_tracking_mode_button_actionlistener);		
	}

	private boolean validate_requested_restricted_phr_tracking_mode_input()
	{
		String requested_restricted_phr_download_to_path;
		File   requested_restricted_phr_dir_object;

		// Validate the requested restricted PHR item selection
		if(requested_restricted_phr_tracking_table.getSelectedRow() < 0)
		{
			JOptionPane.showMessageDialog(this, "Please select the restricted-level PHR that you need to download");
			return false;
		}

		// Validate a requested restricted PHR download to path
		requested_restricted_phr_download_to_path = requested_restricted_phr_download_to_path_textfield.getText();
		if(requested_restricted_phr_download_to_path.equals(""))
		{
			JOptionPane.showMessageDialog(this, "Please specify a restricted-level PHR download directory path");
			return false;
		}

		requested_restricted_phr_dir_object = new File(requested_restricted_phr_download_to_path);
	  	if(!requested_restricted_phr_dir_object.exists())
		{
			JOptionPane.showMessageDialog(this, "The restricted-level PHR download directory does not exist");
			return false;
		}

		return true;
	}

	private final void init_ui_for_requested_restricted_phr_tracking_mode_downloading_transaction(String phr_owner_name, String phr_owner_authority_name)
	{
		// PHR owner authority name
		JLabel     phr_owner_authority_name_label     = new JLabel("Authority name: ", JLabel.RIGHT);
		JTextField phr_owner_authority_name_textfield = new JTextField(phr_owner_authority_name);
		phr_owner_authority_name_textfield.setEnabled(false);

		// PHR owner name
		JLabel     phr_owner_name_label     = new JLabel("PHR ownername: ", JLabel.RIGHT);
		JTextField phr_owner_name_textfield = new JTextField(phr_owner_name);
		phr_owner_name_textfield.setEnabled(false);

		// Requested restricted PHR download to path
		JLabel requested_restricted_phr_download_to_path_label = new JLabel("Download to: ", JLabel.RIGHT);
		requested_restricted_phr_download_to_path_textfield.setEnabled(false);

		// PHR info panel
		JPanel phr_info_inner_panel = new JPanel(new SpringLayout());
		phr_info_inner_panel.setPreferredSize(new Dimension(400, 120));
		phr_info_inner_panel.setMaximumSize(new Dimension(400, 120));

		phr_info_inner_panel.add(phr_owner_authority_name_label);
		phr_info_inner_panel.add(phr_owner_authority_name_textfield);

		phr_info_inner_panel.add(phr_owner_name_label);
		phr_info_inner_panel.add(phr_owner_name_textfield);

		phr_info_inner_panel.add(requested_restricted_phr_download_to_path_label);
		phr_info_inner_panel.add(requested_restricted_phr_download_to_path_textfield);

		SpringUtilities.makeCompactGrid(phr_info_inner_panel, 3, 2, 5, 10, 10, 10);

		JPanel phr_info_outer_panel = new JPanel(new GridLayout(0, 1));
		phr_info_outer_panel.setLayout(new BoxLayout(phr_info_outer_panel, BoxLayout.Y_AXIS));
		phr_info_outer_panel.setPreferredSize(new Dimension(450, 155));
		phr_info_outer_panel.setMaximumSize(new Dimension(450, 155));
    		phr_info_outer_panel.setBorder(BorderFactory.createTitledBorder("PHR Info"));
		phr_info_outer_panel.setAlignmentX(0.5f);
		phr_info_outer_panel.add(phr_info_inner_panel);

		// Emergency PHR EmS side progressbar
		JLabel emergency_phr_ems_side_processing_label = new JLabel("Processing at an emergency server");
		emergency_phr_ems_side_processing_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_ems_side_processing_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_ems_side_processing_label.setAlignmentX(0.0f);

		emergency_phr_ems_side_processing_progressbar = new JProgressBar(0, 100);
		emergency_phr_ems_side_processing_progressbar.setValue(0);
		emergency_phr_ems_side_processing_progressbar.setIndeterminate(false);
		emergency_phr_ems_side_processing_progressbar.setStringPainted(true);
		emergency_phr_ems_side_processing_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_ems_side_processing_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_ems_side_processing_progressbar_panel = new JPanel();
		emergency_phr_ems_side_processing_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_ems_side_processing_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_ems_side_processing_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_ems_side_processing_progressbar_panel.add(emergency_phr_ems_side_processing_label);
		emergency_phr_ems_side_processing_progressbar_panel.add(emergency_phr_ems_side_processing_progressbar);

		// Emergency PHR downloading progressbar
		JLabel emergency_phr_downloading_label = new JLabel("Downloading the restricted-level PHR");
		emergency_phr_downloading_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_downloading_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_downloading_label.setAlignmentX(0.0f);

		emergency_phr_downloading_progressbar = new JProgressBar(0, 100);
		emergency_phr_downloading_progressbar.setValue(0);
		emergency_phr_downloading_progressbar.setIndeterminate(false);
		emergency_phr_downloading_progressbar.setStringPainted(true);
		emergency_phr_downloading_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_downloading_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_downloading_progressbar_panel = new JPanel();
		emergency_phr_downloading_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_downloading_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_downloading_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_downloading_progressbar_panel.add(emergency_phr_downloading_label);
		emergency_phr_downloading_progressbar_panel.add(emergency_phr_downloading_progressbar);

		// Emergency PHR extracting progressbar
		JLabel emergency_phr_extracting_label = new JLabel("Extracting the restricted-level PHR");
		emergency_phr_extracting_label.setPreferredSize(new Dimension(350, 20));
		emergency_phr_extracting_label.setMaximumSize(new Dimension(350, 20));
		emergency_phr_extracting_label.setAlignmentX(0.0f);

		emergency_phr_extracting_progressbar = new JProgressBar(0, 100);
		emergency_phr_extracting_progressbar.setValue(0);
		emergency_phr_extracting_progressbar.setIndeterminate(false);
		emergency_phr_extracting_progressbar.setStringPainted(true);
		emergency_phr_extracting_progressbar.setMaximumSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setMinimumSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setPreferredSize(new Dimension(350, 25));
		emergency_phr_extracting_progressbar.setAlignmentX(0.0f);

		JPanel emergency_phr_extracting_progressbar_panel = new JPanel();
		emergency_phr_extracting_progressbar_panel.setPreferredSize(new Dimension(400, 55));
		emergency_phr_extracting_progressbar_panel.setMaximumSize(new Dimension(400, 55));
		emergency_phr_extracting_progressbar_panel.setAlignmentX(0.0f);
		emergency_phr_extracting_progressbar_panel.add(emergency_phr_extracting_label);
		emergency_phr_extracting_progressbar_panel.add(emergency_phr_extracting_progressbar);

		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.setAlignmentX(0.5f);	

		JPanel cancel_button_panel = new JPanel();
		cancel_button_panel.setPreferredSize(new Dimension(535, 30));
		cancel_button_panel.setMaximumSize(new Dimension(535, 30));
		cancel_button_panel.setAlignmentX(0.0f);
		cancel_button_panel.add(cancel_emergency_phr_downloading_transaction_button);

		JPanel emergency_phr_access_inner_panel = new JPanel();
		emergency_phr_access_inner_panel.setPreferredSize(new Dimension(555, 405));
		emergency_phr_access_inner_panel.setMaximumSize(new Dimension(555, 405));
		emergency_phr_access_inner_panel.setAlignmentX(0.5f);
		emergency_phr_access_inner_panel.add(phr_info_outer_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(emergency_phr_ems_side_processing_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(emergency_phr_downloading_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));		
		emergency_phr_access_inner_panel.add(emergency_phr_extracting_progressbar_panel);
		emergency_phr_access_inner_panel.add(Box.createRigidArea(new Dimension(0, 20)));
		emergency_phr_access_inner_panel.add(cancel_button_panel);

		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.add(emergency_phr_access_inner_panel);
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private final void uninit_ui_for_requested_restricted_phr_tracking_mode_downloading_transaction()
	{
		emergency_phr_access_outer_panel.removeAll();
		emergency_phr_access_outer_panel.revalidate();
		emergency_phr_access_outer_panel.repaint();
	}

	private void setup_actions_for_requested_restricted_phr_tracking_mode_downloading_transaction()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.addActionListener(cancel_emergency_phr_downloading_transaction_button_actionlistener);	
	}

	private void release_actions_for_requested_restricted_phr_tracking_mode_downloading_transaction()
	{
		// Cancel emergency PHR downloading transaction button
		cancel_emergency_phr_downloading_transaction_button.removeActionListener(cancel_emergency_phr_downloading_transaction_button_actionlistener);		
	}

	// Run background tasks on another thread
	private void run_requested_restricted_phr_tracking_mode_downloading_background_task(final String target_emergency_server_ip_addr, final String phr_owner_name, 
		final String phr_owner_authority_name, final String data_description, final int phr_id, final String requested_restricted_phr_download_to_path)
	{
		Thread thread = new Thread()
		{
			public void run()
			{
				perform_requested_restricted_phr_tracking_mode_downloading_transaction(target_emergency_server_ip_addr, phr_owner_name, 
					phr_owner_authority_name, data_description, phr_id, requested_restricted_phr_download_to_path);

				SwingUtilities.invokeLater(new Runnable()
				{
		    			public void run()
					{
						uninit_ui_for_requested_restricted_phr_tracking_mode_downloading_transaction();
						release_actions_for_requested_restricted_phr_tracking_mode_downloading_transaction();
						create_emergency_phr_access_page();

						working_lock.unlock();
					}
				});
			}
		};

		thread.start();
	}

	private void perform_requested_restricted_phr_tracking_mode_downloading_transaction(String target_emergency_server_ip_addr, String phr_owner_name, 
		String phr_owner_authority_name, String data_description, int phr_id, String phr_download_to_path)
	{
		set_emergency_phr_ems_side_processing_success_state(false);
		set_cancel_emergency_phr_downloading(false);
		set_emergency_phr_extracting_state(false);

		set_indeterminate_mode_emergency_phr_ems_side_processing_progressbar();
		set_emergency_phr_downloading_state(true);

		// Call to C function
		if(!download_emergency_phr_main(target_emergency_server_ip_addr, phr_owner_name, phr_owner_authority_name, phr_id, data_description, true))
		{
			set_emergency_phr_downloading_state(false);

			if(!get_emergency_phr_ems_side_processing_success_state())     // Waiting processing at an emergency server
			{
				set_emergency_phr_ems_side_processing_progressbar_value(0);
			}

			if(get_cancel_emergency_phr_downloading())
			{
				set_cancel_emergency_phr_downloading(false);
				JOptionPane.showMessageDialog(main_panel, "Downloading the restricted-level PHR was aborted by a user");
			}

			return;
		}

		set_emergency_phr_downloading_state(false);

		set_indeterminate_mode_emergency_phr_extracting_progressbar();
		set_emergency_phr_extracting_state(true);

		// Call to C function
		if(!extract_emergency_phr_main(phr_download_to_path))
		{
			set_emergency_phr_extracting_state(false);
			set_emergency_phr_extracting_progressbar_value(0);

			if(get_cancel_emergency_phr_downloading())
			{
				set_cancel_emergency_phr_downloading(false);
				JOptionPane.showMessageDialog(main_panel, "Extracting the restricted-level PHR was aborted by a user");
			}

			return;
		}

		set_emergency_phr_extracting_state(false);
		set_emergency_phr_extracting_progressbar_value(100);
		JOptionPane.showMessageDialog(main_panel, "Downloading the restricted-level PHR succeeded");
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

	private synchronized void clear_phr_authority_info_list_callback_handler()
	{
		phr_authority_info_list.clear();
	}

	private synchronized void add_phr_authority_info_to_list_callback_handler(final String phr_authority_name, final String emergency_server_ip_addr)
	{
		phr_authority_info_list.add(new PHRAuthorityInfo(phr_authority_name, emergency_server_ip_addr));
	}

	private synchronized void clear_secure_phr_to_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{			
				secure_phr_downloading_table_model.getDataVector().removeAllElements();
				secure_phr_downloading_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_secure_phr_list_to_table_callback_handler(final String data_description, final String file_size, final int phr_id)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				secure_phr_downloading_table_model.insertRow(secure_phr_downloading_table.getRowCount(), 
					new Object[] {data_description, file_size, Integer.toString(phr_id)});
			}
		});
	}

	private synchronized void clear_restricted_phr_to_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{			
				restricted_phr_downloading_table_model.getDataVector().removeAllElements();
				restricted_phr_downloading_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_restricted_phr_list_to_table_callback_handler(final String data_description, final String file_size, final int approvals, 
		final int threshold_value, final String request_status, final int phr_id)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				restricted_phr_downloading_table_model.insertRow(restricted_phr_downloading_table.getRowCount(), 
					new Object[] {data_description, file_size, approvals + "/" + threshold_value, request_status, Integer.toString(phr_id)});
			}
		});
	}

	private synchronized void clear_requested_restricted_phr_tracking_list_to_table_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{			
				requested_restricted_phr_tracking_table_model.getDataVector().removeAllElements();
				requested_restricted_phr_tracking_table_model.fireTableDataChanged();
			}
		});
	}

	private synchronized void add_requested_restricted_phr_tracking_list_to_table_callback_handler(final String full_phr_ownername, final String data_description, 
		final String file_size, final int approvals, final int threshold_value, final String request_status, final int phr_id, final String emergency_server_ip_addr)
	{
		no_any_requested_restricted_phr_flag = true;
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				requested_restricted_phr_tracking_table_model.insertRow(requested_restricted_phr_tracking_table.getRowCount(), 
					new Object[] {full_phr_ownername, data_description, file_size, approvals + "/" + threshold_value, request_status, 
					Integer.toString(phr_id), emergency_server_ip_addr});
			}
		});
	}

	private synchronized void set_emergency_phr_ems_side_processing_success_state_callback_handler()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				set_emergency_phr_ems_side_processing_success_state(true);
		        	set_emergency_phr_ems_side_processing_progressbar_value(100);
			}
		});
	}

	private synchronized void update_emergency_phr_received_progression_callback_handler(final int percent)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
		        	emergency_phr_downloading_progressbar.setValue(percent);
			}
		});
	}

	// Local class
	private class PHRAuthorityInfo
	{
		private String phr_authority_name;
		private String emergency_server_ip_addr;

		public PHRAuthorityInfo(String phr_authority_name, String emergency_server_ip_addr)
		{
			this.phr_authority_name       = phr_authority_name;
			this.emergency_server_ip_addr = emergency_server_ip_addr;
		}

		public String get_phr_authority_name()
		{
			return phr_authority_name;
		}

		public String get_emergency_server_ip_address()
		{
			return emergency_server_ip_addr;
		}
	}
}



