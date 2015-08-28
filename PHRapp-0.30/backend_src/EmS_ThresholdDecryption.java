import java.math.*;
import java.util.*;
import java.io.*;

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;

public class EmS_ThresholdDecryption
{
	static int                           no_approvals;
	static String                        prefix_file_path;
	static String                        suffix_file_path;

	static PaillierPrivateThresholdKey[] secret_key_list;
	static BigInteger                    enc_unique_emergency_key_passwd;
	static BigInteger                    unique_emergency_key_passwd;

	private static boolean deserialize_threshold_secret_keys()
	{
		// Deserialize the threshold secret keys associated with the number of approvals
		secret_key_list = new PaillierPrivateThresholdKey[no_approvals];

		try{
			for(int i = 0; i < no_approvals; i++)
			{
				FileInputStream   in = new FileInputStream(prefix_file_path + "/secret_key" + suffix_file_path + i);
				ObjectInputStream is = new ObjectInputStream(in);

				secret_key_list[i] = (PaillierPrivateThresholdKey)is.readObject();
			}
		}
		catch(Exception e)
		{
			System.out.println("Deserialize the threshold secret keys failed");
			e.printStackTrace();
			return false;
		}

		return true;
	}

	private static boolean deserialize_encrypted_unique_emergency_key_passwd()
	{
		// Deserialize the encrypted unique emergency key password
		try{
			FileInputStream   in = new FileInputStream(prefix_file_path + "/enc_threshold_msg" + suffix_file_path);
			ObjectInputStream is = new ObjectInputStream(in);

			enc_unique_emergency_key_passwd = (BigInteger)is.readObject();
		}
		catch(Exception e)
		{
			System.out.println("Deserialize the encrypted unique emergency key password failed");
			return false;
		}

		return true;
	}

	private static boolean decrypt_encrypted_unique_emergency_key_passwd()
	{	
		// Decrypt the encrypted unique emergency key password with a set of threshold secret keys
		PaillierThreshold pthreshold;
		DecryptionZKP[]   partial_decryption_list = new DecryptionZKP[no_approvals];

		try{
			for(int i = 0; i < no_approvals; i++)
			{
				pthreshold = new PaillierThreshold(secret_key_list[i]);
				partial_decryption_list[i] = pthreshold.decryptProof(enc_unique_emergency_key_passwd);
			}

			// Decrypt the encrypted unique emergency key password
			pthreshold = new PaillierThreshold(secret_key_list[0]);
			unique_emergency_key_passwd = pthreshold.combineShares(partial_decryption_list);
		}
		catch(IllegalArgumentException e)
		{
			System.out.println("Decrypting the encrypted unique emergency key password failed");
			return false;
		}

		return true;
	}

	private static void show_usage()
	{
		System.out.println("usage: java EmS_ThresholdDecryption no_approvals prefix_file_path suffix_file_path");
		System.out.println("       no_approvals must be a positive integer more than 0");
		System.out.println("       prefix_file_path must be a string");
		System.out.println("       suffix_file_path must be a string");
		System.exit(1);
	}

	// Main method
	public static void main(String[] args)
	{
		if(args.length != 3)
			show_usage();

		// Parse arguments
		try{
        		no_approvals = Integer.parseInt(args[0]);
			if(no_approvals <= 0)
				show_usage();

			prefix_file_path = args[1];
			suffix_file_path = args[2];
    		}
		catch(NumberFormatException e)
		{
        		show_usage();
        		System.exit(1);
    		}

		// Deserialize the threshold secret keys associated with the number of approvals
		if(!deserialize_threshold_secret_keys())
			System.exit(1);

		// Deserialize the encrypted unique emergency key password
		if(!deserialize_encrypted_unique_emergency_key_passwd())
			System.exit(1);

		// Decrypt the encrypted unique emergency key password with a set of threshold secret keys
		if(!decrypt_encrypted_unique_emergency_key_passwd())
			System.exit(1);

		// Output the result to console, so the caller catchs this message and extracts it to be a password of the unique emergency key
		System.out.println("unique_emergency_key_passwd: " + unique_emergency_key_passwd);
	}
}



