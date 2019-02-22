import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class BobProgramHMAC 
{
	final static int numRun = 100;
	public static SecretKey load(String filename) throws IOException
	{
		byte[] keyb = Files.readAllBytes(Paths.get(filename));
		return new SecretKeySpec(keyb, "HMACSHA256");
	}
	
	public static String[] readFile(String filename) throws Exception
	{
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) 
		{
		    String line;
		    int i = 0;
		    String[] arr = new String[2]; 
		    while ((line = br.readLine()) != null) 
		    {
			    // process the line.
		    	arr[i] = line;
		    	i++;
		    }
		    return arr;
		}
	}
	
	public static void verify(String[] arr, SecretKey skey) 
			throws InvalidKeyException, NoSuchAlgorithmException, FileNotFoundException, IOException
	{
		//Extraction
		String hash = arr[0];
		String message = arr[1];
		if(hash.equals(generateMAC(skey, message)))
			System.out.println("Verification Successfully");
		else
			System.out.println("Verification Failure");
	}
	
	public static String generateMAC(SecretKey key, String message) 
			throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException
	{
		Mac mac = Mac.getInstance("HMACSHA256");
		mac.init(key);
		return Base64.encodeBase64String(mac.doFinal(message.getBytes()));
	}	
	
	public static boolean checkFile(String filePath)
	{
		File f = new File(filePath);
		return (f.exists() && !f.isDirectory());
	}
	
    public static void runTime(float runtime)
    {
        System.out.println("Run time: " + runtime + " ms");
        System.out.println("Average run time: " + runtime / numRun + " ms");
    }

	public static void main(String[] args) throws Exception 
	{
		SecretKey skey;
		String[] arr = new String[2]; 
		
		//Loading Secretkey
		skey = load("secretKey.txt");
		
		//Reading hash and verify
		arr = readFile("mactext.txt");
		long startTime = System.currentTimeMillis();
    	for(int i = 0; i < numRun; i++)
    	{
    		verify(arr, skey);
    	}
    	long stopTime = System.currentTimeMillis();
        float elapsedTime = stopTime - startTime;

        //Calculating runtime
        runTime(elapsedTime);
	}

}
