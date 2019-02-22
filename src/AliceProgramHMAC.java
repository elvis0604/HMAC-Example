import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
public class AliceProgramHMAC 
{
	final static int numRun = 100;
	public static SecretKey generateSecretKey() throws NoSuchAlgorithmException
	{
		KeyGenerator kgen = KeyGenerator.getInstance("HMACSHA256");
		return kgen.generateKey();
	}
	
	public static void save(SecretKey key, String filename) throws FileNotFoundException, IOException
	{
		try (FileOutputStream out = new FileOutputStream(filename)) 
		{
		    
			out.write(key.getEncoded());
			out.flush();
			System.out.println("Key Written Successfully");
		}
	}
	
	public static SecretKey load(String filename) throws IOException
	{
		byte[] keyb = Files.readAllBytes(Paths.get(filename));
		return new SecretKeySpec(keyb, "HMACSHA256");
	}
	
	public static void writeFile(String filename, String context, String hashmac) 
			throws FileNotFoundException, IOException
	{
		try (FileOutputStream out = new FileOutputStream(filename)) 
		{
			/*String content cannot be directly written into
			* a file. It needs to be converted into bytes
			*/
			byte[] temp = context.getBytes();
			out.write(temp);
			out.write(System.getProperty("line.separator").getBytes());
			temp = hashmac.getBytes();
			out.write(temp);
			out.flush();
			System.out.println("File Written Successfully");
		}
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
		
	public static String generateMAC(SecretKey key, String message) 
			throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException
	{
		Mac mac = Mac.getInstance("HMACSHA256");
		mac.init(key);
		return Base64.encodeBase64String(mac.doFinal(message.getBytes()));
	}	
	
	public static void verify(String[] arr, SecretKey skey) 
			throws InvalidKeyException, NoSuchAlgorithmException, FileNotFoundException, IOException
	{
		//Extraction
		String message = arr[0];
		String hash = arr[1];
		if(hash.equals(generateMAC(skey, message)))
			System.out.println("Verification Successfully");
		else
			System.out.println("Verification Failure");
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
	
	public static void main(String[] args) throws NoSuchAlgorithmException 
	{
		if (args.length != 1) 
        {
            System.err.println("Usage: java <string message>");
        } else 
        {
			try
			{
				String originalMessage = args[0];
				String filepath = "C:\\Users\\anhtu\\eclipse-workspace\\HMAC-Example\\mactext.txt";
				SecretKey skey;
				
				if(!checkFile(filepath))  //check if file exist; return true if exist
				{ 
					skey = generateSecretKey();
					save(skey, "secretKey.txt");
					
					String hashMAC = generateMAC(skey, originalMessage);
					writeFile("mactext.txt", hashMAC, originalMessage);
					System.out.println("Generated hash");
				} else
				{
					System.out.println("mactext.txt and secretKey.txt existed. Delete for a new key");
				}			
			} catch (Exception e) 
			{
				e.printStackTrace();
				return;
			}			
        }
		
	}

}
