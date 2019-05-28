/*
 * AESKeyGeneration.java
 * 
 * A class used to generate the symmetric AES key
 * for client-server AES-encrypted communication
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AESKeyGeneration {

	private SecretKey AESKey;
	
	public AESKeyGeneration() {
		
	    try {
	    	
	    	/* Generate AES symmetric key using
	    	 * KeyGenerator.
	    	 */
			KeyGenerator genKey = KeyGenerator.getInstance("AES");
			genKey.init(128);
			AESKey = genKey.generateKey();
			
		} 
	    
	    /* Handle exceptions. */
	    catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	/* Getter method for AES key */
	public SecretKey getKey() {
		return AESKey;
	}
	
}
