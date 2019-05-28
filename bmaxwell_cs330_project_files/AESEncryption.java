/*
 * AESEncryption.java
 * 
 * A class using Java Ciphers and a symmetric AES key
 * to encrpyt a message and return it as a String using
 * Base64 encoding
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class AESEncryption {

	static byte[] cipherEncryptedMessage;
	static byte[] completeCipherMessage;
	static String stringEncryptedMessage;
	
	public String encryptor(String toBeEncrypted, String encryptionKey, Base64.Encoder byteEncode) {
		
		try {
			
			/* To use a Java Cipher, we need to recrate the original AES key
			 * from the String encryptionKey passed into the encryptor function.
			 * We do this, and generate a new random initilization vector (IV) byte array
			 * to use the Cipher in CTR (Counter) mode.
			 */
			System.out.println("Key used for encryption: " + encryptionKey + "\n");
			System.out.println("Message to be encrypted: " + toBeEncrypted + "\n");
			SecureRandom randomGen = new SecureRandom();
			Base64.Decoder stringDecode = Base64.getDecoder();
			SecretKey decryptedAESKey = new SecretKeySpec(stringDecode.decode(encryptionKey), "AES");
			byte[] initVector = new byte[16];
			randomGen.nextBytes(initVector);
			IvParameterSpec iv = new IvParameterSpec(initVector);
		    
			/* Perform encryption with Ciphers and AES key */
		    Cipher encrypt = Cipher.getInstance("AES/CTR/PKCS5Padding");
		    encrypt.init(Cipher.ENCRYPT_MODE, decryptedAESKey, iv);
		    cipherEncryptedMessage = encrypt.doFinal(toBeEncrypted.getBytes());
		    
		    /* We need both the IV and the ciphertext to decrypt the message.
		     * So, we put both into a ByteBuffer and get the array that backs it.
		     * From this array, we are able to use both the IV and ciphertext in decryption.
		     */
		    ByteBuffer completeMessageBuffer = ByteBuffer.allocate(initVector.length + cipherEncryptedMessage.length);
		    completeMessageBuffer.put(initVector);
		    completeMessageBuffer.put(cipherEncryptedMessage);
		    completeCipherMessage = completeMessageBuffer.array();
		}
		
		/* Handle exceptions */
		catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
		} 
		
		catch (NoSuchPaddingException e) {
		    	e.printStackTrace();
	    } 
		
		catch (InvalidKeyException e) {
				e.printStackTrace();
		} 
		
		catch (IllegalBlockSizeException e) {
				e.printStackTrace();
		} 
		
		catch (BadPaddingException e) {
				e.printStackTrace();
		} 
		
		catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
		}
		
		/* Return the complete array (ciphertext and IV) back as a string
		 * using Base64 encoding
		 */
		stringEncryptedMessage = byteEncode.encodeToString(completeCipherMessage);
		return stringEncryptedMessage;
	}
	
}
