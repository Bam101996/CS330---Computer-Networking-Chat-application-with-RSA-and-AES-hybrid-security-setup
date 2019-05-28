/*
 * AESDecryption.java
 * 
 * A class using Java Ciphers and a symmetric AES key
 * to decrypt a message and return it as a String
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class AESDecryption {

	static byte[] decryptedCipherMessage;
	static String stringDecryptedMessage;
	
	public String decryptor(String toBeDecrypted, String decryptionKey, Base64.Encoder byteEncode) {
		
		try {
			
			/* To use a Java Cipher, we need to recrate the original AES key
			 * from the String decryptionKey passed into the encryptor function.
			 */
			System.out.println("Key used for decryption: " + decryptionKey + "\n");
			System.out.println("Message to be decrypted: " + toBeDecrypted + "\n");
			Base64.Decoder stringDecode = Base64.getDecoder();
			SecretKey decryptedAESKey = new SecretKeySpec(stringDecode.decode(decryptionKey), "AES");
			
			/* From the AESEncryption class, String toBeDecrypted consists
			 * of the encrypted ciphertext and the IV. Both are needed for decryption
			 * here, so we wrap completeMessage (toBeDecrypted decoded from Base64)
			 * into a ByteBuffer completeMessageBuffer to extract the ciphertext and IV
			 * separately for later use.
			 */
			byte[] completeMessage = stringDecode.decode(toBeDecrypted);
			ByteBuffer completeMessageBuffer = ByteBuffer.wrap(completeMessage);
			byte[] initVector = new byte[16];
			completeMessageBuffer.get(initVector);
			IvParameterSpec iv = new IvParameterSpec(initVector);
			byte[] cipherMessage = new byte[completeMessageBuffer.remaining()];
			completeMessageBuffer.get(cipherMessage);
			
			/* Perform encryption with Ciphers and AES key. */
			Cipher decrypt = Cipher.getInstance("AES/CTR/PKCS5Padding");
			decrypt.init(Cipher.DECRYPT_MODE, decryptedAESKey, iv);
			decryptedCipherMessage = decrypt.doFinal(cipherMessage);
		}
		
		/* Handle exceptions. */
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
		
		/* Return the encrypted message back as a String. */
		stringDecryptedMessage = new String(decryptedCipherMessage);
		return stringDecryptedMessage;
	}
	
}
