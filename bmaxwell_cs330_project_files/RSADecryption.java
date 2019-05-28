/*
 * RSADecryption.java
 * 
 * A class using Java ciphers and RSA private keys to
 * decrypt an encoded message and send it back as
 * a string using Base64 encoding
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */
import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class RSADecryption {

	byte[] decryptedBytes;
	String decryptedKey;
	
	public String decryptor(String toBeDecrypted, PrivateKey decryptionKey, Base64.Encoder byteEncode) {
		
		try {
			
			/* To use a Java Cipher, the String decryptionKey
			 * must be of the same encoding as the original PrivateKey.
			 * The String is decoded using a Base64 decoder.
			 */
			Base64.Decoder stringDecode = Base64.getDecoder();
			
			/*Perform decryption with Java ciphers and private key. */
			Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decrypt.init(Cipher.DECRYPT_MODE, decryptionKey);
			decryptedBytes = decrypt.doFinal(stringDecode.decode(toBeDecrypted.getBytes()));
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
		
		/* Encode the decrypted key as a string for later use 
		 * in message encoding and transmission.
		 */
		decryptedKey = new String(decryptedBytes);
		return decryptedKey;
	}
	
}
