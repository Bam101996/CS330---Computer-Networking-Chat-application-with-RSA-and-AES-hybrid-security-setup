/*
 * RSAEncryption.java
 * 
 * A class using Java Ciphers a client's RSA public key to
 * encrypt the shared AES key and send it back as 
 * a string using Base64 encoding.
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Base64;

public class RSAEncryption {
	
	static byte[] cipherEncryptedKey;
	static String stringEncryptedKey;
	
	public String encryptor(String toBeEncrypted, String encryptionKey, Base64.Encoder byteEncode) {
		
		try {
			
			/* To use a Java Cipher, the String encryptionKey
			 * must be of the same encoding as the original PublicKey.
			 * The String is decoded using a Base64 decoder.
			 */
			Base64.Decoder stringDecode = Base64.getDecoder();
			X509EncodedKeySpec encryptionKeySpec = new X509EncodedKeySpec(stringDecode.decode(encryptionKey));
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			PublicKey decodedEncryptionKey = keyFac.generatePublic(encryptionKeySpec);
			
			/* Perform encryption with Java ciphers and public key */
			Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encrypt.init(Cipher.ENCRYPT_MODE, decodedEncryptionKey);
			cipherEncryptedKey = encrypt.doFinal(toBeEncrypted.getBytes());
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
		
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} 
		
		catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} 
		
		catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		/* Encode the encrypted key as a String
		 * using Base64 for later decoding by the client.
		 */
		stringEncryptedKey = byteEncode.encodeToString(cipherEncryptedKey);
		return stringEncryptedKey;
	}

}
