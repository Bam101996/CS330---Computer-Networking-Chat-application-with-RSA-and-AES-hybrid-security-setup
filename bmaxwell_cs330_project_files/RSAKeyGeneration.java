/*
 * RSAKeyGeneration.java
 *
 * A class used to generate the public and
 * private keys for client-server RSA-encrypted communication
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */

import java.security.*;

public class RSAKeyGeneration {
	
	public PublicKey publicKey;
    private PrivateKey privateKey;
	
    public RSAKeyGeneration() {
    	
    	try {
    		
    		/* Generate RSA public and private keys
    		 * using KeyPairGenerator.
    		 */
    		KeyPairGenerator createPair = KeyPairGenerator.getInstance("RSA");
    		createPair.initialize(2048, new SecureRandom());
    		KeyPair keys = createPair.generateKeyPair();
    		this.publicKey = keys.getPublic();
    		this.privateKey = keys.getPrivate();
    	}
    	
    	/* Handle exceptions. */
    	catch (Exception e) {
    		e.printStackTrace();
    	}
    }
    
    /* Getter methods for public and private keys */
    public PublicKey getPublicKey() {
    	return publicKey;
    }
    
    public PrivateKey getPrivateKey() {
    	return privateKey;
    }
    
}
