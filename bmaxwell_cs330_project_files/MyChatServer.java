/* MyChatServer.java
 *
 * An implementation of a chat server with AES encryption and decryption
 * using Java sockets for communication
 * 
 * NOTE: I have included several println() statements
 * to show the encrypted and decrpyted RSA and AES keys as the
 * initial sharing of keys occurs. This helps us better visualize this exchange.
 * 
 * Author: Blake Maxwell
 * Base server code adapted from the Java Socket Programming 
 * series of lectures by Abhay Redkar
 * 12/14/2018
 */
import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Base64;

public class MyChatServer {
	
    /*
	 * Store usernames and printWriter objects in arrays
	 * for unique username verification and distribution of chat messages
	 * to all clients respectively.
	 */
	static ArrayList<String> userNames = new ArrayList<String>();
	static ArrayList<PrintWriter> printWriters = new ArrayList<PrintWriter>();
	static AESKeyGeneration AESKey;
	static RSAEncryption encryptAESKey;
	static Base64.Encoder serverEncode;
	static String stringEncodedAESKey;
	
    public static void main(String[] args)  {
    	
    	try {
    		
    	    /* Server listens for client connections */
    		System.out.println("Waiting for client connections...\n");
    		ServerSocket myServSocket = new ServerSocket(9800);
    		
    		/* Generate an AES key that will be shared with the clients. */
    		AESKey = new AESKeyGeneration();
    		encryptAESKey = new RSAEncryption();
			serverEncode = Base64.getEncoder();
			stringEncodedAESKey = serverEncode.encodeToString(AESKey.getKey().getEncoded());
			System.out.println("Server-generated AES key: " + stringEncodedAESKey + "\n");
    		
    		while(true) {
    		    Socket mySocket = myServSocket.accept();
    			System.out.println("New connection established!\n");
    			System.out.println("Let's encode the AES key and send it to the client!\n");
    			
    	        /* Pass AES key and Base64 encoders to each Thread instance 
    			 * to handle multiple client connections to the server.
    			 */
    		    Thread newThread = new Thread(new ConversationThreads(mySocket, encryptAESKey, stringEncodedAESKey, serverEncode));
    			newThread.start();
    		}
    		
    	}
    	
    	catch(Exception e) {
    		e.printStackTrace();
    	}
    	
    }

}

/* Thread class to handle multiple client connections
 * to the server. Each thread, like the example Java code
 * seen in class, represents one client connection to the server.
 */
class ConversationThreads implements Runnable {
	
		Socket threadSocket;
		BufferedReader threadInput;
		PrintWriter threadOutput;
		String username;
		Base64.Encoder serverEncode;
		RSAEncryption encryptAESKey;
		String sharedSecret;
		String encodedClientPublicKey;
		
		
		public ConversationThreads(Socket mySocket, RSAEncryption encryptAESKey, String sharedSecret, Base64.Encoder serverEncode) {
			this.threadSocket = mySocket;
			this.sharedSecret = sharedSecret;
			this.serverEncode = serverEncode;
			this.encryptAESKey = encryptAESKey;
		}
	
		public void run() {
			
			try {
				
				/* Establish BufferedReader and PrintWriter objects for
				 * input and output.
				 */
				threadInput = new BufferedReader(new InputStreamReader(threadSocket.getInputStream()));
				threadOutput = new PrintWriter(threadSocket.getOutputStream(), true);
				
				/* When user initially logs in and chooses a username, check the userNames
				 * array to see if that user name is in use. Depending on if it 
				 * is or not, the server sends a status message back to the client
				 * to let them know.
				 */
				boolean nameFlag = true;
				while(true) {
					if (nameFlag == false) {
						threadOutput.println("NAMEINUSE");
					}
					
					else {
						threadOutput.println("GIVENAME");
					}
					
					username = threadInput.readLine();
					
					if(username == null) {
						return;
					}
					
					else if(MyChatServer.userNames.contains(username)) {
						nameFlag = false;
					}
					
					else {
						MyChatServer.userNames.add(username);
						break;
					}
					
				}
				
				/* Accept unique username and read in
				 * client public key for RSA encryption of
				 * AES key.
				 */
				threadOutput.println("USERNAMEACCEPT" + username);
				encodedClientPublicKey = threadInput.readLine();
				MyChatServer.printWriters.add(threadOutput);
				
				System.out.println("Client public key: " + encodedClientPublicKey + "\n");
				
				/* Encrypt server AES key with client public RSA key. */
				String RSAEncodedAESKey = encryptAESKey.encryptor(sharedSecret, encodedClientPublicKey, serverEncode);
				System.out.println("Server AES key after RSA encryption with client public key: " + RSAEncodedAESKey + "\n");
				threadOutput.println(RSAEncodedAESKey);
				
				while(true) {
					
					/* Receive AES encoded message from client. */
					String newMessage = threadInput.readLine();
					System.out.println("Recieved encoded message from client: " + newMessage + "\n");
					
					if (newMessage == null) {
						return;
					}
					
					else {
						
					    /* Use shared AES key to decrypt client message. */
					    AESDecryption AESDecrypt = new AESDecryption();
					    String decodedMessage = AESDecrypt.decryptor(newMessage, sharedSecret, serverEncode);
					    System.out.println("Decoded message from client: " + decodedMessage + "\n");
					    
						/* Encrypt message again using AES key to send back to all clients. */
					    AESEncryption AESEncrypt = new AESEncryption();
					    String fullMessage = (username + ": " + decodedMessage);
					    String finalMessage = AESEncrypt.encryptor(fullMessage, sharedSecret, serverEncode);
					    System.out.println("Encrypted message to send to client: " + finalMessage + "\n");
						
						for (PrintWriter writer : MyChatServer.printWriters) {
							writer.println(finalMessage);
						}
						
					}
					
				}
				
			}
			
			/* Handle exceptions. */
			catch (Exception e) {
				e.printStackTrace();
			}
			
		}
		
}
