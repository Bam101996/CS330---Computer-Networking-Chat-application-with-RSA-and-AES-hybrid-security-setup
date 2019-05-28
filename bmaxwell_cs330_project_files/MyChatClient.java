/* MyChatClient.java
 * 
 * An implementation of a chat client with AES encryption and decryption
 * using Java sockets and Swing GUI
 * 
 * NOTE: I have included several println() statements
 * to show the encrypted and decrpyted RSA and AES keys as the
 * initial sharing of keys occurs. This helps us better visualize this exchange.
 * 
 * Author: Blake Maxwell
 * Base chat client code adapted from the Java Socket Programming 
 * series of lectures by Abhay Redkar
 * 12/14/2018
 */
import java.io.*;
import java.net.*;
import javax.swing.*;
import java.awt.FlowLayout;
import java.util.Base64;

public class MyChatClient {
		
   /*
    * Swing GUI element variables
    * and variables needed for encrypted communication
    */
	static JFrame myChatWindow = new JFrame("CS-330 Chat Application");
	static JTextArea seeChatMessages = new JTextArea(30, 50);
	static JTextField enterChatMessages = new JTextField(45);
	static JLabel chatSeparator = new JLabel("               ");
	static JLabel usernameLabel = new JLabel("                 ");
	static JButton sendButton = new JButton("Say Something!");
	static BufferedReader clientInput;
	static PrintWriter clientOutput;
	static RSAKeyGeneration clientKeyPair;
	static RSADecryption RSADecrypt;
	static AESDecryption AESDecrypt;
	static Base64.Encoder clientEncoder;
    static String encodedClientPublicKey;
    static String encodedServerAESKey;
    static String sharedSecret;
    static String decodedMessage;
	    
	    MyChatClient() {
	    	
	    	/* Adding graphic elements to the chat window */
	    	myChatWindow.setLayout(new FlowLayout());
	    	myChatWindow.add(usernameLabel);
	    	myChatWindow.add(new JScrollPane(seeChatMessages));
	    	myChatWindow.add(chatSeparator);
	    	myChatWindow.add(enterChatMessages);
	    	myChatWindow.add(sendButton);
	    	
	    	/* Establishing size and visibility of the chat window and text entry */
	    	myChatWindow.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	    	myChatWindow.setSize(700, 750);
	    	myChatWindow.setVisible(true);
	    	
	    	/* Make the chat window text entry field initially uneditable. */
	    	enterChatMessages.setEditable(false);
	    	seeChatMessages.setEditable(false);
	    	
	    	/* Add button that users click on to send messages. */
	    	sendButton.addActionListener(new ButtonClicker());
	    	enterChatMessages.addActionListener(new ButtonClicker());
	    	
	    	/*
	    	 * Initially, we generate a public and private RSA key on
	    	 * the client side. The public key will be sent to the server
	    	 * so that the server can encode the AES key generated on its side
	    	 * and share it with the client. Then, using the private key, the client
	    	 * can decode the AES key, and both sides may use this key to encode future messages.
	    	 */
	    	clientKeyPair = new RSAKeyGeneration();
	    	clientEncoder = Base64.getEncoder();
	    	encodedClientPublicKey = clientEncoder.encodeToString(clientKeyPair.publicKey.getEncoded());
	    	RSADecrypt = new RSADecryption();
	    }
	    
	    /*
	     * This method implements the client-side of the protocol used
	     * for communication in this chat application. Using BufferedReaders
	     * and printWriters, we read in server messages and send messages 
	     * to the server respectively.
	     */
	    public void letsTalk() {
	    	
	    	try {
	    		
	    		/* Prompt user for IP address of server and their username
	    		 * and establish BufferedReader and PrintWriter objects. 
	    		 */
	    		String ipAddr = JOptionPane.showInputDialog(myChatWindow, "Enter server IP address:", "IP address", JOptionPane.PLAIN_MESSAGE);
	    		Socket mySocket = new Socket(ipAddr, 9800);
	    		clientInput = new BufferedReader(new InputStreamReader(mySocket.getInputStream()));
	    		clientOutput = new PrintWriter(mySocket.getOutputStream(), true);
	    		
	    		while(true) {
	    			
	    		    /* Test for uniqueness of usernames
	    			 * using server message responses.
	    			 */
	    			String servMessage = clientInput.readLine();
	    			if(servMessage.equals("GIVENAME")) {
	    				String username = JOptionPane.showInputDialog(myChatWindow, "Enter a username:", "Username entry", JOptionPane.PLAIN_MESSAGE);
	    				clientOutput.println(username);
	    			}
	    			
	    			else if(servMessage.equals("NAMEINUSE")) {
	    				String username = JOptionPane.showInputDialog(myChatWindow, "Please enter a different name:", "Username already in use!", JOptionPane.WARNING_MESSAGE);
	    				clientOutput.println(username);
	    			}
	    			
	    			/* If the username is accepted, add it to top of chat window,
	    			 * and send the public RSA key to the server. The server uses this
	    			 * public key to encrypt the AES key it generates.
	    			 * Decrypt server AES key using client RSA private key.
	    			 */
	    			else if(servMessage.startsWith("USERNAMEACCEPT")) {
	    				enterChatMessages.setEditable(true);
	    				usernameLabel.setText("Currently logged in as: " + servMessage.substring(14));
	    				System.out.println("Client public key to be sent to server: " + encodedClientPublicKey + "\n");
	    				
	    				/* Send client public RSA key to server. */
	    				clientOutput.println(encodedClientPublicKey);
	    				
	    				/* Read in RSA encrypted server AES key
	    				 * and decrypt it with client's private RSA key. 
	    				 */
	    				encodedServerAESKey = clientInput.readLine();
	    				System.out.println("RSA encoded AES key from server: " + encodedServerAESKey + "\n");
	    				sharedSecret = RSADecrypt.decryptor(encodedServerAESKey, clientKeyPair.getPrivateKey(), clientEncoder);
	    				System.out.println("Decoded AES Key for future encryption: " + sharedSecret + "\n");
	    			
	    			}
	    			
	    			/* Decrypt incoming AES encoded messages from server using 
	    			 * the shared AES key and print them out for all clients to see.
	    			 */
	    			else {
	    				System.out.println("Received new message from server: " + servMessage + "\n");
	    				AESDecrypt = new AESDecryption();
	    				decodedMessage = AESDecrypt.decryptor(servMessage, sharedSecret, clientEncoder);
	    				System.out.println("Decoded message to append to chat window: " + decodedMessage);
	    				seeChatMessages.append(decodedMessage + "\n");
	    			}
	    		}
	    	}
	    	
	    	/* Handle exceptions */
	    	catch(Exception e) {
	    		e.printStackTrace();
	    	}
	    	
	    }
	    
	public static void main(String[] args) {
	    MyChatClient myChatClient = new MyChatClient();
	    myChatClient.letsTalk();
	}
	    
}
