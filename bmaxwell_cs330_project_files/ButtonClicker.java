/*
 * ButtonClicker.java
 * 
 * A class to handle clicks of the "Say Something!" button
 * on the client side of the program.
 * 
 * Author: Blake Maxwell
 * 12/14/2018
 */
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ButtonClicker implements ActionListener {
		
	public void actionPerformed(ActionEvent event) {
			
		/* Handle clicks of the "Say Something!" button
		 * by initiating AES encryption of typed message
		 * to send to server. Then send the encrypted message
		 * to the server.
		 */
		AESEncryption AESEncrypt = new AESEncryption();
		System.out.println("Button clicked. Attempting to encode message: " + MyChatClient.enterChatMessages.getText() + "\n");
		String encryptedMessage = AESEncrypt.encryptor(MyChatClient.enterChatMessages.getText(), MyChatClient.sharedSecret, MyChatClient.clientEncoder);
		System.out.println("AES encrypted message: " + encryptedMessage + "\n");
		MyChatClient.clientOutput.println(encryptedMessage);
		MyChatClient.enterChatMessages.setText("");
	}
	
}
