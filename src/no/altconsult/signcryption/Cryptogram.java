package no.altconsult.signcryption;

import java.io.UnsupportedEncodingException;

public class Cryptogram {
	private byte[] encrypted;
	private byte[] cleartext;
	private int msgLength;//Max 2^16 - 1 (65 536)
	private byte[] key;
	private AES aes;
	private long unix_timestamp;
	private SigncryptionSettings settings;
	
	/**
	 * Add the encrypted byte-packet and the nr of bytes 
	 * telling the length of the payload.
	 * The payload length is stored in the bytes 
	 * [0 .. nrOfLengthBytes] of the cleartext.
	 * 
	 * @param  encrypted
	 */
	public Cryptogram(byte[] encrypted, byte[] key, 
			SigncryptionSettings settings){
		this.encrypted = encrypted;
		this.key = key;
		this.settings = settings;
		aes = new AES(this.key,settings.kl);
		cleartext = aes.decryptTimestampAndMessage(encrypted, this);
	}
	
	public Cryptogram(byte[] encrypted, 
			SigncryptionSettings settings){
		this.encrypted = encrypted;
		this.settings = settings;
	}
	
	/**
	 * Add the cleartext String you want to encrypt. 
	 * The number of bytes you want to hold the String length.
	 * Key is typically K2 in signcryption.
	 * 
	 * @param cleartext
	 * @param nrOfLengthBytes
	 * @param key
	 */
	public Cryptogram(String cleartext,	byte[] key, 
			SigncryptionSettings settings){
		msgLength = cleartext.length();
		aes = new AES(key, settings.kl);
		encrypted = 
			aes.encryptTimePaddingMessage(cleartext);
	}
	public byte[] getEncrypted(){
		return encrypted;
	}
	/**
	 * The system time of when the message was signed.
	 * 
	 * @return
	 */
	protected long getUnixTimestamp(){
		return unix_timestamp;
	}
	protected void setUnixTimestamp(long timestamp){
		unix_timestamp = timestamp;
	}
	public void setKey(byte[] key){
		this.key = key;
	}
	public void setCleartext(byte[] cleartext) {
		this.cleartext = cleartext;
	}
	/**
	 * Returns utf8 String representation of 
	 * the bytevise cleartext.
	 * 
	 * @return String
	 */
	public String getCleartextAsUTF8String() {
		aes = new AES(key,settings.kl);
		if(cleartext == null)
			cleartext = aes.decryptTimestampAndMessage(encrypted, this);
		try {
			String str =  new String(cleartext,"utf8");
			str.length();
			try{
			str =  str.substring(0, msgLength);
			}catch (StringIndexOutOfBoundsException e) {
				System.out.println(e.getMessage() + 
				" Cryptogram line 54\nOoops! " +
				"You should probably check the symetric K2");
			}
			return str;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	public void setMsgLength(int msgLength){
		this.msgLength = msgLength;
	}
}