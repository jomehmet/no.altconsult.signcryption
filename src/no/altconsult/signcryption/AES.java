package no.altconsult.signcryption;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AES {
    private static int AES_KEY_LENGTH;
    private ParametersWithIV aes_key;
    private BlockCipher symmetricBlockCipher;
    private int symmetricBlockSize;
    private byte[] K2;
	int unix_timestamp_length = 4;
	int padding_length = 1;
    
	public AES(byte[] K2, KeyLength kl){
    	this.K2 = K2;
    	switch(kl){
		case key128:
			AES_KEY_LENGTH = 16;
			break;
		case key192:
			AES_KEY_LENGTH = 24;
			break;
		case key256:
			AES_KEY_LENGTH = 32;
			break;
		default:
			AES_KEY_LENGTH = 32;
    	}
    	UploadCipher();
    }
    private void UploadCipher() {
        // Prepare symmetric block cipher for message
        symmetricBlockCipher = 
        	new CBCBlockCipher(new AESLightEngine());
        symmetricBlockSize = 
        	symmetricBlockCipher.getBlockSize();
        createAESKey();
    }	
    private void createAESKey() {
        byte[] aes_key_bytes = new byte[AES_KEY_LENGTH];
        byte[] iv = new byte[symmetricBlockSize];
		int copylength = AES_KEY_LENGTH;
		if(K2.length < AES_KEY_LENGTH) copylength = K2.length;
        System.arraycopy(K2, 0, aes_key_bytes, 0, copylength);
        aes_key = new ParametersWithIV(
        		new KeyParameter(aes_key_bytes), iv);
    }
    protected byte[] encrypt(byte[] message, boolean isEncryption){
        // initialize block cipher in "encryption" mode
        symmetricBlockCipher.init(isEncryption, aes_key);  

        // pad the message to a multiple of the block size
        int numBlocks = 
        	(message.length / symmetricBlockSize) + 1;
        byte[] plaintext = 
        	new byte[numBlocks * symmetricBlockSize];
        System.arraycopy(message, 0, plaintext, 
        		0, message.length);

        // encrypt!
        byte[] ciphertext = 
        	new byte[numBlocks * symmetricBlockSize];
        for (int i = 0; i < ciphertext.length; 
        	i += symmetricBlockSize) {
            symmetricBlockCipher.processBlock(
            		plaintext, i, ciphertext, i);
        }
        return ciphertext;
    }    
    /**
     * Encrypts current unix_timestamp, padding and the message
     * in this order with 4 bytes +  1 byte + message_byte.length
     * 
     * @param message
     * @param numberOfBytesToStoreLenght
     * @return
     */
    protected byte[] encryptTimePaddingMessage(String message){
    	try {
    	byte[] byte_message = message.getBytes("utf8");
    	byte[] res = new byte[unix_timestamp_length
    	                      + padding_length
    	                      + byte_message.length];
    	
    	long unix_timestamp = System.currentTimeMillis() / 1000L;
    	byte[] unix_timestamp_bytes = BigInteger.valueOf(
    			unix_timestamp).toByteArray();
    	int position = 0;
    	System.arraycopy(unix_timestamp_bytes, 0, res, 
    			position, unix_timestamp_length);
    	position += unix_timestamp_length;
    	
    	int padding = 16 - ((unix_timestamp_length + 
    			padding_length + 
    			byte_message.length) % 16);
    	res[position] = (byte)padding;
    	position++;
    	
    	System.arraycopy(byte_message, 0, res, position, 
    			byte_message.length);
			return encrypt(res, true);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
    }    
    /**
     * Function especially made for the class Cryptogram, 
     * that encrypts and sets the cleartext, msglength and unix
     * timestamp field of the current Cryptogram.
     * 
     * @param cipher
     * @param current
     */
    protected byte[] decryptTimestampAndMessage(byte[] cipher, 
    		Cryptogram current){
    	byte[] cleartext = encrypt(cipher, false);
    	byte[] res = new byte[cipher.length - 
    	                      unix_timestamp_length -
    	                      padding_length];
    	byte[] unix_timestamp_bytes = new byte[unix_timestamp_length];
    	
    	int position = 0;
    	System.arraycopy(cleartext, position, 
    			unix_timestamp_bytes, 0, unix_timestamp_length);
    	position += unix_timestamp_length;
    	
    	int padding = cleartext[position];
    	position++;
    	
    	System.arraycopy(cleartext, position, res, 0, res.length);
    	current.setUnixTimestamp(
    			new BigInteger(unix_timestamp_bytes).longValue());
    	current.setMsgLength(res.length - padding);
    	return res;
    }
}

















