package no.altconsult.signcryption;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

public class SigncryptionManager extends AbstractSigncrypt {
	
	private BigInteger privateKey;
	private String privateKeyAscii85;
	private org.bouncycastle.math.ec.ECPoint publicKey;
	public SigncryptionManager(SigncryptionSettings settings) {
		super(settings);
	}
	public static void main(String[] g){
	}
	public void generateKeyPair(){
		privateKey = new BigInteger(384, new SecureRandom()).abs();
		publicKey =  G.multiply(privateKey);
		privateKeyAscii85 = Ascii85Coder.encodeBytesToAscii85(
				privateKey.toByteArray());
		System.out.println(privateKeyAscii85);
	}
	public String getPublicKeyAsAscii85(){
		return Ascii85Coder.encodeBytesToAscii85(
				new ECPoint.Fp(
				publicKey.getCurve(), publicKey.getX(), 
				publicKey.getY(), true).getEncoded()
				);
	}
	public ECPoint getPublicKeyFromAscii85(String ascii85){
		byte[] bytes  = Ascii85Coder.decodeAscii85StringToBytes(ascii85);
		return curve.decodePoint(bytes);
	}
	
	public ECPoint getPublicKey(){
		return publicKey;
	}
	public BigInteger getPrivateKey(){
		return privateKey;
	}
	protected void setKeyPair(String bigInteger){
		privateKey = new BigInteger(bigInteger);
		publicKey = G.multiply(privateKey);
	}
	
	
	public String getEncryptedAscii85PrivateKey(String password){
		if(privateKey == null)
			return null;
		byte[] bytes =  privateKey.toByteArray();
		AES aes = new AES(password.getBytes(), settings.kl);
		bytes = aes.encrypt(bytes, true);
		return Ascii85Coder.encodeBytesToAscii85(bytes);
	}
	/**
	 * Sets and returns BigInteger privateKey
	 * 
	 * @param ascii85
	 * @param password
	 * @return
	 */
	public BigInteger setPrivateKeyFromEncryptedAscii85(String ascii85, String password){
		byte[] bytes = Ascii85Coder.decodeAscii85StringToBytes(ascii85);
		AES aes = new AES(password.getBytes(), settings.kl);
		bytes = aes.encrypt(bytes, false);
		privateKey = new BigInteger(bytes);
		return privateKey;
	}
	public void setKeyPairFromEncryptedPrivateKey(String ascii85key, String password){
		AES aes = new AES(password.getBytes(), settings.kl);
		privateKey = new BigInteger(
		aes.encrypt(Ascii85Coder.decodeAscii85StringToBytes(
						ascii85key), false));
		publicKey = G.multiply(privateKey);
	}
}
