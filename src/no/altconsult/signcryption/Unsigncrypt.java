package no.altconsult.signcryption;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serves unsigncryption process based on Elliptic Curve.
 * 
 * @author Jo Mehmet
 *
 */
public class Unsigncrypt extends AbstractSigncrypt {
	private SigncryptPacket c;//From sender: c, R and s
	private ECPoint publicKeySender;
	private BigInteger privateKeyReceiver;
	/**
	 * Starts the unsigncryption process and gives access to 
	 * the cleartext message, and its validity.
	 * 
	 * 
	 * @param privateKeySender
	 * @param privateKeyReceiver
	 * @param signCryptPacket
	 * @param settings
	 */
	public Unsigncrypt(ECPoint publicKeySender, 
			BigInteger privateKeyReceiver, 
			byte[] signCryptPacket, 
			SigncryptionSettings settings){
		super(settings);
		this.c = new SigncryptPacket(signCryptPacket, 
				settings, curve);
		if(publicKeySender != null)
			this.publicKeySender = publicKeySender;
		else{ //For testing 
			this.publicKeySender = 
				G.multiply(privateKeyReceiver.add(BigInteger.ONE));
		}
		this.privateKeyReceiver = privateKeyReceiver;
		calculateSecrets();
	}
	/**
	 * Calculate K1, K2 and r
	 */
	private void calculateSecrets(){
		ECPoint P  = c.R.add(publicKeySender).multiply(c.s);
		//K1 = hash(s(R + Pa))
		K1 = SHA256asAbsBigInt(ConcatECPoints(P));
		P = P.multiply(privateKeyReceiver);
		//K2 = hash(v_b*s(R + Pa)
		K2 = SHA256asBytes(ConcatECPoints(P));
		c.c.setKey(K2);
		// r = hash(c , K1)
		r = SHA256asAbsBigInt(c.c + K2.toString());
	}
	/**
	 * UTF-8 formated string of the message.
	 * 
	 * @return
	 */
	public String getStringMessage(){
		 return c.c.getCleartextAsUTF8String();
	}
	/**
	 * The Unix timestamp of when the message was signcrypted
	 * in seconds.
	 * 
	 * @return
	 */
	public long getUnixTimeStamp(){
		return c.getTimeStamp();
	}
	/**
	 * Validate the integrity of the message.
	 * 
	 * @return boolean
	 */
	public boolean isAccepted(){
		return G.multiply(r).equals(c.R); 
	}
}