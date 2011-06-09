package no.altconsult.signcryption;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class Signcrypt extends AbstractSigncrypt {
	private ECPoint publicKeyReceiver;
	private BigInteger privateKeySender; 
	private String message;
	private SigncryptPacket c;
	private BigInteger nounce;
	
	/**
	 * To signcrypt a message,
	 * the following parameters are necessary:
	 * 
	 * The private key of the sender,
	 * an BigInteger [1..q],<br>
	 * The public key of the receiver,
	 * a Point in the curve, <br>
	 * The message
	 * 
	 * @param privateKeySender
	 * @param publicKeyReceiver
	 * @param message
	 */
	public Signcrypt(BigInteger privateKeySender, 
			ECPoint publicKeyReceiver, String message, 
			SigncryptionSettings settings){
		super(settings);
		c = new SigncryptPacket();
		this.privateKeySender = privateKeySender;
		if(publicKeyReceiver != null)
			this.publicKeyReceiver = publicKeyReceiver;
		else{ //For testing
			this.privateKeySender = privateKeySender.add(BigInteger.ONE);
			this.publicKeyReceiver = G.multiply(privateKeySender);
		}
		this.message = message;	
		setRandomNounce();
	}
	/***
	 * Calculate String c, ECPoint R and BigInteger s and 
	 * wrap it into the class Cryptogram.
	 * 
	 * @return Cryptogram
	 */
	public SigncryptPacket getSignCryptPacket(){
		calculate();
		return c;
	}
	/**
	 * Calculate the matematics of the unsigncryption.
	 */
	private void calculate() {
		c.settings = settings;
		ECPoint tmp = G.multiply(nounce);
		K1 = SHA256asAbsBigInt(ConcatECPoints(tmp));
		K2 = SHA256asBytes(ConcatECPoints(publicKeyReceiver.multiply(nounce)));
		c.c = new Cryptogram(message, K2, settings);
		r = SHA256asAbsBigInt(c.c + K1.toString());
		c.s = nounce.multiply(
				r.add(privateKeySender).modInverse(q)).mod(q);
		c.R = G.multiply(r);
		//Compress R to the half R
		c.R = new ECPoint.Fp(c.R.getCurve(), c.R.getX(), 
				c.R.getY(), true);
	}
	/**
	 * Makes a secure random nonce that belongs to [1..q-1]
	 */
	private void setRandomNounce(){
		do{
			nounce = secureRandomUniformBigInteger();
		}while(nounce.compareTo(q) > -1);//Ensure nounce < q
	}
	public String toString(){
		return "message:" + message + 
			"\nnounce:" + nounce + 
			"(" + nounce.bitLength() + ")";
	}
}