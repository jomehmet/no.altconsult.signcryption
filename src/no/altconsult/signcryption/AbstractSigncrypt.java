package no.altconsult.signcryption;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public abstract class AbstractSigncrypt {
	protected ECCurve curve;
	protected BigInteger q;;
	protected ECPoint G;
	protected BigInteger K1;
	protected byte[] K2;
	protected BigInteger r;
	protected SigncryptionSettings settings;
	
	protected AbstractSigncrypt(SigncryptionSettings settings){
		this.settings = settings;
		new Fields(this,settings.ft);
	}
	/**
	 * Generates with help of the java.security.SecureRandom 
	 * class an uniformly chosen BigInteger from [1..q.bitLength]
	 * Uses about 30 more than the regular Random class.
	 * Complies with FIPS 140-2, Security Requirements for 
	 * Cryptographic Modules
	 */
	protected BigInteger secureRandomUniformBigInteger(){
		return new BigInteger(q.bitLength(), new SecureRandom());
	}
	/***
	 * Return a positive BigInteger digest of 
	 * the SHA256 digest.
	 * 
	 * @return BigInteger digest
	 */
	protected static BigInteger SHA256asAbsBigInt(String s){
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			digest.update(s.getBytes());
			return new BigInteger(digest.digest()).abs();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		}
		return null;
	}
	/***
	 * Return byte digest of SHA256.
	 * 
	 * @return BigInteger digest
	 */
	protected static byte[] SHA256asBytes(String s){
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			digest.update(s.getBytes());
			return digest.digest();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		}
		return null;
	}		
	/**
	 * Concatenate the string represantation of 
	 * x and y of a ECPoint.
	 * 
	 * @param ecp
	 * @return String x|y
	 */
	protected static String ConcatECPoints(ECPoint ecp){
		String s =  ecp.toString() + ecp.getY().toString();
		return s;
	}
	/**
	 * String representation of the curveequation.
	 * 
	 * @return String
	 */
	public String curveEquation(){
		return "X^3 +\n" + curve.getA().toBigInteger()
		+"(" + curve.getA().toBigInteger().bitLength() +")X" 
		+"+\n" + curve.getB().toBigInteger() 
		+"(" + curve.getB().toBigInteger().bitLength() +")" 
		+ "\nmod p -> q=" + q
		+"(" + q.bitLength() +")";
	}
	public String toString(){
		return "K1:" + K1 + ",\nK2:" + K2 + ", \nr:" + r;
	}
	public static String PointName(ECPoint P, String name){
		String s =  name 
					+ "("+ P.getX().toBigInteger() + "," 
					+P.getY().toBigInteger() +")";
		if(P.isInfinity()) 
			s += "isInfinity";
		return s;	
	}
	public void printField(int number){
		System.out.print("The field with base point: " 
				+ PointName(G, "G"));
		for(int i=0;i<number;i++){
			if(i%3 == 0) System.out.println();
			ECPoint P = G.multiply(
					new BigInteger(new Integer(i).toString()));
			if(P.isInfinity()) System.out.print("(inf)");
			else System.out.print(PointName(P," "));
		}
		System.out.println("\n");
	}
}