package no.altconsult.signcryption;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class defines different Elliptic Curve fields and set the
 * FieldType chosen to an AbstractSigncrypt object.
 * 
 * To add more Elliptic Curve fields, extend this class. 
 * 
 * @author Jo Mehmet
 *
 */
public class Fields {
	private AbstractSigncrypt as;
	protected Fields(AbstractSigncrypt as, FieldType ft){
		this.as = as;
		switch(ft){
			case selfDefined:
				selfDefined();
				return;
			case P192:
				setP192();
				break;
			case P256:
				setP256();
				break;
			case P384:
				setP384();
				break;
			default:
				setP384();
			break;
		}
	}
	private void setP192()
    {
        // p = 2^192 - 2^64 - 1
        BigInteger p = 
        	fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFEFFFFFFFFFFFFFFFF");
        BigInteger a = 
        	fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFEFFFFFFFFFFFFFFFC");
        BigInteger b = 
        	fromHex("64210519E59C80E70FA7E9AB" +
        			"72243049FEB8DEECC146B9B1");
        as.q = 
        	fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"99DEF836146BC9B1B4D22831");

        as.curve = new ECCurve.Fp(p, a, b);
        as.G = as.curve.decodePoint(
        		Hex.decode("04188DA80EB03090F" +
        				"67CBF20EB43A18800F4F" +
        				"F0AFD82FF101207192B9" +
        				"5FFC8DA78631011ED6B2" +
        				"4CDD573F977A11E794811"));
    }
    private void setP256()
    {
    	// p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
        BigInteger p = 
        	fromHex("FFFFFFFF0000000100000000" +
        			"0000000000000000FFFFFFFF" +
        			"FFFFFFFFFFFFFFFF");
        BigInteger a = 
        	fromHex("FFFFFFFF0000000100000000" +
        			"0000000000000000FFFFFFFF" +
        			"FFFFFFFFFFFFFFFC");
        BigInteger b = 
        	fromHex("5AC635D8AA3A93E7B3EBBD55" +
        			"769886BC651D06B0CC53B0F6" +
        			"3BCE3C3E27D2604B");
        as.q = 
        	fromHex("FFFFFFFF00000000FFFFFFFF" +
        			"FFFFFFFFBCE6FAADA7179E84" +
        			"F3B9CAC2FC632551");

        as.curve = new ECCurve.Fp(p, a, b);
        as.G = as.curve.decodePoint(
        		Hex.decode("046B17D1F2E12C424" +
        				"7F8BCE6E563A440F2770" +
        				"37D812DEB33A0F4A1394" +
        				"5D898C2964FE342E2FE1" +
        				"A7F9B8EE7EB4A7C0F9E1" +
        				"62BCE33576B315ECECBB" +
        				"6406837BF51F5"));
    }
    private void setP384()
    {
        // p = 2^384 - 2^128 - 2^96 + 2^32 - 1
        BigInteger p = 
        	fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFFFFFFFFFEFFFFFFFF" +
        			"0000000000000000FFFFFFFF");
        BigInteger a = 
        	fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFFFFFFFFFEFFFFFFFF" +
        			"0000000000000000FFFFFFFC");
        BigInteger b = 
        	fromHex("B3312FA7E23EE7E4988E056B" +
        			"E3F82D19181D9C6EFE814112" +
        			"0314088F5013875AC656398D" +
        			"8A2ED19D2A85C8EDD3EC2AEF");
        as.q = 
        	fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"FFFFFFFFFFFFFFFFFFFFFFFF" +
        			"C7634D81F4372DDF581A0DB2" +
        			"48B0A77AECEC196ACCC52973");

        as.curve = new ECCurve.Fp(p, a, b);
        as.G = as.curve.decodePoint(
        		Hex.decode("04AA87CA22BE8B053" +
        				"78EB1C71EF320AD746E1" +
        				"D3B628BA79B9859F741E" +
        				"082542A385502F25DBF5" +
        				"5296C3A545E3872760AB" +
        				"73617DE4A96262C6F5D9" +
        				"E98BF9292DC29F8F41DB" +
        				"D289A147CE9DA3113B5F" +
        				"0B8C00A60B1CE1D7E819" +
        				"D7A431D7C90EA0E5F"));
    }
	/**
	 * Initialize the field with the basepoint G.
	 * Values from the IS book p310.
	 */
	protected void selfDefined(){
		//Make the Curve as in ch10.4, p310 of the IS-book
		BigInteger Q = new BigInteger("23");//Q, The prime
		BigInteger a = new BigInteger("1");// A		
		BigInteger b = new BigInteger("1");// B
		as.curve = new ECCurve.Fp(Q, a, b);
		//Set the base point G
		BigInteger x = new BigInteger("17");
		BigInteger y = new BigInteger("3");
		as.G = new ECPoint.Fp(as.curve, 
				new ECFieldElement.Fp(Q, x), 
				new ECFieldElement.Fp(Q, y));
	}
    private static BigInteger fromHex(String hex)
    {
        return new BigInteger(1, Hex.decode(hex));
    }
}
