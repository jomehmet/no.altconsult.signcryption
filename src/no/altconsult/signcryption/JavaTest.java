package no.altconsult.signcryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;

public class JavaTest {
	public String txt = "";
	SigncryptionSettings settings = new SigncryptionSettings((byte)0xAA,(byte)0x01,
			FieldType.P384,KeyLength.key256);
    public static void main(String[] args) {
    	JavaTest t = new JavaTest();
    	t.testAverage(10);
        System.out.println(t.txt);
    }
    private void addTxt(String s){
    	txt = txt + "\n" + s;
    }
    private void clearTxt(){
    	txt = "";
    }
    public void test(String message){
    	clearTxt();
    	Benchmark.START("Total program");
    	//Testparameters
    	//PrivateKeySender
		BigInteger v_a = new BigInteger(384, new SecureRandom());
		BigInteger v_b = v_a;//PrivateKeyReceiver
		SigncryptionSettings settings = 
			new SigncryptionSettings((byte)0xAA,(byte)0x01,
					FieldType.P384,KeyLength.key256);
		Benchmark.START("signcrypt");
		Signcrypt sc = new Signcrypt(v_a, null, message, settings);
		SigncryptPacket signcryptPacket = sc.getSignCryptPacket();
		
		byte[] signCryptBytePacket = signcryptPacket.getPacketAsBytes();
		String stringpacket = Ascii85Coder.encodeBytesToAscii85(signCryptBytePacket);
		Benchmark.STOP_Print("signcrypt");
		
		signCryptBytePacket = Ascii85Coder.decodeAscii85StringToBytes(stringpacket);
		
		//System.out.println(sc.curveEquation());
		addTxt("-- Alice --");
		//addTxt(sc + ", ");
		addTxt(signcryptPacket.toString());
		addTxt("signCryptBytePacket byte size: " + 
				signCryptBytePacket.length);
		//addTxt("signCryptBase64Packet size: " + 
		//signCryptBase64Packet.length());
		
		addTxt("\n-- Bob --");
		//signCryptBytePacket = 
		//Base64Coder.decode(signCryptBase64Packet.toCharArray());
		Benchmark.START("UnSigncrypt");
		Unsigncrypt us = new Unsigncrypt(null, v_b, 
				signCryptBytePacket, settings);
		addTxt("Decrypted message:" + us.getStringMessage());
		addTxt("Unix Time Stamp:" + us.getUnixTimeStamp());
		Benchmark.STOP_Print("UnSigncrypt");
		Benchmark.STOP("Total program");
    }

    public void test2(String message){
    	clearTxt();
    	//long startTime = System.currentTimeMillis();// run your code here
		Benchmark.START("Total program");
		//Testparameters
		BigInteger v_a = new BigInteger(384, new Random());
		BigInteger v_b = v_a;
		SigncryptionSettings settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P384, KeyLength.key256);
		
		Benchmark.START("Signcrypt");
		Signcrypt sc = new Signcrypt(v_a, null, message, settings);
		byte[] bytes = sc.getSignCryptPacket().getPacketAsBytes();
		Benchmark.STOP("Signcrypt");
		
		Benchmark.START("Encode Ascii85");
		String ascii85 = Ascii85Coder.encodeBytesToAscii85(bytes);
		Benchmark.STOP("Encode Ascii85");
		
		Benchmark.START("Decode Ascii85");
		bytes = Ascii85Coder.decodeAscii85StringToBytes(ascii85);
		Benchmark.STOP("Decode Ascii85");

		Benchmark.START("Unsigncrypt");
		Unsigncrypt us = new Unsigncrypt(null, v_b, bytes, settings);
		us.getStringMessage();
		us.getUnixTimeStamp();
		Benchmark.STOP("Unsigncrypt");
		Benchmark.STOP("Total program");
    }
    public void test(String message, int round){
    	addTxt("--- Round " + round + " start---");
    	Benchmark.START("Total program");
		
		Benchmark.START("Generate private key");
		BigInteger v_a = new BigInteger(384, new SecureRandom());
		Benchmark.STOP("Generate private key");
		BigInteger v_b = v_a;
		
		
		Benchmark.START("Signcrypt");
		Signcrypt sc = new Signcrypt(v_a, null, message, settings);
		byte[] bytes = sc.getSignCryptPacket().getPacketAsBytes();
		Benchmark.STOP("Signcrypt");
		
		Benchmark.START("Encode Ascii85");
		String ascii85 = Ascii85Coder.encodeBytesToAscii85(bytes);
		Benchmark.STOP("Encode Ascii85");
		
		Benchmark.START("Decode Ascii85");
		bytes = Ascii85Coder.decodeAscii85StringToBytes(ascii85);
		Benchmark.STOP("Decode Ascii85");

		Benchmark.START("Unsigncrypt");
		Unsigncrypt us = new Unsigncrypt(null, v_b, bytes, settings);
		addTxt("Decrypted message:" +us.getStringMessage() + "(timestamp(" + new Date(us.getUnixTimeStamp()* 1000L).toString() + ")");
		Benchmark.STOP("Unsigncrypt");
		//addTxt(Benchmark.getAllResults(round+1));
		addTxt("--- Round" + round +" stop---(" + Benchmark.STOP("Total program") + ")");
    }
    public void testAverage(int rounds){
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P384, KeyLength.key256);
    	String message = "Secret";
    	Benchmark.resetAll();
    	for (int i = 0; i < rounds; i++) {
    		test(message + String.valueOf(i), i);
		}
    	addTxt("\n--- Benchmark Results ---");
    	addTxt(Benchmark.getAllResults(rounds));
    }
}