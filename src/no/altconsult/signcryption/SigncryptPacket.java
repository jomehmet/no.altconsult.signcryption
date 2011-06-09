package no.altconsult.signcryption;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class SigncryptPacket {
	public ECCurve curve;
	public Cryptogram c;
	public ECPoint R;
	public BigInteger s;
	public SigncryptionSettings settings;
	public byte[] packetAsBytes;
	
	public SigncryptPacket(){
		
	}
	public SigncryptPacket(Cryptogram c, ECPoint r, 
			BigInteger s, SigncryptionSettings settings) {
		this.c = c;
		R = r;
		this.s = s;
		this.settings = settings;
	}
	public SigncryptPacket(byte[] signCryptPacket, 
			SigncryptionSettings settings, ECCurve curve){
		this.curve = curve;
		this.settings = settings;
		packetAsBytes = signCryptPacket;
		fetchFromBytes();
	}
	/**
	 * The byte packet to send over the communication channel.
	 * 
	 * @return
	 */
	private byte[] makeBytes(){
		Benchmark.START("getPacketAsBytes");
		byte[] RBytes = R.getEncoded();
		byte RBytesLength = (byte)RBytes.length;
		System.out.println("SigncryptPacket(39)R:" + 
				(int)RBytesLength + " bytes");
		byte[] sBytes = s.toByteArray();//24
		byte sBytesLength = (byte)(sBytes.length);
		System.out.println("SigncryptPacket(39)s:" + 
				(int)sBytesLength + " bytes");
		byte[] cBytes = c.getEncrypted();//16
		System.out.println("SigncryptPacket(39)c:" + 
				cBytes.length + " bytes");
		packetAsBytes = 
			new byte[settings.getAppPreambleByteSize() + 
                         settings.getVersionByteSize() +
                         1 + (int)RBytesLength +
                         1 + (int)sBytesLength +
                         cBytes.length];
		int position = 0;
		packetAsBytes[position] = settings.appPreamble;
		position += settings.getAppPreambleByteSize();
		
		packetAsBytes[position] = settings.version;
		position += settings.getVersionByteSize();
		
		packetAsBytes[position] = RBytesLength;
		position += 1;
		
		System.arraycopy(RBytes, 0, packetAsBytes, 
				position, (int)RBytesLength);
		position += (int)RBytesLength;
		
		packetAsBytes[position] = sBytesLength;
		position += 1;
		
		System.arraycopy(sBytes, 0, packetAsBytes, 
				position, (int)sBytesLength);
		position += (int)sBytesLength;
		
		System.arraycopy(cBytes, 0, packetAsBytes, 
				position, cBytes.length);
		Benchmark.STOP_Print("getPacketAsBytes");
		return packetAsBytes;
	}
	public byte[] getPacketAsBytes(){
		if(packetAsBytes == null)
			return makeBytes();
		return packetAsBytes;
	}	
	private void fetchFromBytes(){
		Benchmark.START("fetchFromBytes");
		byte[] appPreambleBytes = 
			new byte[settings.getAppPreambleByteSize()];
		byte[] versionBytes = 
			new byte[settings.getVersionByteSize()];
		
		int position = 0;
		System.arraycopy(packetAsBytes, position, 
				appPreambleBytes, 0, 
				settings.getAppPreambleByteSize());
		position += settings.getAppPreambleByteSize();
		
		System.arraycopy(packetAsBytes, position, 
				versionBytes, 0, settings.getVersionByteSize());
		position += settings.getVersionByteSize();
		
		int RBytesLength = packetAsBytes[position];
		position += 1;
		
		byte[] RBytes = new byte[RBytesLength];
		System.arraycopy(packetAsBytes, position, 
				RBytes, 0, RBytesLength);
		position += RBytesLength;
		
		int sBytesLength = packetAsBytes[position];
		position += 1;
		
		byte[] sBytes = new byte[sBytesLength];
		System.arraycopy(packetAsBytes, position, 
				sBytes, 0, sBytesLength);
		position += sBytesLength;
		
		byte[] cBytes = 
			new byte[packetAsBytes.length - position];
		System.arraycopy(packetAsBytes, position, cBytes, 0, 
				packetAsBytes.length - position);
		
		R = curve.decodePoint(RBytes);
		s = new BigInteger(sBytes);
		c = new Cryptogram(cBytes, settings);
		Benchmark.STOP_Print("fetchFromBytes");
	}
	public long getTimeStamp(){
		return c.getUnixTimestamp();
	}
	public String toString(){
		return "R(" + R.getX().toBigInteger() + "," 
		+ R.getY().toBigInteger() 
		+ "), \ns(" + s + "("+s.bitLength()+")) , " 
		+ "\nencrypted message(" 
		+ new String(c.getEncrypted()) + ")";
	}
}