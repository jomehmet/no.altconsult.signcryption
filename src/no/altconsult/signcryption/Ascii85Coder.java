package no.altconsult.signcryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

import com.idataconnect.lib.ascii85codec.Ascii85InputStream;
import com.idataconnect.lib.ascii85codec.Ascii85OutputStream;

public class Ascii85Coder {
	public static void main(String[]a){
		
		byte[] signCryptBytePacket = new byte[2];
		signCryptBytePacket[0] = (byte) 6;
		signCryptBytePacket[1] = (byte) 7;
		String signCryptAscii85Packet = encodeBytesToAscii85(signCryptBytePacket);
		System.out.println("Ascii85-out:" + signCryptAscii85Packet);
		byte[] signCryptBytePacket2 = decodeAscii85StringToBytes(signCryptAscii85Packet);
		System.out.println("bytes:" + signCryptBytePacket2);
	}
	/**
	 * Decodes an Ascii85 back in to bytes.
	 * 
	 * @param Ascii85
	 * @return
	 */
	public static byte[] decodeAscii85StringToBytes(String Ascii85){
		ArrayList<Byte> list = new ArrayList<Byte>();
		ByteArrayInputStream in_byte=null;
		try {
			in_byte = new ByteArrayInputStream(Ascii85.getBytes("ascii"));
		}catch(UnsupportedEncodingException e){e.printStackTrace();}
		Ascii85InputStream in_ascii = new Ascii85InputStream(in_byte);
		try {
			int r = in_ascii.read();
			while(r != -1000){
				list.add(new Byte((byte)r));
				r = in_ascii.read();
			}
		} catch (IOException e) {e.printStackTrace();}
		byte[] bytes = new byte[list.size()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = list.get(i).byteValue();
		}
		return bytes;
	}
	/**
	 * Encodes a byte array into Ascii85 encoded String.
	 * 
	 * @param bytes
	 * @return
	 */
	public static String encodeBytesToAscii85(byte[] bytes){
		ByteArrayOutputStream out_byte = new ByteArrayOutputStream();
		Ascii85OutputStream out_ascii = new Ascii85OutputStream(out_byte);
		
		try {
			out_ascii.write(bytes);
			out_ascii.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		String res = "";
		try {
			res = out_byte.toString("ascii");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return res;
	}
}
