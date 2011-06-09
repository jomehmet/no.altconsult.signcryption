package no.altconsult.signcryption;

public final class SigncryptionSettings {
	public byte appPreamble;
	public byte version;
	public FieldType ft;
	public KeyLength kl;
	public SigncryptionSettings(byte appPreamble, byte version, 
			FieldType ft, KeyLength kl) {
		super();
		this.appPreamble = appPreamble;
		this.version = version;
		this.ft = ft;
		this.kl = kl;
	}
	public int getAppPreambleByteSize(){
		return 1;
	}
	public int getVersionByteSize(){
		return 1;
	}
}
