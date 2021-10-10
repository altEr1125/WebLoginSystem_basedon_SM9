package com.kgcmaster;

import com.yy.gm.sm9.KGC;
import com.yy.gm.sm9.MasterKeyPair;
import com.yy.gm.sm9.PrivateKey;
import com.yy.gm.sm9.PrivateKeyType;
import com.yy.gm.sm9.SM9Curve;

public class KGCMaster {
	private MasterKeyPair masterKeyPair;
	private byte[] privateKey;
	private byte[] publicKey;
	private SM9Curve sm9Curve = new SM9Curve();
    private KGC kgc = new KGC(sm9Curve);//获取公私钥的密钥对，分签名主公私钥、用户公私钥；加密主公私钥、用户公私钥
	public KGCMaster() {
		this.masterKeyPair = kgc.genEncryptMasterKeyPair();
		this.privateKey = this.masterKeyPair.getPrivateKey().toByteArray();
		this.publicKey = this.masterKeyPair.getPublicKey().toByteArray();
		this.kgc = kgc;
	}
	
	public byte[] getUserPrivateKey(String uid) {
        PrivateKey encryptPrivateKey = null;
		try {
			encryptPrivateKey = kgc.genPrivateKey(this.masterKeyPair.getPrivateKey(), uid, PrivateKeyType.KEY_ENCRYPT);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return encryptPrivateKey.toByteArray();
	}
	public KGC getKgc() {
		return kgc;
	}
	public MasterKeyPair getMasterKeyPair() {
		return masterKeyPair;
	}

	public void setMasterKeyPair(MasterKeyPair masterKeyPair) {
		this.masterKeyPair = masterKeyPair;
	}

	public byte[] getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(byte[] privateKey) {
		this.privateKey = privateKey;
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public static void main(String[] args) {
		
	}
}
