package com.yy.test;

import com.yy.Main;
import com.yy.gm.sm3.SM3;
import com.yy.gm.sm4.SM4;
import com.yy.gm.sm9.KGC;
import com.yy.gm.sm9.KGCWithStandardTestKey;
import com.yy.gm.sm9.MasterKeyPair;
import com.yy.gm.sm9.MasterPrivateKey;
import com.yy.gm.sm9.MasterPublicKey;
import com.yy.gm.sm9.PrivateKey;
import com.yy.gm.sm9.PrivateKeyType;
import com.yy.gm.sm9.SM9;
import com.yy.gm.sm9.ResultKeyExchange;
import com.yy.gm.sm9.SM9Curve;
import com.yy.gm.sm9.ResultEncapsulate;
import com.yy.gm.sm9.ResultEncapsulateCipherText;
import com.yy.gm.sm9.G1KeyPair;
import com.yy.gm.sm9.ResultCipherText;
import com.yy.gm.sm9.ResultSignature;
import com.yy.gm.sm9.SM9Utils;
import com.yy.gm.sm9.SM9WithStandardTestKey;

import java.math.BigInteger;

/**
 * SM9 standard test.
 *
 */
public final class SM9Test {
    private SM9Test() {

    }

    public static void test(int testType, boolean allowReconstructData,String [] type,String id_B,String msg)
    {
        SM9Curve sm9Curve = new SM9Curve();
        Main.showMsg(sm9Curve.toString());

        KGC kgc = new KGC(sm9Curve);
        SM9 sm9 = new SM9(sm9Curve);
        

        try {
             if(testType==1) {
                kgc = new KGCWithStandardTestKey(sm9Curve);
                sm9 = new SM9WithStandardTestKey(sm9Curve);

                if(allowReconstructData) {
                    test_sm9_sign_re(kgc, sm9);
                    test_sm9_keyExchange_re(kgc, sm9);
                    test_sm9_keyEncap_re(kgc, sm9);
                    test_sm9_encrypt_re(kgc, sm9);
                } else {
                    test_sm9_sign_standard(kgc, sm9);
                    test_sm9_keyExchange_standard(kgc, sm9);
                    test_sm9_keyEncap_standard(kgc, sm9);
                    test_sm9_encrypt_standard(kgc, sm9);
                }
            } else {
                 //test_sm9_sign(kgc, sm9);
                 //test_sm9_keyExchange(kgc, sm9);
                 //test_sm9_keyEncap(kgc, sm9);
                 test_sm9_encrypt(kgc, sm9,type,id_B,msg);
             }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }




    public static void test_sm9_keyEncap(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9��Կ��װ����\n");

        String id_B = "Bob";

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(id_B);

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("����˽Կ de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        int keyByteLen = 32;
        Main.showMsg("��Կ��װ�ĳ���: " + keyByteLen + " bytes");

        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);
        Main.showMsg("��Կ��װ���:");
        Main.showMsg(keyEncapsulation.toString());

        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);
        Main.showMsg("�������Կ:");
        Main.showMsg(SM9Utils.toHexString(K));

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("���Գɹ�");
        else
            Main.showMsg("����ʧ��");
    }

    public static void test_sm9_encrypt(KGC kgc, SM9 sm9,String [] type,String id_B,String msg) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9�ӽ��ܲ���\n");

//        String id_B = "Bob";
//        String msg = "Chinese IBE standard";

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
//        Main.showMsg("������˽Կ ke:");
//        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
//        Main.showMsg("��������Կ Ppub-e:");
//        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(id_B);

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
//        Main.showMsg("����˽Կ de_B:");
//        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("��������Ϣ M:");
        Main.showMsg(msg);
//        Main.showMsg("��ϢM�ĳ���: "+msg.length() + " bytes");
//        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
//        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            if(isBaseBlockCipher)
                Main.showMsg("�������ĵķ���Ϊ���������㷨 ����:");
            else
                Main.showMsg("�������ĵķ���Ϊ����KDF���������� ����:");

            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("���ܺ������ C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));
            type[0]=SM9Utils.toHexString(resultCipherText.toByteArray());
            
            
            Main.showMsg("");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("���ܺ������M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("�ӽ��ܳɹ�");
            } else {
                Main.showMsg("�ӽ���ʧ��");
            }

            isBaseBlockCipher = true;
        }
        
    }

    public static byte[] encrypt(KGC kgc, SM9 sm9,MasterPublicKey masterPublicKey,String id_B,String msg) throws Exception {

        int macKeyByteLen = SM3.DIGEST_SIZE;

        boolean isBaseBlockCipher = false;

        ResultCipherText resultCipherText = sm9.encrypt(masterPublicKey, id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
        Main.showMsg("���ܺ������ C=C1||C3||C2:");
        Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));
        return resultCipherText.toByteArray();

    }
    
    public static void dencrypt(KGC kgc, SM9 sm9,String [] type,String id_B,String msg,PrivateKey encryptPrivateKey,ResultCipherText resultCipherText) throws Exception {

        int macKeyByteLen = SM3.DIGEST_SIZE;
        boolean isBaseBlockCipher = false;
        byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
        Main.showMsg("���ܺ������M':");
        Main.showMsg(new String(msgd));
        }
        
    
    public static void test_sm9_keyExchange(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9��Կ��������\n");


        String myId = "Alice";
        String othId = "Bob";

        MasterKeyPair masterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(masterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(masterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��A�ı�ʶIDA:");
        Main.showMsg(myId);
        PrivateKey myPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), myId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("ʵ��A�ļ���˽Կ de_A:");
        Main.showMsg(myPrivateKey.toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(othId);
        PrivateKey othPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), othId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("ʵ��B�ļ���˽Կ de_B:");
        Main.showMsg(othPrivateKey.toString());

        int keyByteLen = 16;
        Main.showMsg("��Կ�����ĳ���: " + keyByteLen + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        G1KeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), othId);

        SM9WithStandardTestKey.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        G1KeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), myId);

        ResultKeyExchange othAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), false,
                othId, myId, othPrivateKey, othTempKeyPair, myTempKeyPair.getPublicKey(), keyByteLen);

        ResultKeyExchange myAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), true,
                myId, othId, myPrivateKey, myTempKeyPair, othTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("A��");
        Main.showMsg("SA: "+SM9Utils.toHexString(myAgreementKey.getSA2()));
        Main.showMsg("S1: "+SM9Utils.toHexString(myAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(myAgreementKey.getSK()));

        Main.showMsg("B��");
        Main.showMsg("S2: "+SM9Utils.toHexString(othAgreementKey.getSA2()));
        Main.showMsg("SB: "+SM9Utils.toHexString(othAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(othAgreementKey.getSK()));

        boolean isSuccess = true;
        if(SM9Utils.byteEqual(myAgreementKey.getSA2(), othAgreementKey.getSA2()))
            Main.showMsg("SA = S2");
        else {
            Main.showMsg("SA != S2");
            isSuccess = false;
        }

        if(SM9Utils.byteEqual(myAgreementKey.getSB1(), othAgreementKey.getSB1()))
            Main.showMsg("S1 = SB");
        else {
            Main.showMsg("S1 != SB");
            isSuccess = false;
        }

        if(SM9Utils.byteEqual(myAgreementKey.getSK(), othAgreementKey.getSK()))
            Main.showMsg("SK_A = SK_B");
        else {
            Main.showMsg("SK_A != SK_B");
            isSuccess = false;
        }

        if(isSuccess)
            Main.showMsg("��Կ�����ɹ�");
        else
            Main.showMsg("��Կ����ʧ��");
    }

    public static void test_sm9_sign(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9ǩ������\n");

        String id_A = "Alice";

        //����ǩ������Կ��
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("ǩ����˽Կ ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("ǩ������Կ Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());

        //��ʾID��Ϣ
        Main.showMsg("ʵ��A�ı�ʶIDA:");
        Main.showMsg(id_A);

        //����ǩ��˽Կ
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("ǩ��˽Կ ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //ǩ��
        Main.showMsg("ǩ�������е����ֵ:");
        String msg = "Chinese IBS standard";
        Main.showMsg("��ǩ����Ϣ M:");
        Main.showMsg(msg);

        ResultSignature signature = sm9.sign(signMasterKeyPair.getPublicKey(), signPrivateKey, msg.getBytes());
        Main.showMsg("��ϢM��ǩ��Ϊ(h,s):");
        Main.showMsg(signature.toString());

        //��ǩ
        if(sm9.verify(signMasterKeyPair.getPublicKey(), id_A, msg.getBytes(), signature))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }

    public static void test_sm9_keyEncap_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9��Կ��װ����\n");

        String id_B = "Bob";

        Main.showMsg("��������Կ���û���Կ���������е����ֵ:");

        KGCWithStandardTestKey.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("����˽Կ de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        int keyByteLen = 32;
        Main.showMsg("��Կ��װ�ĳ���: " + keyByteLen + " bytes");

        Main.showMsg("��Կ��װ����A1-A7�е����ֵ:");
        SM9WithStandardTestKey.r = new BigInteger("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722", 16);
        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);

        Main.showMsg("���װ����B1-B4�е����ֵ:");
        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("���Գɹ�");
        else
            Main.showMsg("����ʧ��");
    }

    public static void test_sm9_keyEncap_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9��Կ��װ����\n");

        String id_B = "Bob";

        Main.showMsg("��������Կ���û���Կ���������е����ֵ:");
        KGCWithStandardTestKey.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());


        //�ع�ǩ������Կ��
        Main.showMsg("������˽Կ�ع�����:");
        MasterPrivateKey encryptMasterPrivateKey = MasterPrivateKey.fromByteArray(encryptMasterKeyPair.getPrivateKey().toByteArray());
        Main.showMsg("�ع���ļ�����˽Կ:");
        Main.showMsg(encryptMasterPrivateKey.toString());


        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterPrivateKey, id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("����˽Կ de_B:");
        Main.showMsg(encryptPrivateKey.toString());


        //�ع�ǩ��˽Կ
        Main.showMsg("����˽Կ�ع�����:");
        PrivateKey encryptPrivateKey0 = PrivateKey.fromByteArray(kgc.getCurve(), encryptPrivateKey.toByteArray());
        Main.showMsg("�ع���ļ���˽Կ:");
        Main.showMsg(encryptPrivateKey0.toString());


        int keyByteLen = 32;
        Main.showMsg("��Կ��װ�ĳ���: " + keyByteLen + " bytes");


        Main.showMsg("��Կ��װ����A1-A7�е����ֵ:");
        SM9WithStandardTestKey.r = new BigInteger("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722", 16);
        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);
        Main.showMsg("��Կ��װ���ֵ:");
        Main.showMsg(keyEncapsulation.toString());

        //�ع���Կ����
        Main.showMsg("�ع���Կ��װ����е���Կ����:");
        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        Main.showMsg("�ع������Կ����:");
        Main.showMsg(cipherText.toString());


        Main.showMsg("���װ����B1-B4�е����ֵ:");
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("���Գɹ�");
        else
            Main.showMsg("����ʧ��");
    }

    public static void test_sm9_encrypt_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9�ӽ��ܲ���\n");

        String id_B = "Bob";
        String msg = "Chinese IBE standard";

        Main.showMsg("��������Կ���û�������Կ���������е����ֵ:");

        KGCWithStandardTestKey.k= new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("����˽Կ de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("��������Ϣ M:");
        Main.showMsg(msg);
        Main.showMsg("M��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        Main.showMsg("��ϢM�ĳ���: "+msg.length() + " bytes");
        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C", 16);

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            if(isBaseBlockCipher)
                Main.showMsg("�������ĵķ���Ϊ���������㷨 ����:");
            else
                Main.showMsg("�������ĵķ���Ϊ����KDF���������� ����:");

            Main.showMsg("�����㷨����A1-A8�е����ֵ:");
            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("���� C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));

            Main.showMsg("");
            Main.showMsg("�����㷨����B1-B5�е����ֵ:");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("���ܺ������M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("�ӽ��ܳɹ�");
            } else {
                Main.showMsg("�ӽ���ʧ��");
            }

            isBaseBlockCipher = true;
        }
    }

    public static void test_sm9_encrypt_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9�ӽ��ܲ���\n");

        String id_B = "Bob";
        String msg = "Chinese IBE standard";

        Main.showMsg("��������Կ���û�������Կ���������е����ֵ:");

        KGCWithStandardTestKey.k= new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("����˽Կ de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("��������Ϣ M:");
        Main.showMsg(msg);
        Main.showMsg("M��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        Main.showMsg("��ϢM�ĳ���: "+msg.length() + " bytes");
        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C", 16);

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            if(isBaseBlockCipher)
                Main.showMsg("�������ĵķ���Ϊ���������㷨 ����:");
            else
                Main.showMsg("�������ĵķ���Ϊ����KDF���������� ����:");

            Main.showMsg("�����㷨����A1-A8�е����ֵ:");
            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("���� C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));

            //�����ع�
            Main.showMsg("�����ع�����:");
            ResultCipherText resultCipherText0 = ResultCipherText.fromByteArray(sm9.getCurve(), resultCipherText.toByteArray());
            Main.showMsg("�ع��������:");
            Main.showMsg(resultCipherText0.toString());

            Main.showMsg("");
            Main.showMsg("�����㷨����B1-B5�е����ֵ:");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("���ܺ������M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("�ӽ��ܳɹ�");
            } else {
                Main.showMsg("�ӽ���ʧ��");
            }

            isBaseBlockCipher = true;
        }
    }

    public static void test_sm9_keyExchange_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9��Կ��������\n");


        String myId = "Alice";
        String othId = "Bob";

        KGCWithStandardTestKey.k = new BigInteger("02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
        MasterKeyPair masterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(masterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(masterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��A�ı�ʶIDA:");
        Main.showMsg(myId);
        Main.showMsg("IDA��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(myId.getBytes()));
        PrivateKey myPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), myId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("ʵ��A�ļ���˽Կ de_A:");
        Main.showMsg(myPrivateKey.toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(othId);
        Main.showMsg("IDB��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(othId.getBytes()));
        PrivateKey othPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), othId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("ʵ��B�ļ���˽Կ de_B:");
        Main.showMsg(othPrivateKey.toString());

        int keyByteLen = 16;
        Main.showMsg("��Կ�����ĳ���: " + keyByteLen + " bytes");

        Main.showMsg("��Կ��������A1-A4�е����ֵ:");
        SM9WithStandardTestKey.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        G1KeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), othId);

        Main.showMsg("��Կ��������B1-B8�е����ֵ:");
        SM9WithStandardTestKey.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        G1KeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), myId);

        ResultKeyExchange othAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), false,
                othId, myId, othPrivateKey, othTempKeyPair, myTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("��Կ��������A5-A8�е����ֵ:");
        ResultKeyExchange myAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), true,
                myId, othId, myPrivateKey, myTempKeyPair, othTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("A��");
        Main.showMsg("SA: "+SM9Utils.toHexString(myAgreementKey.getSA2()));
        Main.showMsg("S1: "+SM9Utils.toHexString(myAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(myAgreementKey.getSK()));

        Main.showMsg("B��");
        Main.showMsg("S2: "+SM9Utils.toHexString(othAgreementKey.getSA2()));
        Main.showMsg("SB: "+SM9Utils.toHexString(othAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(othAgreementKey.getSK()));

        boolean isSuccess = true;
        if(SM9Utils.byteEqual(myAgreementKey.getSA2(), othAgreementKey.getSA2()))
            Main.showMsg("SA = S2");
        else {
            Main.showMsg("SA != S2");
            isSuccess = false;
        }

        if(SM9Utils.byteEqual(myAgreementKey.getSB1(), othAgreementKey.getSB1()))
            Main.showMsg("S1 = SB");
        else {
            Main.showMsg("S1 != SB");
            isSuccess = false;
        }

        if(SM9Utils.byteEqual(myAgreementKey.getSK(), othAgreementKey.getSK()))
            Main.showMsg("SK_A = SK_B");
        else {
            Main.showMsg("SK_A != SK_B");
            isSuccess = false;
        }

        if(isSuccess)
            Main.showMsg("��Կ�����ɹ�");
        else
            Main.showMsg("��Կ����ʧ��");
    }

    public static void test_sm9_keyExchange_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9��Կ��������\n");


        String myId = "Alice";
        String othId = "Bob";

        KGCWithStandardTestKey.k = new BigInteger("02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
        MasterKeyPair masterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("������˽Կ ke:");
        Main.showMsg(masterKeyPair.getPrivateKey().toString());
        Main.showMsg("��������Կ Ppub-e:");
        Main.showMsg(masterKeyPair.getPublicKey().toString());

        Main.showMsg("ʵ��A�ı�ʶIDA:");
        Main.showMsg(myId);
        Main.showMsg("IDA��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(myId.getBytes()));
        PrivateKey myPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), myId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("ʵ��A�ļ���˽Կ de_A:");
        Main.showMsg(myPrivateKey.toString());

        Main.showMsg("ʵ��B�ı�ʶIDB:");
        Main.showMsg(othId);
        Main.showMsg("IDB��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(othId.getBytes()));
        PrivateKey othPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), othId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("ʵ��B�ļ���˽Կ de_B:");
        Main.showMsg(othPrivateKey.toString());

        int keyByteLen = 16;
        Main.showMsg("��Կ�����ĳ���: " + keyByteLen + " bytes");

        Main.showMsg("��Կ��������A1-A4�е����ֵ:");
        SM9WithStandardTestKey.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        G1KeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), othId);

        //G1��Կ���ع�����
        Main.showMsg("A��G1��Կ���ع�����");
        G1KeyPair myTempKeyPair0 = G1KeyPair.fromByteArray(sm9.getCurve(), myTempKeyPair.toByteArray());
        Main.showMsg("�ع����A��G1��Կ��");
        Main.showMsg(myTempKeyPair0.toString());

        Main.showMsg("��Կ��������B1-B8�е����ֵ:");
        SM9WithStandardTestKey.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        G1KeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), myId);


        ResultKeyExchange othAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), false,
                othId, myId, othPrivateKey, othTempKeyPair, myTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("��Կ��������A5-A8�е����ֵ:");
        ResultKeyExchange myAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), true,
                myId, othId, myPrivateKey, myTempKeyPair, othTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("A��");
        Main.showMsg("SA: "+SM9Utils.toHexString(myAgreementKey.getSA2()));
        Main.showMsg("S1: "+SM9Utils.toHexString(myAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(myAgreementKey.getSK()));

        Main.showMsg("B��");
        Main.showMsg("S2: "+SM9Utils.toHexString(othAgreementKey.getSA2()));
        Main.showMsg("SB: "+SM9Utils.toHexString(othAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(othAgreementKey.getSK()));

        boolean isSuccess = true;
        if(SM9Utils.byteEqual(myAgreementKey.getSA2(), othAgreementKey.getSA2()))
            Main.showMsg("SA = S2");
        else {
            Main.showMsg("SA != S2");
            isSuccess = false;
        }

        if(SM9Utils.byteEqual(myAgreementKey.getSB1(), othAgreementKey.getSB1()))
            Main.showMsg("S1 = SB");
        else {
            Main.showMsg("S1 != SB");
            isSuccess = false;
        }

        if(SM9Utils.byteEqual(myAgreementKey.getSK(), othAgreementKey.getSK()))
            Main.showMsg("SK_A = SK_B");
        else {
            Main.showMsg("SK_A != SK_B");
            isSuccess = false;
        }

        if(isSuccess)
            Main.showMsg("��Կ�����ɹ�");
        else
            Main.showMsg("��Կ����ʧ��");
    }

    public static void test_sm9_sign_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9ǩ������\n");

        String id_A = "Alice";

        Main.showMsg("ǩ������Կ���û�ǩ��˽Կ���������е����ֵ:");

        //����ǩ������Կ��
        KGCWithStandardTestKey.k= new BigInteger("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("ǩ����˽Կ ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("ǩ������Կ Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());

        //��ʾID��Ϣ
        Main.showMsg("ʵ��A�ı�ʶIDA:");
        Main.showMsg(id_A);
        Main.showMsg("IDA��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(id_A.getBytes()));

        //����ǩ��˽Կ
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("ǩ��˽Կ ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //ǩ��
        Main.showMsg("ǩ�������е����ֵ:");
        String msg = "Chinese IBS standard";
        Main.showMsg("��ǩ����Ϣ M:");
        Main.showMsg(msg);
        Main.showMsg("M��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        SM9WithStandardTestKey.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        ResultSignature signature = sm9.sign(signMasterKeyPair.getPublicKey(), signPrivateKey, msg.getBytes());
        Main.showMsg("��ϢM��ǩ��Ϊ(h,s):");
        Main.showMsg(signature.toString());


        //��ǩ
        Main.showMsg("��֤�����е����ֵ:");
        if(sm9.verify(signMasterKeyPair.getPublicKey(), id_A, msg.getBytes(), signature))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }

    public static void test_sm9_sign_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9ǩ������\n");

        String id_A = "Alice";

        Main.showMsg("ǩ������Կ���û�ǩ��˽Կ���������е����ֵ:");

        //����ǩ������Կ��
        KGCWithStandardTestKey.k= new BigInteger("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("ǩ����˽Կ ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("ǩ������Կ Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());
        Main.showMsg("ʵ��A�ı�ʶIDA:");
        Main.showMsg(id_A);
        Main.showMsg("IDA��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(id_A.getBytes()));


        //�ع�ǩ������Կ��
        Main.showMsg("����Կ���ع�����:");
        MasterKeyPair signMasterKeyPair0 = MasterKeyPair.fromByteArray(kgc.getCurve(), signMasterKeyPair.toByteArray());
        Main.showMsg("�ع��������Կ:");
        Main.showMsg(signMasterKeyPair0.toString());


        //����ǩ��˽Կ
        Main.showMsg("ʹ���ع����ǩ������Կ�Ե�˽Կ����ǩ��˽Կ:");
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair0.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("ǩ��˽Կ ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //�ع�ǩ������Կ
        Main.showMsg("ǩ������Կ�ع�����:");
        MasterPublicKey masterPublicKey = MasterPublicKey.fromByteArray(sm9.getCurve(), signMasterKeyPair.getPublicKey().toByteArray());
        Main.showMsg("�ع����ǩ������Կ:");
        Main.showMsg(masterPublicKey.toString());


        //�ع�ǩ��˽Կ
        Main.showMsg("ǩ��˽Կ�ع�����:");
        PrivateKey signPrivateKey0 = PrivateKey.fromByteArray(kgc.getCurve(), signPrivateKey.toByteArray());
        Main.showMsg("�ع����ǩ��˽Կ:");
        Main.showMsg(signPrivateKey0.toString());


        //ǩ��
        Main.showMsg("ʹ���ع����ǩ������Կ���ع����ǩ��˽Կ����ǩ��:");
        Main.showMsg("ǩ�������е����ֵ:");
        String msg = "Chinese IBS standard";
        Main.showMsg("��ǩ����Ϣ M:");
        Main.showMsg(msg);
        Main.showMsg("M��16���Ʊ�ʾ");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        SM9WithStandardTestKey.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        ResultSignature signature = sm9.sign(masterPublicKey, signPrivateKey0, msg.getBytes());
        Main.showMsg("��ϢM��ǩ��Ϊ(h,s):");
        Main.showMsg(signature.toString());


        //�ع�ǩ�����ֵ
        Main.showMsg("ǩ�����ֵ�ع�����:");
        ResultSignature signature1 = ResultSignature.fromByteArray(sm9.getCurve(), signature.toByteArray());
        Main.showMsg("�ع����ǩ��ֵ:");
        Main.showMsg(signature1.toString());


        //��ǩ
        Main.showMsg("ʹ���ع����ǩ������Կ���ع����ǩ��ֵ������ǩ:");
        Main.showMsg("��֤�����е����ֵ:");
        if(sm9.verify(masterPublicKey, id_A, msg.getBytes(), signature1))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }
}
