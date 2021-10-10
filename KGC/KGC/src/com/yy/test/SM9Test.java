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
        Main.showMsg("SM9密钥封装测试\n");

        String id_B = "Bob";

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        int keyByteLen = 32;
        Main.showMsg("密钥封装的长度: " + keyByteLen + " bytes");

        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);
        Main.showMsg("密钥封装结果:");
        Main.showMsg(keyEncapsulation.toString());

        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);
        Main.showMsg("解封后的密钥:");
        Main.showMsg(SM9Utils.toHexString(K));

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("测试成功");
        else
            Main.showMsg("测试失败");
    }

    public static void test_sm9_encrypt(KGC kgc, SM9 sm9,String [] type,String id_B,String msg) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9加解密测试\n");

//        String id_B = "Bob";
//        String msg = "Chinese IBE standard";

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
//        Main.showMsg("加密主私钥 ke:");
//        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
//        Main.showMsg("加密主公钥 Ppub-e:");
//        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
//        Main.showMsg("加密私钥 de_B:");
//        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("待加密消息 M:");
        Main.showMsg(msg);
//        Main.showMsg("消息M的长度: "+msg.length() + " bytes");
//        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
//        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            if(isBaseBlockCipher)
                Main.showMsg("加密明文的方法为分组密码算法 测试:");
            else
                Main.showMsg("加密明文的方法为基于KDF的序列密码 测试:");

            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("加密后的密文 C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));
            type[0]=SM9Utils.toHexString(resultCipherText.toByteArray());
            
            
            Main.showMsg("");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("解密后的明文M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("加解密成功");
            } else {
                Main.showMsg("加解密失败");
            }

            isBaseBlockCipher = true;
        }
        
    }

    public static byte[] encrypt(KGC kgc, SM9 sm9,MasterPublicKey masterPublicKey,String id_B,String msg) throws Exception {

        int macKeyByteLen = SM3.DIGEST_SIZE;

        boolean isBaseBlockCipher = false;

        ResultCipherText resultCipherText = sm9.encrypt(masterPublicKey, id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
        Main.showMsg("加密后的密文 C=C1||C3||C2:");
        Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));
        return resultCipherText.toByteArray();

    }
    
    public static void dencrypt(KGC kgc, SM9 sm9,String [] type,String id_B,String msg,PrivateKey encryptPrivateKey,ResultCipherText resultCipherText) throws Exception {

        int macKeyByteLen = SM3.DIGEST_SIZE;
        boolean isBaseBlockCipher = false;
        byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
        Main.showMsg("解密后的明文M':");
        Main.showMsg(new String(msgd));
        }
        
    
    public static void test_sm9_keyExchange(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9密钥交换测试\n");


        String myId = "Alice";
        String othId = "Bob";

        MasterKeyPair masterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(masterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(masterKeyPair.getPublicKey().toString());

        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(myId);
        PrivateKey myPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), myId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("实体A的加密私钥 de_A:");
        Main.showMsg(myPrivateKey.toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(othId);
        PrivateKey othPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), othId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("实体B的加密私钥 de_B:");
        Main.showMsg(othPrivateKey.toString());

        int keyByteLen = 16;
        Main.showMsg("密钥交换的长度: " + keyByteLen + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        G1KeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), othId);

        SM9WithStandardTestKey.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        G1KeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), myId);

        ResultKeyExchange othAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), false,
                othId, myId, othPrivateKey, othTempKeyPair, myTempKeyPair.getPublicKey(), keyByteLen);

        ResultKeyExchange myAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), true,
                myId, othId, myPrivateKey, myTempKeyPair, othTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("A方");
        Main.showMsg("SA: "+SM9Utils.toHexString(myAgreementKey.getSA2()));
        Main.showMsg("S1: "+SM9Utils.toHexString(myAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(myAgreementKey.getSK()));

        Main.showMsg("B方");
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
            Main.showMsg("密钥交换成功");
        else
            Main.showMsg("密钥交换失败");
    }

    public static void test_sm9_sign(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9签名测试\n");

        String id_A = "Alice";

        //生成签名主密钥对
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("签名主私钥 ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("签名主公钥 Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());

        //显示ID信息
        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(id_A);

        //生成签名私钥
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("签名私钥 ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //签名
        Main.showMsg("签名步骤中的相关值:");
        String msg = "Chinese IBS standard";
        Main.showMsg("待签名消息 M:");
        Main.showMsg(msg);

        ResultSignature signature = sm9.sign(signMasterKeyPair.getPublicKey(), signPrivateKey, msg.getBytes());
        Main.showMsg("消息M的签名为(h,s):");
        Main.showMsg(signature.toString());

        //验签
        if(sm9.verify(signMasterKeyPair.getPublicKey(), id_A, msg.getBytes(), signature))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }

    public static void test_sm9_keyEncap_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9密钥封装测试\n");

        String id_B = "Bob";

        Main.showMsg("加密主密钥和用户密钥产生过程中的相关值:");

        KGCWithStandardTestKey.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        int keyByteLen = 32;
        Main.showMsg("密钥封装的长度: " + keyByteLen + " bytes");

        Main.showMsg("密钥封装步骤A1-A7中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722", 16);
        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);

        Main.showMsg("解封装步骤B1-B4中的相关值:");
        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("测试成功");
        else
            Main.showMsg("测试失败");
    }

    public static void test_sm9_keyEncap_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9密钥封装测试\n");

        String id_B = "Bob";

        Main.showMsg("加密主密钥和用户密钥产生过程中的相关值:");
        KGCWithStandardTestKey.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());


        //重构签名主密钥对
        Main.showMsg("加密主私钥重构测试:");
        MasterPrivateKey encryptMasterPrivateKey = MasterPrivateKey.fromByteArray(encryptMasterKeyPair.getPrivateKey().toByteArray());
        Main.showMsg("重构后的加密主私钥:");
        Main.showMsg(encryptMasterPrivateKey.toString());


        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterPrivateKey, id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());


        //重构签名私钥
        Main.showMsg("加密私钥重构测试:");
        PrivateKey encryptPrivateKey0 = PrivateKey.fromByteArray(kgc.getCurve(), encryptPrivateKey.toByteArray());
        Main.showMsg("重构后的加密私钥:");
        Main.showMsg(encryptPrivateKey0.toString());


        int keyByteLen = 32;
        Main.showMsg("密钥封装的长度: " + keyByteLen + " bytes");


        Main.showMsg("密钥封装步骤A1-A7中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722", 16);
        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);
        Main.showMsg("密钥封装结果值:");
        Main.showMsg(keyEncapsulation.toString());

        //重构密钥密文
        Main.showMsg("重构密钥封装结果中的密钥密文:");
        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        Main.showMsg("重构后的密钥密文:");
        Main.showMsg(cipherText.toString());


        Main.showMsg("解封装步骤B1-B4中的相关值:");
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("测试成功");
        else
            Main.showMsg("测试失败");
    }

    public static void test_sm9_encrypt_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9加解密测试\n");

        String id_B = "Bob";
        String msg = "Chinese IBE standard";

        Main.showMsg("加密主密钥和用户加密密钥产生过程中的相关值:");

        KGCWithStandardTestKey.k= new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("待加密消息 M:");
        Main.showMsg(msg);
        Main.showMsg("M的16进制表示");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        Main.showMsg("消息M的长度: "+msg.length() + " bytes");
        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C", 16);

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            if(isBaseBlockCipher)
                Main.showMsg("加密明文的方法为分组密码算法 测试:");
            else
                Main.showMsg("加密明文的方法为基于KDF的序列密码 测试:");

            Main.showMsg("加密算法步骤A1-A8中的相关值:");
            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("密文 C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));

            Main.showMsg("");
            Main.showMsg("解密算法步骤B1-B5中的相关值:");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("解密后的明文M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("加解密成功");
            } else {
                Main.showMsg("加解密失败");
            }

            isBaseBlockCipher = true;
        }
    }

    public static void test_sm9_encrypt_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9加解密测试\n");

        String id_B = "Bob";
        String msg = "Chinese IBE standard";

        Main.showMsg("加密主密钥和用户加密密钥产生过程中的相关值:");

        KGCWithStandardTestKey.k= new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("待加密消息 M:");
        Main.showMsg(msg);
        Main.showMsg("M的16进制表示");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        Main.showMsg("消息M的长度: "+msg.length() + " bytes");
        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C", 16);

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            if(isBaseBlockCipher)
                Main.showMsg("加密明文的方法为分组密码算法 测试:");
            else
                Main.showMsg("加密明文的方法为基于KDF的序列密码 测试:");

            Main.showMsg("加密算法步骤A1-A8中的相关值:");
            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("密文 C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));

            //密文重构
            Main.showMsg("密文重构测试:");
            ResultCipherText resultCipherText0 = ResultCipherText.fromByteArray(sm9.getCurve(), resultCipherText.toByteArray());
            Main.showMsg("重构后的密文:");
            Main.showMsg(resultCipherText0.toString());

            Main.showMsg("");
            Main.showMsg("解密算法步骤B1-B5中的相关值:");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("解密后的明文M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("加解密成功");
            } else {
                Main.showMsg("加解密失败");
            }

            isBaseBlockCipher = true;
        }
    }

    public static void test_sm9_keyExchange_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9密钥交换测试\n");


        String myId = "Alice";
        String othId = "Bob";

        KGCWithStandardTestKey.k = new BigInteger("02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
        MasterKeyPair masterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(masterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(masterKeyPair.getPublicKey().toString());

        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(myId);
        Main.showMsg("IDA的16进制表示");
        Main.showMsg(SM9Utils.toHexString(myId.getBytes()));
        PrivateKey myPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), myId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("实体A的加密私钥 de_A:");
        Main.showMsg(myPrivateKey.toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(othId);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(othId.getBytes()));
        PrivateKey othPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), othId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("实体B的加密私钥 de_B:");
        Main.showMsg(othPrivateKey.toString());

        int keyByteLen = 16;
        Main.showMsg("密钥交换的长度: " + keyByteLen + " bytes");

        Main.showMsg("密钥交换步骤A1-A4中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        G1KeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), othId);

        Main.showMsg("密钥交换步骤B1-B8中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        G1KeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), myId);

        ResultKeyExchange othAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), false,
                othId, myId, othPrivateKey, othTempKeyPair, myTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("密钥交换步骤A5-A8中的相关值:");
        ResultKeyExchange myAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), true,
                myId, othId, myPrivateKey, myTempKeyPair, othTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("A方");
        Main.showMsg("SA: "+SM9Utils.toHexString(myAgreementKey.getSA2()));
        Main.showMsg("S1: "+SM9Utils.toHexString(myAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(myAgreementKey.getSK()));

        Main.showMsg("B方");
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
            Main.showMsg("密钥交换成功");
        else
            Main.showMsg("密钥交换失败");
    }

    public static void test_sm9_keyExchange_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9密钥交换测试\n");


        String myId = "Alice";
        String othId = "Bob";

        KGCWithStandardTestKey.k = new BigInteger("02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
        MasterKeyPair masterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(masterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(masterKeyPair.getPublicKey().toString());

        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(myId);
        Main.showMsg("IDA的16进制表示");
        Main.showMsg(SM9Utils.toHexString(myId.getBytes()));
        PrivateKey myPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), myId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("实体A的加密私钥 de_A:");
        Main.showMsg(myPrivateKey.toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(othId);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(othId.getBytes()));
        PrivateKey othPrivateKey = kgc.genPrivateKey(masterKeyPair.getPrivateKey(), othId, PrivateKeyType.KEY_KEY_EXCHANGE);
        Main.showMsg("实体B的加密私钥 de_B:");
        Main.showMsg(othPrivateKey.toString());

        int keyByteLen = 16;
        Main.showMsg("密钥交换的长度: " + keyByteLen + " bytes");

        Main.showMsg("密钥交换步骤A1-A4中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        G1KeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), othId);

        //G1密钥对重构测试
        Main.showMsg("A方G1密钥对重构测试");
        G1KeyPair myTempKeyPair0 = G1KeyPair.fromByteArray(sm9.getCurve(), myTempKeyPair.toByteArray());
        Main.showMsg("重构后的A方G1密钥对");
        Main.showMsg(myTempKeyPair0.toString());

        Main.showMsg("密钥交换步骤B1-B8中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        G1KeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublicKey(), myId);


        ResultKeyExchange othAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), false,
                othId, myId, othPrivateKey, othTempKeyPair, myTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("密钥交换步骤A5-A8中的相关值:");
        ResultKeyExchange myAgreementKey = sm9.keyExchange(masterKeyPair.getPublicKey(), true,
                myId, othId, myPrivateKey, myTempKeyPair, othTempKeyPair.getPublicKey(), keyByteLen);

        Main.showMsg("A方");
        Main.showMsg("SA: "+SM9Utils.toHexString(myAgreementKey.getSA2()));
        Main.showMsg("S1: "+SM9Utils.toHexString(myAgreementKey.getSB1()));
        Main.showMsg("SK: "+SM9Utils.toHexString(myAgreementKey.getSK()));

        Main.showMsg("B方");
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
            Main.showMsg("密钥交换成功");
        else
            Main.showMsg("密钥交换失败");
    }

    public static void test_sm9_sign_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9签名测试\n");

        String id_A = "Alice";

        Main.showMsg("签名主密钥和用户签名私钥产生过程中的相关值:");

        //生成签名主密钥对
        KGCWithStandardTestKey.k= new BigInteger("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("签名主私钥 ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("签名主公钥 Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());

        //显示ID信息
        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(id_A);
        Main.showMsg("IDA的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_A.getBytes()));

        //生成签名私钥
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("签名私钥 ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //签名
        Main.showMsg("签名步骤中的相关值:");
        String msg = "Chinese IBS standard";
        Main.showMsg("待签名消息 M:");
        Main.showMsg(msg);
        Main.showMsg("M的16进制表示");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        SM9WithStandardTestKey.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        ResultSignature signature = sm9.sign(signMasterKeyPair.getPublicKey(), signPrivateKey, msg.getBytes());
        Main.showMsg("消息M的签名为(h,s):");
        Main.showMsg(signature.toString());


        //验签
        Main.showMsg("验证步骤中的相关值:");
        if(sm9.verify(signMasterKeyPair.getPublicKey(), id_A, msg.getBytes(), signature))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }

    public static void test_sm9_sign_re(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9签名测试\n");

        String id_A = "Alice";

        Main.showMsg("签名主密钥和用户签名私钥产生过程中的相关值:");

        //生成签名主密钥对
        KGCWithStandardTestKey.k= new BigInteger("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("签名主私钥 ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("签名主公钥 Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());
        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(id_A);
        Main.showMsg("IDA的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_A.getBytes()));


        //重构签名主密钥对
        Main.showMsg("主密钥对重构测试:");
        MasterKeyPair signMasterKeyPair0 = MasterKeyPair.fromByteArray(kgc.getCurve(), signMasterKeyPair.toByteArray());
        Main.showMsg("重构后的主密钥:");
        Main.showMsg(signMasterKeyPair0.toString());


        //生成签名私钥
        Main.showMsg("使用重构后的签名主密钥对的私钥生成签名私钥:");
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair0.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("签名私钥 ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //重构签名主公钥
        Main.showMsg("签名主公钥重构测试:");
        MasterPublicKey masterPublicKey = MasterPublicKey.fromByteArray(sm9.getCurve(), signMasterKeyPair.getPublicKey().toByteArray());
        Main.showMsg("重构后的签名主公钥:");
        Main.showMsg(masterPublicKey.toString());


        //重构签名私钥
        Main.showMsg("签名私钥重构测试:");
        PrivateKey signPrivateKey0 = PrivateKey.fromByteArray(kgc.getCurve(), signPrivateKey.toByteArray());
        Main.showMsg("重构后的签名私钥:");
        Main.showMsg(signPrivateKey0.toString());


        //签名
        Main.showMsg("使用重构后的签名主公钥和重构后的签名私钥进行签名:");
        Main.showMsg("签名步骤中的相关值:");
        String msg = "Chinese IBS standard";
        Main.showMsg("待签名消息 M:");
        Main.showMsg(msg);
        Main.showMsg("M的16进制表示");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        SM9WithStandardTestKey.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        ResultSignature signature = sm9.sign(masterPublicKey, signPrivateKey0, msg.getBytes());
        Main.showMsg("消息M的签名为(h,s):");
        Main.showMsg(signature.toString());


        //重构签名结果值
        Main.showMsg("签名结果值重构测试:");
        ResultSignature signature1 = ResultSignature.fromByteArray(sm9.getCurve(), signature.toByteArray());
        Main.showMsg("重构后的签名值:");
        Main.showMsg(signature1.toString());


        //验签
        Main.showMsg("使用重构后的签名主公钥和重构后的签名值进行验签:");
        Main.showMsg("验证步骤中的相关值:");
        if(sm9.verify(masterPublicKey, id_A, msg.getBytes(), signature1))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }
}
