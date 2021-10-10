package com.yy.gm.sm4;

import com.yy.gm.GMProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public final class SM4 {
    public static final int KEY_BYTE_LENGTH = 16;
    public static final String ALGORITHM_NAME= "SM4";

    private SM4() {
    }

    public static byte[] ecbCrypt(boolean isEncrypt, byte[] key,  byte[] data, int offset, int length) throws Exception
    {
        byte[] cipherText;

            try {
                SecretKey secretKey = new SecretKeySpec(key, ALGORITHM_NAME);

                Cipher cipher = Cipher.getInstance(getAlgorithm() + "/ECB/PKCS5Padding", getCipherProvider());
                if(isEncrypt)
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                else
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);

                cipherText = cipher.doFinal(data);

            } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException
                    | NoSuchPaddingException | IllegalBlockSizeException e) {
                throw new Exception("SM4 ECB crypt failed." + e.getMessage());
            }

        return cipherText;
    }

    public static Provider getCipherProvider() {
        return GMProvider.getProvider();
    }

    public static String getAlgorithm() {
        return ALGORITHM_NAME;
    }


}
