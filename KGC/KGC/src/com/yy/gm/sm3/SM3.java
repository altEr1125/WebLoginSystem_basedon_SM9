package com.yy.gm.sm3;

import com.yy.gm.GMProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class SM3 {
    public static final int DIGEST_SIZE = 32;

    private SM3()
    {
    }

    /**
     * Get MessageDigest object for SM3 algorithm instance.
     * @return SM3 MessageDigest object
     * @throws NoSuchAlgorithmException
     */
    public static MessageDigest getInstance() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SM3", GMProvider.getProvider());
    }
}
