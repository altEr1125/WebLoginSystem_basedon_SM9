package com.yy.gm.sm9;

public enum PrivateKeyType {
    /** SM9 signed private key. */
    KEY_SIGN,
    /** SM9 key exchange private key(also is a encrypted private key). */
    KEY_KEY_EXCHANGE,
    /** SM9 encrypted private key. */
    KEY_ENCRYPT
}
