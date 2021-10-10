package com.yy.gm.sm9;

import com.yy.Main;

import java.math.BigInteger;

import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;


public class KGCWithStandardTestKey extends KGC {
    public static BigInteger k = BigInteger.ONE;

    public KGCWithStandardTestKey(SM9Curve curve) {
        super(curve);
    }

    @Override
    public MasterKeyPair genSignMasterKeyPair()
    {
//        BigInteger ks = SM9Utils.genRandom(mCurve.getRandom(), mCurve.N);
        BigInteger ks = KGCWithStandardTestKey.k;
        CurveElement ppubs = mCurve.P2.duplicate().mul(ks);
        return new MasterKeyPair(new MasterPrivateKey(ks), new MasterPublicKey(ppubs, true));
    }

    @Override
    public MasterKeyPair genEncryptMasterKeyPair()
    {
//        BigInteger ke = SM9Utils.genRandom(mCurve.random, mCurve.N);
        BigInteger ke = KGCWithStandardTestKey.k;
        CurveElement ppube = mCurve.P1.duplicate().mul(ke);
        return new MasterKeyPair(new MasterPrivateKey(ke), new MasterPublicKey(ppube, false));
    }

    @Override
    protected BigInteger T2(MasterPrivateKey privateKey, String id, byte hid) throws Exception {
        BigInteger h1 = SM9Utils.H1(id, hid, mCurve.N);

        Main.showMsg("H1:");
        Main.showMsg(SM9Utils.toHexString(SM9Utils.BigIntegerToBytes(h1)));

        BigInteger t1 = h1.add(privateKey.d).mod(mCurve.N);
        if(t1.equals(BigInteger.ZERO))
            throw new Exception("Need to update the master private key");

        Main.showMsg("t1:");
        Main.showMsg(SM9Utils.toHexString(SM9Utils.BigIntegerToBytes(t1)));

        return privateKey.d.multiply(t1.modInverse(mCurve.N)).mod(mCurve.N);
    }

    @Override
    PrivateKey genSignPrivateKey(MasterPrivateKey privateKey, String id) throws Exception {
        BigInteger t2 = T2(privateKey, id, SM9Curve.HID_SIGN);

        Main.showMsg("t2:");
        Main.showMsg(SM9Utils.toHexString(SM9Utils.BigIntegerToBytes(t2)));

        CurveElement ds = mCurve.P1.duplicate().mul(t2);
        return new PrivateKey(ds, SM9Curve.HID_SIGN);
    }

    @Override
    PrivateKey genEncryptPrivateKey(MasterPrivateKey privateKey, String id, byte hid) throws Exception {
        BigInteger t2 = T2(privateKey, id, hid);

        Main.showMsg("t2:");
        Main.showMsg(SM9Utils.toHexString(SM9Utils.BigIntegerToBytes(t2)));

        CurveElement de = mCurve.P2.duplicate().mul(t2);
        return new PrivateKey(de, hid);
    }
}
