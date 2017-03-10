package vken.algorithm.md;


import java.security.MessageDigest;

/**
 * Created by vkenchen on 17/3/10.
 */
public class SHAUtil {

    public static String bytes2Hex(byte[] bts) {
        String des = "";
        String tmp = null;
        for (int i = 0; i < bts.length; i++) {
            tmp = (Integer.toHexString(bts[i] & 0xFF));
            if (tmp.length() == 1) {
                des += "0";
            }
            des += tmp;
        }
        return des;
    }

    public static String SHA1(String src) {
        return baseSHA(src, "SHA-1");
    }

    public static String SHA256(String src) {
        return baseSHA(src, "SHA-256");
    }

    public static String SHA384(String src) {
        return baseSHA(src, "SHA-384");
    }

    public static String SHA512(String src) {
        return baseSHA(src, "SHA-512");
    }


    private static String baseSHA(String src, String algorithm) {
        MessageDigest md = null;
        String strDes = null;
        byte[] bt = src.getBytes();
        try {
            md = MessageDigest.getInstance(algorithm);// 将此换成SHA-1、SHA-512、SHA-384等参数
            md.update(bt);
            strDes = bytes2Hex(md.digest()); // to HexString
            return strDes;
        } catch (Throwable e) {
            return null;
        }
    }

}
