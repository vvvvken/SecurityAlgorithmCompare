package vken.algorithm.md;

import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;

/**
 * Created by vkenchen on 17/3/9.
 */
public class MDUtil {

    //bouncy castle实现md2方式
    public static String bcMd2(String src) {
        MD2Digest md2Digest = new MD2Digest();
        md2Digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] md2bytes = new byte[md2Digest.getDigestSize()];
        md2Digest.doFinal(md2bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(md2bytes);
    }

    //bouncy castle实现md4方式
    public static String bcMd4(String src) {
        MD4Digest md4Digest = new MD4Digest();
        md4Digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] md4bytes = new byte[md4Digest.getDigestSize()];
        md4Digest.doFinal(md4bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(md4bytes);
    }

    //bouncy castle实现md5方式
    public static String bcMd5(String src) {
        MD5Digest md5Digest = new MD5Digest();
        md5Digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] md5bytes = new byte[md5Digest.getDigestSize()];
        md5Digest.doFinal(md5bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(md5bytes);
    }
}
