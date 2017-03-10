package vken.tester;

import vken.algorithm.mac.HMACUtil;

/**
 * Created by vkenchen on 17/3/10.
 */
public class HMACTester {

    /**
     * 进行相关的摘要算法的处理展示
     * @throws Exception
     * **/
    public static void main(String[] args) throws Exception {
        HMACComparer comparer = new HMACComparer();
        String datak = "Parse the JWE representation to extract the serialized values for the components of the JWE. When using the JWE Compact Serialization, these components are the base64url-encoded representations of the JWE Protected Header, the JWE Encrypted Key, the JWE Initialization Vector, the JWE Ciphertext, and the JWE Authentication Tag, and when using the JWE JSON Serialization, these components also include the base64url-encoded representation of the JWE AAD and the unencoded JWE Shared Unprotected Header and JWE Per-Recipient Unprotected Header values. When using the JWE Compact Serialization, the JWE Protected Header, the JWE Encrypted Key, the JWE Initialization Vector, the JWE Ciphertext, and the JWE Authentication Tag are represented as base64url-encoded values in that order, with each value being separated from the next by a single period ('.') character, resulting in exactly four delimiting period characters being used. The JWE JSON Serialization is described in ";
/*        comparer.compare(datak.getBytes(),10);
        comparer.compare(datak.getBytes(),100);
        comparer.compare(datak.getBytes(),1000);
        comparer.compare(datak.getBytes(),10000);*/
        comparer.compare(datak.getBytes(),10000);
        comparer.compare(datak.getBytes(),100000);
    }
}
