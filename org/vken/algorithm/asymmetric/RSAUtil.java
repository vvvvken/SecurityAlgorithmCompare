package vken.algorithm.asymmetric;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Arrays;

/**
 * Created by vkenchen on 17/3/10.
 */
public class RSAUtil {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM_ECB1 = "RSA/ECB/PKCS1Padding";


    static PublicKey publicKey;
    static PrivateKey privateKey;
    static Cipher cipher;
    static KeyPair keyPair;


    static void encrypt(String str) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); //公钥加密
        byte[] encrypt = cipher.doFinal(str.getBytes());
        System.out.println("公钥加密后1：" + Arrays.toString(encrypt));

        cipher.init(Cipher.DECRYPT_MODE, privateKey);//私钥解密
        byte[] decrypt = cipher.doFinal(encrypt);
        System.out.println("私钥解密后1：" + new String(decrypt));
    }

    static void decrypt(String str) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); //公钥加密
        byte[] encrypt = cipher.doFinal(str.getBytes());
        System.out.println("公钥加密后1：" + Arrays.toString(encrypt));

        cipher.init(Cipher.DECRYPT_MODE, privateKey);//私钥解密
        byte[] decrypt = cipher.doFinal(encrypt);
        System.out.println("私钥解密后1：" + new String(decrypt));
    }
}
