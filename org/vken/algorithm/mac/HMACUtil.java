package vken.algorithm.mac;
import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
/**
 * Created by vkenchen on 17/3/10.
 */

public class HMACUtil {
    /**
     * 初始化HmacMD5的密钥
     * @return byte[] 密钥
     *
     * */
    public static byte[] initHmacMD5Key() throws Exception{
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacMD5");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacMD5消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacMD5(byte[] data,byte[] key) throws Exception{
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacMD5");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }

///////////////////////////////HmacSHA1//////////////////////////////////
    /**
     * 初始化HmacSHA1的密钥
     * @return byte[] 密钥
     *
     * */
    public static byte[] initHmacSHAKey() throws Exception{
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacSHA1");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacSHA1消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacSHA(byte[] data,byte[] key) throws Exception{
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacSHA1");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }

///////////////////////////////HmacSHA256//////////////////////////////////
    /**
     * 初始化HmacSHA256的密钥
     * @return byte[] 密钥
     *
     * */
    public static byte[] initHmacSHA256Key() throws Exception{
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacSHA256");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacSHA256消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacSHA256(byte[] data,byte[] key) throws Exception{
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacSHA256");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }

///////////////////////////////HmacSHA384//////////////////////////////////
    /**
     * 初始化HmacSHA384的密钥
     * @return byte[] 密钥
     *
     * */
    public static byte[] initHmacSHA384Key() throws Exception{
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacSHA384");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacSHA384消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacSHA384(byte[] data,byte[] key) throws Exception{
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacSHA384");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }

///////////////////////////////HmacSHA512//////////////////////////////////
    /**
     * 初始化HmacSHA512的密钥
     * @return byte[] 密钥
     *
     * */
    public static byte[] initHmacSHA512Key() throws Exception{
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacSHA512");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacSHA512消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacSHA512(byte[] data,byte[] key) throws Exception{
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacSHA512");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }
///////////////////////////////HmacMD2-BouncyCastle才支持的实现//////////////////////////////////
    /**
     * 初始化HmacMD2的密钥
     * @return byte[] 密钥
     * */
    public static byte[] initHmacMD2Key() throws Exception{

        //加入BouncyCastleProvider的支持
        Security.addProvider(new BouncyCastleProvider());
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacMD2");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacMD2消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacMD2(byte[] data,byte[] key) throws Exception{
        //加入BouncyCastleProvider的支持
        Security.addProvider(new BouncyCastleProvider());
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacMD2");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }
    /**
     * HmacMD2Hex消息摘要
     * @param data 待做消息摘要处理的数据
     * @param key 密钥
     * @return byte[] 消息摘要
     * */
    public static String encodeHmacMD2Hex(byte[] data,byte[] key) throws Exception{
        //执行消息摘要处理
        byte[] b=encodeHmacMD2(data, key);
        //做十六进制转换
        return new String(Hex.encode(b));
    }

///////////////////////////////HmacMD4-BouncyCastle才支持的实现//////////////////////////////////
    /**
     * 初始化HmacMD2的密钥
     * @return byte[] 密钥
     * */
    public static byte[] initHmacMD4Key() throws Exception{

        //加入BouncyCastleProvider的支持
        Security.addProvider(new BouncyCastleProvider());
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacMD4");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacMD4消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacMD4(byte[] data,byte[] key) throws Exception{
        //加入BouncyCastleProvider的支持
        Security.addProvider(new BouncyCastleProvider());
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacMD4");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }
    /**
     * HmacMD4Hex消息摘要
     * @param data 待做消息摘要处理的数据
     * @param key 密钥
     * @return byte[] 消息摘要
     * */
    public static String encodeHmacMD4Hex(byte[] data,byte[] key) throws Exception{
        //执行消息摘要处理
        byte[] b=encodeHmacMD4(data, key);
        //做十六进制转换
        return new String(Hex.encode(b));
    }
///////////////////////////////HmacSHA224-BouncyCastle才支持的实现//////////////////////////////////
    /**
     * 初始化HmacSHA224的密钥
     * @return byte[] 密钥
     * */
    public static byte[] initHmacSHA224Key() throws Exception{

        //加入BouncyCastleProvider的支持
        Security.addProvider(new BouncyCastleProvider());
        //初始化KeyGenerator
        KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacSHA224");
        //产生密钥
        SecretKey secretKey=keyGenerator.generateKey();
        //获取密钥
        return secretKey.getEncoded();
    }
    /**
     * HmacSHA224消息摘要
     * @param data 待做摘要处理的数据
     * @param key 密钥
     * @return  byte[] 消息摘要
     * */
    public static byte[] encodeHmacSHA224(byte[] data,byte[] key) throws Exception{
        //加入BouncyCastleProvider的支持
        Security.addProvider(new BouncyCastleProvider());
        //还原密钥，因为密钥是以byte形式为消息传递算法所拥有
        SecretKey secretKey=new SecretKeySpec(key,"HmacSHA224");
        //实例化Mac
        Mac mac=Mac.getInstance(secretKey.getAlgorithm());
        //初始化Mac
        mac.init(secretKey);
        //执行消息摘要处理
        return mac.doFinal(data);
    }
    /**
     * HmacSHA224Hex消息摘要
     * @param data 待做消息摘要处理的数据
     * @param key 密钥
     * @return byte[] 消息摘要
     * */
    public static String encodeHmacSHA224Hex(byte[] data,byte[] key) throws Exception{
        //执行消息摘要处理
        byte[] b=encodeHmacSHA224(data,key);
        //做十六进制转换
        return new String(Hex.encode(b));
    }

}
