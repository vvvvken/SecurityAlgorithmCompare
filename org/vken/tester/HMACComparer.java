package vken.tester;

import vken.algorithm.mac.HMACUtil;
import vken.comparer.Comparer;
import vken.comparer.ICompareCell;

/**
 * Created by vkenchen on 17/3/10.
 */
public class HMACComparer extends Comparer {

    public class HMACMD2 implements ICompareCell {
        private byte[] key = null;

        public HMACMD2() {
            try {
                key = HMACUtil.initHmacMD2Key();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacMD2(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-MD2";
        }
    }

    public class HMACMD4 implements ICompareCell {
        private byte[] key = null;

        public HMACMD4() {
            try {
                key = HMACUtil.initHmacMD4Key();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacMD4(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-MD4";
        }
    }

    public class HMACMD5 implements ICompareCell {
        private byte[] key = null;

        public HMACMD5() {
            try {
                key = HMACUtil.initHmacMD5Key();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacMD5(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-MD5";
        }
    }




    public class HMACSHA1 implements ICompareCell {
        private byte[] key = null;

        public HMACSHA1() {
            try {
                key = HMACUtil.initHmacSHAKey();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacSHA(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-SHA1";
        }
    }

    public class HMACSHA256 implements ICompareCell {
        private byte[] key = null;

        public HMACSHA256() {
            try {
                key = HMACUtil.initHmacSHA256Key();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacSHA256(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-SHA256";
        }
    }

    public class HMACSHA384 implements ICompareCell {
        private byte[] key = null;

        public HMACSHA384() {
            try {
                key = HMACUtil.initHmacSHA384Key();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacSHA384(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-SHA384";
        }
    }

    public class HMACSHA512 implements ICompareCell {
        private byte[] key = null;

        public HMACSHA512() {
            try {
                key = HMACUtil.initHmacSHA512Key();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void operation(byte[] data) {
            try {
                //获取摘要信息
                byte[] data1 = HMACUtil.encodeHmacSHA512(data, key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String cellName() {
            return "HMAC-SHA512";
        }
    }


    public HMACComparer() {
        addCell(new HMACMD2());
        addCell(new HMACMD4());
        addCell(new HMACMD5());
        addCell(new HMACSHA1());
        addCell(new HMACSHA256());
        addCell(new HMACSHA384());
        addCell(new HMACSHA512());
    }

}
