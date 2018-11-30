package com.mlq.sm;

import java.io.IOException;  
import java.math.BigInteger;
import java.util.Base64;

import com.sun.deploy.util.StringUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;  
import org.bouncycastle.crypto.params.ECPublicKeyParameters;  
import org.bouncycastle.math.ec.ECPoint; 

public class SM2Utils {

    static String hexPrivateKey;
    static String hexPublicKey;

	  //生成随机秘钥对  
    public static void generateKeyPair(){
        byte[] raw = Base64.getDecoder().decode("MHcCAQEEINigrH6TwNcBOfATr5J8FfnNZhp8UFodnLu++AhhYnHQoAoGCCqBHM9V" +
                "AYItoUQDQgAEJ/HyI+zwnL15oxHpaA9xVlTEBX8AjBNpCKO6HgMhaReM9TU81VQ2" +
                "ep/rU5fpKzeeEvKvZs0eg/E/E3/Maze9wQ==");
        System.out.println(new String(Util.hexStringToBytes("30770201010420")));
        System.out.println(new String(Util.hexStringToBytes("A00A06082A811CCF5501822DA144034200")));

        System.out.println(Util.byteToHex(raw));
        for(int i = 0; i < 2; i++) {
            SM2 sm2 = SM2.Instance();
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
            BigInteger privateKey = ecpriv.getD();
            ECPoint publicKey = ecpub.getQ();

            hexPrivateKey = Util.byteToHex(privateKey.toByteArray());
            hexPublicKey = Util.byteToHex(publicKey.getEncoded());

            System.out.println(privateKey.toString(16).length());
            System.out.println(privateKey.toString(16));
            System.out.println(hexPrivateKey);

            if((privateKey.toString(16).length() >= 64)
                    && (privateKey.toString(16).charAt(0) - '0') >= 8){
                System.out.println(hexPrivateKey.length() > 64);
            }
            else
            {
                System.out.println(hexPrivateKey.length() == 64);
            }
            System.out.println();


        }
    }
      
    //数据加密  
    public static String encrypt(byte[] publicKey, byte[] data) throws IOException  
    {  
        if (publicKey == null || publicKey.length == 0)  
        {  
            return null;  
        }  
          
        if (data == null || data.length == 0)  
        {  
            return null;  
        }  
          
        byte[] source = new byte[data.length];  
        System.arraycopy(data, 0, source, 0, data.length);  
          
        Cipher cipher = new Cipher();  
        SM2 sm2 = SM2.Instance();  
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);  
          
        ECPoint c1 = cipher.Init_enc(sm2, userKey);  
        cipher.Encrypt(source);  
        byte[] c3 = new byte[32];  
        cipher.Dofinal(c3);  
          
//      System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));  
//      System.out.println("C2 " + Util.byteToHex(source));  
//      System.out.println("C3 " + Util.byteToHex(c3));  
        //C1 C2 C3拼装成加密字串  
        return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);  
          
    }  
      
    //数据解密  
    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException  
    {  
        if (privateKey == null || privateKey.length == 0)  
        {  
            return null;  
        }  
          
        if (encryptedData == null || encryptedData.length == 0)  
        {  
            return null;  
        }  
        //加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2  
        String data = Util.byteToHex(encryptedData);  
        /***分解加密字串 
         * （C1 = C1标志位2位 + C1实体部分128位 = 130） 
         * （C3 = C3实体部分64位  = 64） 
         * （C2 = encryptedData.length * 2 - C1长度  - C2长度） 
         */  
        byte[] c1Bytes = Util.hexToByte(data.substring(0,130));  
        int c2Len = encryptedData.length - 97;  
        byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));  
        byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));  
          
        SM2 sm2 = SM2.Instance();  
        BigInteger userD = new BigInteger(1, privateKey);  
          
        //通过C1实体字节来生成ECPoint  
        ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);  
        Cipher cipher = new Cipher();  
        cipher.Init_dec(userD, c1);  
        cipher.Decrypt(c2);  
        cipher.Dofinal(c3);  
          
        //返回解密结果  
        return c2;  
    }  
      
    public static void main(String[] args) throws Exception   
    {  
        //生成密钥对  
        generateKeyPair();  
          
        String plainText = "ererfeiisgod";  
        byte[] sourceData = plainText.getBytes();

        {
            System.out.println("加密: ");
            String cipherText = SM2Utils.encrypt(Util.hexToByte(hexPublicKey), sourceData);
            System.out.println(cipherText);
            System.out.println("解密: ");
            plainText = new String(SM2Utils.decrypt(Util.hexToByte(hexPrivateKey), Util.hexToByte(cipherText)));

            System.out.println(plainText);
        }

        {
            // key generated by openssl
            String prik = (
            "d8:a0:ac:7e:93:c0:d7:01:39:f0:13:af:92:7c:15:"+
            "f9:cd:66:1a:7c:50:5a:1d:9c:bb:be:f8:08:61:62:"+
            "71:d0").replaceAll(" ", "").replaceAll(":", "").toUpperCase();
            String pubk = (
                    "04:27:f1:f2:23:ec:f0:9c:bd:79:a3:11:e9:68:0f:" +
            "71:56:54:c4:05:7f:00:8c:13:69:08:a3:ba:1e:03:"+
            "21:69:17:8c:f5:35:3c:d5:54:36:7a:9f:eb:53:97:"+
            "e9:2b:37:9e:12:f2:af:66:cd:1e:83:f1:3f:13:7f:"+
            "cc:6b:37:bd:c1"
                ).replaceAll(" ", "").replaceAll(":", "").toUpperCase();

            System.out.println("加密: ");
            String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
            System.out.println(cipherText);
            System.out.println("解密: ");
            plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(cipherText)));

            System.out.println(plainText);
        }
    }  
}
