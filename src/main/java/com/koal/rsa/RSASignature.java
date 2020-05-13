package com.koal.rsa;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author yangxu@koal.com
 * @Title: RSASignature
 * @ProjectName RSADemo
 * @Description: TODO
 * @create by 2020/5/1313:21
 */
public class RSASignature {
    /**
     * 签名算法
     */
    public static final String SIGN_ALGORITHMS = "SHA1WithRSA";

    /**
     * RSA签名
     * @param content 待签名数据
     * @param privateKey 商户私钥
     * @param encode 字符集编码
     * @return 签名值
     */
    public static String sign(String content,String privateKey,String encode){
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.getEncoder().encode(privateKey.getBytes()));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            //设置签名时的使用私钥
            signature.initSign(priKey);
            //获取代签名数据的字节文件
            signature.update(content.getBytes(encode));
            //签名的数据
            byte[] signed = signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥签名的无需字符集
     * @param content
     * @param privateKey
     * @return
     */
    public static String sign(String content,String privateKey){
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey prikey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(prikey);
            signature.update(content.getBytes());
            byte[] signed = signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA 签名检查
     * @param content 代签名的数据
     * @param sign 签名数值
     * @param publicKey 分配给开发商的公钥
     * @param encode 字符编码集
     * @return 布尔值
     */
    public static boolean doCheck(String content,String sign ,String publicKey,String encode){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.getDecoder().decode(publicKey);
            //获取公钥证书标准规范
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            Signature signature  = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initVerify(pubKey);
            signature.update(content.getBytes());
            boolean bverify = signature.verify(Base64.getDecoder().decode(sign));
            return bverify;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 公钥验签不用指定字符集
     * @param content 代签名数据
     * @param sign 签名值
     * @param publicKey 提供给商户的公钥
     * @return 布尔值
     */
    public static boolean doCheck(String content,String sign ,String publicKey){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] ecodedKey = Base64.getDecoder().decode(publicKey);
            PublicKey pubkey = keyFactory.generatePublic(new X509EncodedKeySpec(ecodedKey));
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initVerify(pubkey);
            signature.update(content.getBytes());
            boolean bverify = signature.verify(Base64.getDecoder().decode(sign));
            return bverify;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
