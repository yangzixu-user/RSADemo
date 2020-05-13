package com.koal.rsa;

import java.security.interfaces.RSAPublicKey;

/**
 * @author yangxu@koal.com
 * @Title: MainTest
 * @ProjectName RSADemo
 * @Description: TODO
 * @create by 2020/5/1314:14
 */
public class MainTest {

    public static void main(String[] args) throws Exception{
        String filePath="D:/tmp/";

        System.out.println("==============公钥加密私钥解密过程===============");
        String plainText = "RSA_公钥加密私钥解密";
        //使用RSA算法获取密钥对
        RSAEncrypt.genKeyPair(filePath);
        //公钥加密过程
        //1.从文件中获取公钥
        String publicKeyByFile = RSAEncrypt.loadPublicKeyByFile(filePath);
        //2.通过公钥字符串获取公钥
        RSAPublicKey rsaPublicKey = RSAEncrypt.loadPublicKeyByStr(publicKeyByFile);
        //3.执行公钥加密操作
        byte[] cipherDate = RSAEncrypt.encrypt(rsaPublicKey, plainText.getBytes());
        String cipher = Base64.encode(cipherDate);
        //私钥解密过程
        byte[] res = RSAEncrypt.decrypt(RSAEncrypt.loadPrivateKeyByStr(RSAEncrypt.loadPrivateKeyByFile(filePath)), Base64.decode(cipher));
        String restr = new String(res);
        System.out.println("原文:"+plainText);
        System.out.println("加密:"+cipher);
        System.out.println("解密:"+restr);

        System.out.println("============RSA私钥加密公钥解密==============");
        plainText = "RSA_私钥加密公钥解密";
        //私钥加密过程
        cipherDate = RSAEncrypt.encrypt(RSAEncrypt.loadPrivateKeyByStr(RSAEncrypt.loadPrivateKeyByFile(filePath)), plainText.getBytes());
        cipher = Base64.encode(cipherDate);
        //公钥解密过程
        res = RSAEncrypt.decrypt(RSAEncrypt.loadPublicKeyByStr(RSAEncrypt.loadPublicKeyByFile(filePath)),Base64.decode(cipher));
        restr = new String (res);
        System.out.println("原文:"+plainText);
        System.out.println("加密:"+cipher);
        System.out.println("解密:"+restr);


        System.out.println("=================私钥签名过程===============");
        String content = "RSA_这是用于签名的原始数据";
        String signstr = RSASignature.sign(content,RSAEncrypt.loadPrivateKeyByFile(filePath));
        System.out.println("签名原数据："+content);
        System.out.println("签名数据："+signstr);
        System.out.println();
        System.out.println("=================公钥验证签名过程===============");
        System.out.println("签名原数据："+content);
        System.out.println("签名数据："+signstr);
        System.out.println("验签："+RSASignature.doCheck(content,signstr,RSAEncrypt.loadPublicKeyByFile(filePath)));
    }

}
