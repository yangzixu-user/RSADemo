package com.koal.cert;

import com.koal.rsa.Base64;


import java.io.File;
import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author yangxu@koal.com
 * @Title: CertManager
 * @ProjectName RSADemo
 * @Description: TODO
 * @create by 2020/5/1316:46
 */
public class CertManager {
    //认证公司证书
    public static void main(String[] args) throws Exception{

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream( new File("D:/my.cer/")));
        PublicKey publicKey = cert.getPublicKey();
        String encode = Base64.encode(publicKey.getEncoded());
        System.out.println("=========================证书info==================");
        System.out.println("版本号:"+cert.getVersion());
        System.out.println("证书序列号:"+cert.getSerialNumber());
        System.out.println("签名算法:"+cert.getSigAlgName());
        System.out.println("签名哈希算法");
        System.out.println("颁发者DN:"+cert.getIssuerDN().getName());
        System.out.println("有效期"+cert.getNotBefore());
        System.out.println("到"+cert.getNotAfter());
        System.out.println("使用者DN:"+cert.getSubjectDN());
        System.out.println("公钥:"+publicKey);
        System.out.println(cert.getExtensionValue("2.5.29.19"));
        System.out.println(cert.getCriticalExtensionOIDs());
        System.out.println(cert.getNonCriticalExtensionOIDs());

        System.out.println("=====================扩展项==========================");
        System.out.println("颁发机构密钥标示符:");
        System.out.println("使用者密钥标示符:");
        System.out.println("使用者备用名称:");
        System.out.println("增强密钥用法:");
        System.out.println("证书认证策略:");
        System.out.println("颁发机构信息访问:");
        System.out.println("基本约束:");
        System.out.println("密钥用法:");
        System.out.println("指纹算法:");
        System.out.println("指纹:");
        System.out.println(encode);
    }


}
