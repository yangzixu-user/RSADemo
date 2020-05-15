package com.koal.jks;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * @author yangxu@koal.com
 * @Title: CreateJKS
 * @ProjectName RSADemo
 * @Description: 创建jks密钥库
 * @create by 2020/5/1520:03
 */
public class CreateJKS {


    public static void main(String[] args) throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null,null);
            keyStore.store(new FileOutputStream("mytestkey.jks"),"password".toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }
}
