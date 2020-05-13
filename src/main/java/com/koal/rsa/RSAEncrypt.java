package com.koal.rsa;



import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/**
 * @author yangxu@koal.com
 * @Title: RSAEncrypt
 * @ProjectName RSADemo
 * @Description: TODO
 * @create by 2020/5/1310:23
 */
public class RSAEncrypt {
    /**
     * 字节数据转字符串专用集合
     */
    private static final char[] HEX_CHAR = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    /**
     * 随机生成密钥对
     */
    public static void genKeyPair(String filePath){
        //KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = null;
        try {
            keyPairGen=KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //初始化密钥对生成器，密钥大小为96~1024位
        keyPairGen.initialize(1024,new SecureRandom());
        //生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        //得到公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

        try {
            //得到公钥字符串
            String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            //的到私钥字符串
            String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            //将密钥对写入文件中
            FileWriter pubfw = new FileWriter(filePath+"/publicKey.keystore");
            FileWriter prifw = new FileWriter(filePath+"/privateKey.keystore");
            BufferedWriter pubbw = new BufferedWriter(pubfw);
            BufferedWriter pribw = new BufferedWriter(prifw);
            pubbw.write(publicKeyString);
            pribw.write(privateKeyString);
            pubbw.flush();
            pubbw.close();
            pubfw.close();
            pribw.flush();
            pribw.close();
            prifw.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
        }
    }

    /**
     * 从文件输入流中加载公钥
     * @param path
     * @return
     */
    public static String loadPublicKeyByFile(String path) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new FileReader(path+"/publicKey.keystore"));
            String readLine = null;
            StringBuffer sb = new StringBuffer();
            while((readLine=br.readLine())!= null){
                    sb.append(readLine);
            }
            br.close();
            return sb.toString();
        } catch (FileNotFoundException e) {
            throw new Exception("公钥输入流为空");
        } catch (IOException e) {
             throw new Exception("公钥数据流读取错误");
        }

    }

    /**
     * 从字符串中获取公钥
     * @param publicKeyStr
     * @return
     * @throws Exception
     */
    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr) throws Exception{

        try {
            byte[] buffer = Base64.getDecoder().decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        }catch (NullPointerException e){
            throw new Exception("公钥数据为空");
        }

    }

    /**
     *  从文件输入流中加载私钥
     * @param path
     * @return
     * @throws Exception
     */
    public static String loadPrivateKeyByFile(String path) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new FileReader(path+"/privateKey.keystore"));
            String readLine = null;
            StringBuffer sb = new StringBuffer();
            while ((readLine = br.readLine())!= null){
                sb.append(readLine);
            }
            br.close();
            return sb.toString();
        } catch (FileNotFoundException e) {
            throw new Exception("私钥数据文件流读取错误");
        } catch (IOException e) {
            throw new Exception("私钥输入流错误");
        }
    }

    /**
     * 从字符串中获取私钥
     * @param privateKyeStr
     * @return
     * @throws Exception
     */
    public static RSAPrivateKey loadPrivateKeyByStr(String privateKyeStr) throws Exception{
        try {
            byte[] buffer = Base64.getDecoder().decode(privateKyeStr);
            //私钥使用的是PKCS8编码规范
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        }   catch (NullPointerException e){
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 使用公钥进行加密过程
     * @param publicKey
     * @param plainTextData
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(RSAPublicKey publicKey,byte[] plainTextData) throws Exception{
            if (publicKey==null){
                throw new Exception("加密公钥为空，请设置");
            }
             Cipher cipher = null;
        try {
            //默认了使用RSA
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] outPut = cipher.doFinal(plainTextData);
            return outPut;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }

    }

    /**
     * 使用私钥进行加密过程
     * @param privateKey
     * @param plainTextData
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(RSAPrivateKey privateKey,byte[] plainTextData) throws Exception{
        if (privateKey==null){
            throw new Exception("加密私钥为空，请设置");
        }
        Cipher cipher = null;
        try {
            //默认了使用RSA
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);
            byte[] outPut = cipher.doFinal(plainTextData);
            return outPut;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }

    }

    /**
     * 私钥解密过程
     * @param privateKey　私钥
     * @param cipherDate  加密后的信息
     * @return
     * @throws Exception  解密过程中的异常
     */
    public static byte[] decrypt(RSAPrivateKey privateKey,byte[] cipherDate)throws Exception
    {
        if (privateKey==null){
            throw new Exception("解密私钥为空，请设置");
        }
        try {
            Cipher cipher = null;
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] outPut = cipher.doFinal(cipherDate);
            return outPut;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 公钥解密过程
     * @param publicKey 公钥
     * @param cipherDate 密文数据
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static byte[] decrypt(RSAPublicKey publicKey,byte[] cipherDate)throws Exception
    {
        if (publicKey==null){
            throw new Exception("解密公钥钥为空，请设置");
        }
        try {
            Cipher cipher = null;
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            byte[] outPut = cipher.doFinal(cipherDate);
            return outPut;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 字节数组转16进制字符串
     * @param data
     * @return
     */
    public static String byteArrayToString(byte[] data){
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(HEX_CHAR[(data[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(HEX_CHAR[(data[i] & 0x0f)]);
            if (i < data.length - 1) {
                stringBuilder.append(' ');
            }
        }
        return stringBuilder.toString();
    }



    /*public static void main(String[] args) {

        String org = "yangZiXu";
        String desc = Base64.getEncoder().encodeToString(org.getBytes(StandardCharsets.UTF_8));
        System.out.println("加密后的字符串结果为"+desc);

        String nuDecoder = new String(Base64.getDecoder().decode(desc), StandardCharsets.UTF_8);
        System.out.println("解密后的字符串为"+nuDecoder);
    }*/
}
