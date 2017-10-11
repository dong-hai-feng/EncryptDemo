package com.ethan.encryptdemo;

import android.text.TextUtils;
import android.util.Log;

/**
 * 作者：Created by BarryDong on 2017/10/10.
 * 邮箱：barry.dong@tianyitechs.com
 */

public class jni {
    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private jni(){}

    private static jni mInstance;

    public static jni getInstance() {
        if (mInstance == null) {
            synchronized (jni.class) {
                if (mInstance == null) {
                    mInstance = new jni();
                    return mInstance;
                }
            }
        }
        return mInstance;
    }
    /**
     * MD5加密（不可逆）
     * */
    public String encrypt_MD5(String msg){
        return MD5(msg);
    }

    /**
     * RSA公钥加密
     * */
    public String encrypt_RSAbyPublicKey(String msg) {
        if (msg == null) {
            msg = "";
        }
        String result= encryptRSAbyPublicKey(msg);
        if (TextUtils.isEmpty(result)) {
            return "";
        }
        if (result.contains("\r")){
            result= result.replaceAll("\r", "");
        }
        if (result.contains("\n")){
            result= result.replaceAll("\n", "");
        }
        if (result.contains("0x0a")) {
            result= result.replaceAll("0x0a", "");
        }
        return result;
    }

    /**
     * 公钥解密
     * */
    public String decrypt_RSAbyPublicKey(String msg) {
        if (msg == null) {
            msg = "";
            Log.e("haifeng","空的");
        }
        return decryptRSAbyPublicKey(msg);
    }

    /**
     * 私钥加密
     * */
    public String encrypt_RSAbyPrivateKey(String msg) {
        if (msg == null) {
            msg = "";
        }
        String result= encryptRSAbyPrivateKey(msg);
        if (TextUtils.isEmpty(result)) {
            return "";
        }
        if (result.contains("\r")){
            result= result.replaceAll("\r", "");
        }
        if (result.contains("\n")){
            result= result.replaceAll("\n", "");
        }
        if (result.contains("0x0a")) {
            result= result.replaceAll("0x0a", "");
        }
        return result;
    }

    /**
     * 私钥解密
     * */
    public String decrypt_RSAbyPrivateKey(String msg) {
        if (msg == null) {
            msg = "";
            Log.e("haifeng","空的");
        }
        return decryptRSAbyPrivateKey(msg);
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    private native String MD5(String msg);

    public native String encryptRSAbyPublicKey(String msg);

    public native String decryptRSAbyPublicKey(String msg);

    private native String decryptRSAbyPrivateKey(String msg);

    public native String encryptRSAbyPrivateKey(String msg);
}
