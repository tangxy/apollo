/**
 * @auth: tangxiyuan
 * @time: 2020-7-1411:56:39
 * 
 */
package com.ctrip.framework.apollo.core.utils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityUtil {

  private SecurityUtil() {
    throw new IllegalStateException("Utility class");
  }

  private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);
  private static final String SOLT = "0123456789abcdef";
  private static final String DEFAULT_PRIVATE_KEY_STRING =
      "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAocbCrurZGbC5GArEHKlAfDSZi7gFBnd4yxOt0rwTqKBFzGyhtQLu5PRKjEiOXVa95aeIIBJ6OhC2f8FjqFUpawIDAQABAkAPejKaBYHrwUqUEEOe8lpnB6lBAsQIUFnQI/vXU4MV+MhIzW0BLVZCiarIQqUXeOhThVWXKFt8GxCykrrUsQ6BAiEA4vMVxEHBovz1di3aozzFvSMdsjTcYRRo82hS5Ru2/OECIQC2fAPoXixVTVY7bNMeuxCP4954ZkXp7fEPDINCjcQDywIgcc8XLkkPcs3Jxk7uYofaXaPbg39wuJpEmzPIxi3k0OECIGubmdpOnin3HuCP/bbjbJLNNoUdGiEmFL5hDI4UdwAdAiEAtcAwbm08bKN7pwwvyqaCBC//VnEWaq39DCzxr+Z2EIk=";
  public static final String DEFAULT_PUBLIC_KEY_STRING =
      "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKHGwq7q2RmwuRgKxBypQHw0mYu4BQZ3eMsTrdK8E6igRcxsobUC7uT0SoxIjl1WveWniCASejoQtn/BY6hVKWsCAwEAAQ==";
  private static final String RSA_ALGORITHM_STRING = "RSA/ECB/PKCS1Padding";
  private static final String RSA_PROVIDER_STRING = "SunRsaSign";

  public static String decrypt(String cipherText) {
    return decrypt((String) null, cipherText);
  }

  public static String decrypt(String privateKeyText, String cipherText) {
    if (privateKeyText == null || privateKeyText.length() == 0) {
      privateKeyText = SecurityUtil.DEFAULT_PRIVATE_KEY_STRING;
    }
    PrivateKey privateKey = getPrivateKey(privateKeyText);
    return decrypt(privateKey, cipherText);
  }


  private static String decrypt(PrivateKey privateKey, String cipherText) {
    try {
      Cipher cipher = Cipher.getInstance(RSA_ALGORITHM_STRING);
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      if (cipherText == null || cipherText.length() == 0) {
        return cipherText;
      }
      byte[] cipherBytes = Base64.base64ToByteArray(cipherText);
      byte[] plainBytes = cipher.doFinal(cipherBytes);
      return new String(plainBytes);
    } catch (Exception ex) {
      logger.warn("decrypt exception:", ex);
      return cipherText;
    }

  }

  private static PrivateKey getPrivateKey(String privateKeyText) {

    try {
      byte[] privateKeyBytes = Base64.base64ToByteArray(privateKeyText);
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
      KeyFactory factory = KeyFactory.getInstance("RSA", RSA_PROVIDER_STRING);
      return factory.generatePrivate(spec);
    } catch (Exception e) {
      throw new IllegalArgumentException("failed to get private key", e);
    }
  }


  private static PublicKey getPublicKey(String publicKeyText) {
    try {
      byte[] publicKeyBytes = Base64.base64ToByteArray(publicKeyText);
      X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA", RSA_PROVIDER_STRING);
      return keyFactory.generatePublic(x509KeySpec);
    } catch (Exception ex) {
      throw new IllegalArgumentException("failed to get public key", ex);
    }
  }

  public static String encrypt(String plainText) {
    return encrypt((String) null, plainText);
  }

  public static String encrypt(String publicKeyText, String plainText) {
    if (publicKeyText == null) {
      publicKeyText = DEFAULT_PUBLIC_KEY_STRING;
    }
    PublicKey publicKey = getPublicKey(publicKeyText);
    return encrypt(publicKey, plainText);
  }

  private static String encrypt(PublicKey publicKey, String plainText) {
    try {
      Cipher cipher = Cipher.getInstance(RSA_ALGORITHM_STRING);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
      return Base64.byteArrayToBase64(encryptedBytes);
    } catch (Exception ex) {
      logger.warn("encrypt exeception:", ex);
      return plainText;
    }
  }

  public static byte[][] genKeyPairBytes(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    byte[][] keyPairBytes = new byte[2][];

    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", RSA_PROVIDER_STRING);
    gen.initialize(keySize, new SecureRandom());
    KeyPair pair = gen.generateKeyPair();

    keyPairBytes[0] = pair.getPrivate().getEncoded();
    keyPairBytes[1] = pair.getPublic().getEncoded();

    return keyPairBytes;
  }

  public static String[] genKeyPair() {

    String[] keyPairs = new String[2];
    try {
      byte[][] keyPairBytes = genKeyPairBytes(1024);
      keyPairs[0] = Base64.byteArrayToBase64(keyPairBytes[0]);
      keyPairs[1] = Base64.byteArrayToBase64(keyPairBytes[1]);
    } catch (Exception ex) {
      logger.warn("generate rsa key exception:", ex);
      keyPairs[0] = "";
      keyPairs[1] = "";
    }
    return keyPairs;
  }



  private static String ByteArrayToHexString(byte[] b) {
    StringBuilder sb = new StringBuilder(64);
    for (int i = 0; i < b.length; i++) {
      sb.append(SOLT.charAt(b[i] >>> 4 & 0x0F));
      sb.append(SOLT.charAt(b[i] & 0x0F));
    }
    return sb.toString();

  }


  public static String getSignSrc(Map<String, String> secMap, boolean isUseKey, String split) {
    StringBuilder content = new StringBuilder(512);
    List<String> keys = new ArrayList<>(secMap.keySet());
    Collections.sort(keys);

    for (int i = 0; i < keys.size(); i++) {
      Object key = keys.get(i);
      if ("sign".equals(key)) {
        continue;
      }
      Object value = secMap.get(key);
      if (value instanceof String) {
        if (isUseKey) {
          content.append((i == 0 ? "" : split) + key + "=" + (String) value);
        } else {
          content.append((i == 0 ? "" : split) + (String) value);
        }
      }
    }
    return content.toString();
  }

  public static String getSignSrcSkipNull(Map<String, String> secMap, boolean isUseKey,
      String split) {
    StringBuilder content = new StringBuilder(512);
    List<String> keys = new ArrayList<>(secMap.keySet());
    Collections.sort(keys);

    for (int i = 0; i < keys.size(); i++) {
      Object key = keys.get(i);
      if ("sign".equals(key)) {
        continue;
      }
      Object value = secMap.get(key);
      if (value instanceof String) {
        if ("".equals(value)) {
          continue;
        }
        if (isUseKey) {
          content.append((i == 0 ? "" : split) + key + "=" + (String) value);
        } else {
          content.append((i == 0 ? "" : split) + (String) value);
        }
      }


    }
    return content.toString();
  }

  private static byte[] hashData(String algorithm, byte[] b) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(b);
    byte[] digest = md.digest();
    return digest;
  }

  public static String md5(byte[] b) {
    try {
      byte[] a = hashData("MD5", b);
      return ByteArrayToHexString(a).toUpperCase();
    } catch (NoSuchAlgorithmException e) {
      return "";
    }
  }

}
