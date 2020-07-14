/**
 * @auth: tangxiyuan
 * @time: 2020-7-1414:24:07
 * 
 */
package com.ctrip.framework.apollo.core.utils;

public class GenerateTestInfomain {
  public static void main(String[] args) {
    String plainText = "abc中国123";
    try {
      String[] keyPairStrings = SecurityUtil.genKeyPair();
      System.out.println("private key: " + keyPairStrings[0]);
      System.out.println("public key: " + keyPairStrings[1]);
      System.out.println("source plain text: " + plainText);
      System.out.println("encrypted: " + SecurityUtil.encrypt(keyPairStrings[1], plainText));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
