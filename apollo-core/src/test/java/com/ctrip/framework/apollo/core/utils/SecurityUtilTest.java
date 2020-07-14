/**
 * @auth: tangxiyuan
 * @time: 2020-7-1413:34:20 Copyright (c) 2020, lakala All Rights Reserved.
 * 
 */
package com.ctrip.framework.apollo.core.utils;

import org.junit.Assert;
import org.junit.Test;

public class SecurityUtilTest {
  @Test
  public void testEncryptAndDecrypt() {
    String plainText = "abc中国123";
    try {
      Assert.assertEquals(plainText, SecurityUtil.decrypt(SecurityUtil.encrypt(plainText)));
      String[] keyPairStrings = SecurityUtil.genKeyPair();
      Assert.assertEquals(plainText, SecurityUtil.decrypt(keyPairStrings[0],
          SecurityUtil.encrypt(keyPairStrings[1], plainText)));
    } catch (Exception e) {
      e.printStackTrace();
      Assert.assertEquals(1, 0);
    }

  }
}
