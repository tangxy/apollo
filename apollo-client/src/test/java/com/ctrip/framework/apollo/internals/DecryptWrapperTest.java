/**
 * @auth: tangxiyuan
 * 
 */
package com.ctrip.framework.apollo.internals;

import org.junit.Assert;
import org.junit.Test;

public class DecryptWrapperTest {
  private String trimPrefixAndSuffix(String encryptedValue) {
    return encryptedValue.substring(4, encryptedValue.length() - 1);
  }

  @Test
  public void testGetPropertyWithAllPropertyHierarchy() throws Exception {
    String sourceString = "ABC123中文";
    String someKey = "ENC(" + sourceString + ")";
    Assert.assertEquals(sourceString, trimPrefixAndSuffix(someKey));
  }
}
