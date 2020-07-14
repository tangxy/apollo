/**
 * @auth: tangxiyuan
 * @time: 2020-7-1416:25:09
 * 
 */
package com.ctrip.framework.apollo.exceptions;

public class ApolloDecryptException extends RuntimeException {
  public ApolloDecryptException(String message) {
    super(message);
  }

  public ApolloDecryptException(String message, Throwable cause) {
    super(message, cause);
  }
}
