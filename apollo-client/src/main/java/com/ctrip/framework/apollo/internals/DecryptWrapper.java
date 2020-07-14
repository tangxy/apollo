/**
 * @auth: tangxiyuan
 * @time: 2020-7-149:35:23
 * 
 */
package com.ctrip.framework.apollo.internals;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ctrip.framework.apollo.build.ApolloInjector;
import com.ctrip.framework.apollo.core.dto.DecryptEntry;
import com.ctrip.framework.apollo.core.dto.ServiceDTO;
import com.ctrip.framework.apollo.core.utils.SecurityUtil;
import com.ctrip.framework.apollo.exceptions.ApolloConfigException;
import com.ctrip.framework.apollo.exceptions.ApolloDecryptException;
import com.ctrip.framework.apollo.util.ConfigUtil;
import com.ctrip.framework.apollo.util.http.HttpRequest;
import com.ctrip.framework.apollo.util.http.HttpResponse;
import com.ctrip.framework.apollo.util.http.HttpUtil;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.escape.Escaper;
import com.google.common.net.UrlEscapers;

public class DecryptWrapper {
  private static final Logger logger = LoggerFactory.getLogger(DecryptWrapper.class);
  private static final Joiner.MapJoiner MAP_JOINER = Joiner.on("&").withKeyValueSeparator("=");
  private static final Escaper pathEscaper = UrlEscapers.urlPathSegmentEscaper();
  private static final Escaper queryParamEscaper = UrlEscapers.urlFormParameterEscaper();

  private final ConfigServiceLocator m_serviceLocator;
  private final HttpUtil m_httpUtil;
  private final ConfigUtil m_configUtil;

  public DecryptWrapper() {
    m_httpUtil = ApolloInjector.getInstance(HttpUtil.class);
    m_serviceLocator = ApolloInjector.getInstance(ConfigServiceLocator.class);
    m_configUtil = ApolloInjector.getInstance(ConfigUtil.class);

  }

  public void processEncryptedValue(Properties newConfigProperties) {
    Set<Object> keys = newConfigProperties.keySet();
    for (Object k : keys) {
      String key = k.toString();
      String value = newConfigProperties.getProperty(key);
      if (isEncryptedValue(value)) {
        try {
          newConfigProperties.setProperty(key, decryptValue(key, value));
        } catch (Exception ex) {
          logger.error("decrypt value fail:", ex);
        }
      }
    }
  }

  private boolean isEncryptedValue(String value) {
    return value.startsWith("ENC(") && value.endsWith(")");
  }

  private String trimPrefixAndSuffix(String wrappedValue) {
    return wrappedValue.substring(4, wrappedValue.length() - 1);
  }

  private String decryptValue(String key, String wrappedValue) {
    logger.info("[{}]'s value [{}] need decrypt", key, wrappedValue);
    String encryptedValue = trimPrefixAndSuffix(wrappedValue);
    String[] rsaKeyStrings = SecurityUtil.genKeyPair();
    List<ServiceDTO> configServices = getConfigServices();
    List<ServiceDTO> randomConfigServices = Lists.newLinkedList(configServices);
    Collections.shuffle(randomConfigServices);
    String decryptedValue = "";
    for (ServiceDTO configService : randomConfigServices) {
      try {
        decryptedValue = doDecryptValue(configService.getHomepageUrl(), rsaKeyStrings[0],
            rsaKeyStrings[1], encryptedValue);
        break;
      } catch (Exception ex) {
        logger.warn("decrypt exception:", ex);
        try {
          m_configUtil.getOnErrorRetryIntervalTimeUnit().sleep(3000);
        } catch (InterruptedException exi) {
          logger.warn("interrupted!", exi);
          Thread.currentThread().interrupt();
        }
      }
    }
    return decryptedValue;
  }

  private String doDecryptValue(String uri, String privateKey, String publicKey,
      String encryptedValue) throws Exception {
    try {
      String timestamp = Long.toString(System.currentTimeMillis());
      String urlString =
          assembleDecryptUrl(uri, m_configUtil.getAppId(), timestamp, publicKey, encryptedValue);
      logger.info("decrypt url [{}]", urlString);
      HttpRequest request = new HttpRequest(urlString);
      HttpResponse<DecryptEntry> response = m_httpUtil.doGet(request, DecryptEntry.class);
      logger.info("response: [{}] {}", response.getStatusCode(), response.getBody());
      if (response.getStatusCode() != 200) {
        throw new ApolloDecryptException("do decrypt fail");
      }
      DecryptEntry decryptEntry = response.getBody();
      String decryptedValue = SecurityUtil.decrypt(privateKey, decryptEntry.getDecrypted());
      if (!checkDecryptResponse(decryptedValue, timestamp, decryptEntry.getMac())) {
        throw new ApolloDecryptException("decrypt response incomplete");
      }
      return decryptedValue;
    } catch (Exception ex) {
      logger.warn("decrypt exception:", ex);
      throw ex;
    }

  }

  private boolean checkDecryptResponse(String decryptedValue, String timestamp, String mac) {
    Map<String, String> secMap = new HashMap<>(8);
    secMap.put("timestamp", timestamp);
    secMap.put("decryptedValue", decryptedValue);
    return mac.equals(SecurityUtil
        .md5(SecurityUtil.getSignSrcSkipNull(secMap, true, "&").getBytes(StandardCharsets.UTF_8)));
  }

  private String assembleDecryptUrl(String uri, String appId, String timestamp, String publicKey,
      String encryptedValue) {
    String path = "decrypt/%s";
    List<String> pathParams = Lists.newArrayList(pathEscaper.escape(appId));
    Map<String, String> queryParams = Maps.newHashMap();
    if (!Strings.isNullOrEmpty(timestamp)) {
      queryParams.put("timestamp", queryParamEscaper.escape(timestamp));
    }
    if (!Strings.isNullOrEmpty(publicKey)) {
      queryParams.put("publicKey", queryParamEscaper.escape(publicKey));
    }
    if (!Strings.isNullOrEmpty(encryptedValue)) {
      queryParams.put("encryptedValue", queryParamEscaper.escape(encryptedValue));
    }

    String localIp = m_configUtil.getLocalIp();
    if (!Strings.isNullOrEmpty(localIp)) {
      queryParams.put("ip", queryParamEscaper.escape(localIp));
    }

    String pathExpanded = String.format(path, pathParams.toArray());

    if (!queryParams.isEmpty()) {
      pathExpanded += "?" + MAP_JOINER.join(queryParams);
    }
    if (!uri.endsWith("/")) {
      uri += "/";
    }
    return uri + pathExpanded;
  }

  private List<ServiceDTO> getConfigServices() {
    List<ServiceDTO> services = m_serviceLocator.getConfigServices();
    if (services.size() == 0) {
      throw new ApolloConfigException("no available config service");
    }

    return services;
  }
}
