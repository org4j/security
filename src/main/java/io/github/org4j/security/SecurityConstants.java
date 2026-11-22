package io.github.org4j.security;

/** Where the library's settings live. */
public final class SecurityConstants {

  /** Routes, roles and trusted issuers: {@code org4j.security.*}. */
  public static final String PROPERTIES_PREFIX = "org4j.security";

  static final String USERNAME_CLAIM = "preferred_username";

  static final String CLIENT_CLAIM = "azp";

  static final String REALM_ACCESS_CLAIM = "realm_access";
  static final String ROLES = "roles";
  static final String ROLE_PREFIX = "ROLE_";

  static final String ROLE_MISSING = "Route %s needs at least one realm role, none blank";

  static final String ISSUER_INCOMPLETE =
      "Trusted issuer %s needs its uri, audience and the roles it may grant";

  static final String ISSUER_NOT_TRUSTED = "The token's issuer is not trusted";

  static final String ISSUER_TWICE = "Trusted issuer %s is listed twice";

  static final String ISSUERS_AND_ISSUER_URI =
      "Set org4j.security.issuers or spring.security.oauth2.resourceserver.jwt.issuer-uri, not both";

  static final String SSL_BUNDLE_WITHOUT_ISSUERS =
      "org4j.security.ssl-bundle needs org4j.security.issuers";

  static final String BOOT_ISSUER_URI = "spring.security.oauth2.resourceserver.jwt.issuer-uri";

  static final String METHOD_SEPARATOR = " ";

  /** Service-to-service tokens: {@code org4j.security.service-tokens.*}. */
  public static final String SERVICE_TOKENS_PREFIX = "org4j.security.service-tokens";

  static final String ROUTES_IN_CONFIGURATION =
      "A Customizer<HttpSecurity> set route rules; they belong in org4j.security.roles and"
          + " org4j.security.public-routes, and a customizer adds filters only";
  static final String HTTP_CLIENT_FACTORY =
      "org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder";
  static final String DEFAULT_TOKEN_CONNECT_TIMEOUT = "5s";
  static final String DEFAULT_TOKEN_READ_TIMEOUT = "10s";
  static final String INVALID_TOKEN = "error=\"invalid_token\"";

  static final String SERVICE_PRINCIPAL = "service-tokens";

  static final String SERVICE_AUTHORITY = "ROLE_SERVICE";
  static final String BOOT_OAUTH2_CLIENT =
      "org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration";
  static final String CLIENT_REGISTRATIONS =
      "org.springframework.security.oauth2.client.registration.ClientRegistrationRepository";
  static final String SERVICE_GROUP_CONFIGURER =
      "org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer";

  static final String BOOT_WEB_SECURITY =
      "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration";
  static final String BOOT_MANAGEMENT_SECURITY =
      "org.springframework.boot.security.autoconfigure.actuate.web.servlet.ManagementWebSecurityAutoConfiguration";

  static final String BOOT_OAUTH2_CLIENT_SECURITY =
      "org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration";

  static final String BOOT_RESOURCE_SERVER_SECURITY =
      "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration";

  static final String HTTPS = "https";

  static final String HTTP = "http";

  static final int HTTPS_PORT = 443;

  static final int HTTP_PORT = 80;

  private SecurityConstants() {}
}
