package io.github.org4j.security;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Turns a Keycloak access token into an authentication: its realm roles become {@code ROLE_*}
 * authorities, upper case, and its {@code preferred_username} the name.
 */
public class KeycloakJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    var username = jwt.getClaimAsString(SecurityConstants.USERNAME_CLAIM);
    // Without a username the token's subject names the caller, as Spring Security does.
    return username == null
        ? new JwtAuthenticationToken(jwt, roles(jwt))
        : new JwtAuthenticationToken(jwt, roles(jwt), username);
  }

  private static Collection<GrantedAuthority> roles(Jwt jwt) {
    var realmAccess = jwt.getClaimAsMap(SecurityConstants.REALM_ACCESS_CLAIM);
    if (realmAccess == null
        || !(realmAccess.get(SecurityConstants.ROLES) instanceof List<?> roles)) {
      return List.of();
    }
    return roles.stream()
        .<GrantedAuthority>map(role -> new SimpleGrantedAuthority(authority(role.toString())))
        .toList();
  }

  static String authority(String realmRole) {
    return SecurityConstants.ROLE_PREFIX + realmRole.toUpperCase(Locale.ROOT);
  }
}
