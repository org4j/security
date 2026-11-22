package io.github.org4j.security;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Who is calling, from the current request's token. Without a token, including on a public route
 * where Spring Security stands in an anonymous user, there is no caller: null, and no role.
 */
public final class CurrentUser {

  private static final AuthenticationTrustResolver TRUST = new AuthenticationTrustResolverImpl();

  private CurrentUser() {}

  /** The caller's name: the token's {@code preferred_username}, or its subject without one. */
  public static @Nullable String name() {
    var caller = caller();
    return caller == null ? null : caller.getName();
  }

  /** The caller's id: the token's subject. */
  public static @Nullable String id() {
    return caller() instanceof JwtAuthenticationToken token ? token.getToken().getSubject() : null;
  }

  /** The client the token was issued to: its {@code azp}. */
  public static @Nullable String clientId() {
    return caller() instanceof JwtAuthenticationToken token
        ? token.getToken().getClaimAsString(SecurityConstants.CLIENT_CLAIM)
        : null;
  }

  /**
   * Whether the caller holds a realm role, by its Keycloak name ({@code merchant-admin}), so no app
   * rebuilds the {@code ROLE_*} authority itself.
   */
  public static boolean hasRealmRole(String realmRole) {
    var caller = caller();
    if (caller == null) {
      return false;
    }
    var wanted = KeycloakJwtConverter.authority(realmRole);
    return caller.getAuthorities().stream()
        .anyMatch(authority -> wanted.equals(authority.getAuthority()));
  }

  private static @Nullable Authentication caller() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication == null || TRUST.isAnonymous(authentication) ? null : authentication;
  }
}
