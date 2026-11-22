/**
 * One way to secure every service: Keycloak access tokens, route rules from configuration where
 * anything not listed is refused, and client-credentials tokens on calls to other services. {@link
 * io.github.org4j.security.CurrentUser} says who is calling.
 */
@NullMarked
package io.github.org4j.security;

import org.jspecify.annotations.NullMarked;
