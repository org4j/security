# security

One way to secure every service: Keycloak access tokens (realm roles as `ROLE_*`), route rules
from configuration where anything not listed is refused, public routes that ignore any token sent,
401 and 403 as problem details, and client-credentials tokens on calls to other services.

```groovy
implementation libs.security
```

Set Boot's `spring.security.oauth2.resourceserver.jwt.issuer-uri` (the realm) and
`spring.security.oauth2.resourceserver.jwt.audiences` (the API's audience, e.g. `demo-api`).

A service that takes tokens from several issuers (another unit's Keycloak) lists them in
`org4j.security.issuers` instead: each issuer's tokens must name its `audience`, and only the
realm `roles` listed for it count (one unit's Keycloak can't grant another's roles); a token from any
other issuer is refused (401), and each issuer's keys are fetched with its first token. An issuer
that can't be reached then answers 500, as Boot's one issuer does, and is tried again on the next
request. Who may call what is granted in Keycloak alone, by the audience and roles it puts in the
token: the service keeps no list of callers. `issuers` and Boot's `issuer-uri` together stop
startup, as do an incomplete issuer and one issuer listed twice.

## Properties

| Property | What |
|---|---|
| `org4j.security.public-routes` | routes anyone may call; a token sent with them is never read. `"POST /api/v1/registrations/**"` limits one to a method, in any case |
| `org4j.security.signed-in-routes` | routes any caller with a valid token may call, whatever its roles; the operation decides what it gives |
| `org4j.security.roles` | each route and the realm role it needs, in order, e.g. `"[/api/v1/admin/**]": ADMIN` |
| `org4j.security.issuers[n].uri`, `.audience`, `.roles` | trusted issuers, instead of Boot's one `issuer-uri`: each issuer's URI (its tokens' `iss`), the audience its tokens must name, and the realm roles it may grant (others in its tokens are dropped); all three required |
| `org4j.security.ssl-bundle` | an SSL bundle (`spring.ssl.bundle.*`) whose trust store the trusted issuers' keys are fetched with, for a Keycloak whose certificate comes from the app's own CA; unset, the JVM's trust store. Needs `issuers`; a bundle not defined stops startup |
| `org4j.security.service-tokens.groups` | HTTP service groups and the OAuth2 client registration (`spring.security.oauth2.client.registration.<id>`) their calls take a client-credentials token from |
| `org4j.security.service-tokens.connect-timeout` | 5s: a token request's wait for a connection |
| `org4j.security.service-tokens.read-timeout` | 10s: a token request's wait for its answer |
| `org4j.security.service-tokens.ssl-bundle` | an SSL bundle whose trust the token requests go over, as `ssl-bundle` for the keys; unset, the JVM's trust store |

## Adding to the chain

A module adds a filter with a `Customizer<HttpSecurity>` bean, which Spring Security applies before
the library's rules: `http -> http.addFilterAfter(filter, BearerTokenAuthenticationFilter.class)`.
To refuse a request, hand `ProblemSecurityHandler` the reason so the answer is a problem detail.
Filters only; the route rules stay in configuration: a customizer that sets route rules
(`authorizeHttpRequests`) stops startup.

## Calling another service

With an OAuth2 client registration and `org4j.security.service-tokens.groups.<group>=<registration>`,
the group's `@HttpExchange` clients send the service's own client-credentials token (Spring
Security's interceptor gets and refreshes it). A 401 that refuses the token (no challenge, or
`error="invalid_token"`) drops it and the call is tried once more; `insufficient_scope` is the
answer. The app's own `OAuth2AuthorizedClientManager` bean gets the tokens when it has one;
otherwise a manager over Boot's authorized-client store does (Spring Security's default needs a
servlet request, which a job's call has not), its token requests over Boot's `RestClient.Builder`.
Without registrations nothing changes. The registration's secret comes from Vault.


## Who is calling

| Call | Gives |
|---|---|
| `CurrentUser.name()` | the token's `preferred_username`, or its subject without one |
| `CurrentUser.id()` | the token's subject |
| `CurrentUser.clientId()` | the client the token was issued to (`azp`) |
| `CurrentUser.hasRealmRole("merchant-admin")` | whether the caller holds a realm role, by its Keycloak name, so no app rebuilds the `ROLE_*` authority |

Without a token, on a public route too, there is no caller: null, and no role.

## Checking a URL a caller hands in

`PublicAddresses.allowed(url, testHosts)` says whether the app may call a URL a caller gave it, such
as a webhook. It must be HTTPS on port 443 to a host whose every address is public. Private,
loopback, link-local, reserved and documentation ranges are refused, and so are IPv6 forms that
embed an IPv4 address. A test host (`host:port`) passes over HTTP or HTTPS without the check. The
call resolves the host again, so hand `PublicAddresses.resolvePublic` to the HTTP client as its
resolver: then the address called is the address checked.

## Errors

401 and 403 are answered by the app's `AuthenticationEntryPoint` and `AccessDeniedHandler` beans;
the library has none of its own and doesn't depend on error. Without them the app doesn't start. With
the error library on the classpath, its `ProblemSecurityHandler` is both, so the answers are
`UNAUTHORIZED` (401) and `FORBIDDEN` (403) problem details.

## Beans you can replace

| Bean | Replace with |
|---|---|
| `apiSecurity` (`SecurityFilterChain`) | your own chain, when a service needs a different one |
| `KeycloakJwtConverter` | your own token-to-authorities converter |
| `bearerTokenResolver` | your own `BearerTokenResolver` |
| `ServiceTokens` | your own `RestClientHttpServiceGroupConfigurer` |

## Tests

- `./gradlew test`:
  - route rules, methods in any case, and public routes with stale tokens;
  - module customizers, the token converter, and who is calling (no one on a public route);
  - `PublicAddresses`, and service tokens armed and dormant.
- `./gradlew integrationTest`: a real Keycloak with password and client-credentials tokens.
  - Roles, the audience, stale tokens on public routes, and a module's refusing filter.
  - Service tokens: a role check, one retry on 401, and a rotated secret.
  - Trusted issuers over four realms: a client of either trusted issuer, an issuer not trusted,
    another audience, a role the issuer may not grant, and a client without the route's role.
  - A Keycloak over HTTPS only, its certificate from a test CA (`tls/`) the JVM doesn't trust: the
    token and the keys go over the SSL bundles.
