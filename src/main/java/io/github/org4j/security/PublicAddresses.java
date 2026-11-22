package io.github.org4j.security;

import static io.github.org4j.security.SecurityConstants.HTTP;
import static io.github.org4j.security.SecurityConstants.HTTPS;
import static io.github.org4j.security.SecurityConstants.HTTPS_PORT;
import static io.github.org4j.security.SecurityConstants.HTTP_PORT;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.jspecify.annotations.Nullable;

/**
 * Checks a URL a caller hands in, such as a webhook, before the app calls it: HTTPS on port 443 to
 * a host whose every address is public. Private, loopback, link-local, reserved and documentation
 * ranges are refused, and so are IPv6 forms that embed an IPv4 address (6to4, Teredo, NAT64).
 * Configured test hosts ({@code host:port}) pass over HTTP or HTTPS without the check.
 *
 * <p>A check resolves the host once; the app's call resolves it again. Hand {@link #resolvePublic}
 * to the HTTP client as its resolver so the address called is the address checked.
 */
public final class PublicAddresses {

  private static final List<Range> REFUSED_V4 =
      List.of(
          Range.of("0.0.0.0/8"),
          Range.of("10.0.0.0/8"),
          Range.of("100.64.0.0/10"),
          Range.of("127.0.0.0/8"),
          Range.of("169.254.0.0/16"),
          Range.of("172.16.0.0/12"),
          Range.of("192.0.0.0/24"),
          Range.of("192.0.2.0/24"),
          Range.of("192.168.0.0/16"),
          Range.of("198.18.0.0/15"),
          Range.of("198.51.100.0/24"),
          Range.of("203.0.113.0/24"),
          Range.of("224.0.0.0/4"),
          Range.of("240.0.0.0/4"));

  private static final Range GLOBAL_V6 = Range.of("2000::/3");

  private static final List<Range> REFUSED_V6 =
      List.of(
          Range.of("2001::/32"), // Teredo
          Range.of("2001:db8::/32"), // documentation
          Range.of("2002::/16"), // 6to4
          Range.of("64:ff9b::/96")); // NAT64

  private PublicAddresses() {}

  /** Whether the app may call the URL: a test host, or HTTPS on 443 to public addresses only. */
  public static boolean allowed(String url, Collection<String> testHosts) {
    var uri = parse(url);
    if (uri == null) {
      return false;
    }
    if (allowedTestHost(url, testHosts)) {
      return true;
    }
    return HTTPS.equals(scheme(uri)) && port(uri) == HTTPS_PORT && resolvesPublic(uri.getHost());
  }

  /** Whether the URL's host and port are one of the test hosts, over HTTP or HTTPS. */
  public static boolean allowedTestHost(String url, Collection<String> testHosts) {
    var uri = parse(url);
    if (uri == null) {
      return false;
    }
    var entry = uri.getHost().toLowerCase(Locale.ROOT) + ":" + port(uri);
    return testHosts.stream().anyMatch(test -> test.toLowerCase(Locale.ROOT).equals(entry));
  }

  /** Whether the host is a test host, on any port. */
  public static boolean isTestHost(String host, Collection<String> testHosts) {
    var prefix = host.toLowerCase(Locale.ROOT) + ":";
    return testHosts.stream().anyMatch(test -> test.toLowerCase(Locale.ROOT).startsWith(prefix));
  }

  private static @Nullable URI parse(String url) {
    try {
      var uri = new URI(url);
      var scheme = scheme(uri);
      return uri.getHost() != null && (HTTPS.equals(scheme) || HTTP.equals(scheme)) ? uri : null;
    } catch (URISyntaxException e) {
      return null;
    }
  }

  private static String scheme(URI uri) {
    return uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
  }

  private static int port(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    return HTTPS.equals(scheme(uri)) ? HTTPS_PORT : HTTP_PORT;
  }

  /**
   * Resolves a host, refusing it unless every address is public.
   *
   * @throws UnknownHostException when the host doesn't resolve or an address isn't public
   */
  public static InetAddress[] resolvePublic(String host) throws UnknownHostException {
    var addresses = InetAddress.getAllByName(host);
    if (!Arrays.stream(addresses).allMatch(PublicAddresses::isPublic)) {
      throw new UnknownHostException(
          "%s resolves to an address that is not public".formatted(host));
    }
    return addresses;
  }

  /** Whether the host resolves, and only to public addresses. */
  public static boolean resolvesPublic(String host) {
    try {
      resolvePublic(host);
      return true;
    } catch (UnknownHostException e) {
      return false;
    }
  }

  static boolean isPublic(InetAddress address) {
    var bytes = address.getAddress();
    if (bytes.length == 4) {
      return REFUSED_V4.stream().noneMatch(range -> range.contains(bytes));
    }
    return GLOBAL_V6.contains(bytes)
        && REFUSED_V6.stream().noneMatch(range -> range.contains(bytes));
  }

  private static final class Range {
    private final byte[] network;
    private final int prefix;

    private Range(byte[] network, int prefix) {
      this.network = network;
      this.prefix = prefix;
    }

    static Range of(String cidr) {
      var parts = cidr.split("/", 2);
      try {
        return new Range(InetAddress.getByName(parts[0]).getAddress(), Integer.parseInt(parts[1]));
      } catch (UnknownHostException e) {
        throw new IllegalStateException(e);
      }
    }

    boolean contains(byte[] address) {
      if (address.length != network.length) {
        return false;
      }
      var bits = address.length * 8;
      var mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE).shiftRight(prefix).not();
      return new BigInteger(1, address).and(mask).equals(new BigInteger(1, network).and(mask));
    }
  }
}
