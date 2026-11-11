using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace RenderService;

public enum HostVerdict
{
    Allowed,
    Internal,
    DnsFailed,
}

/// <summary>
/// Application-level SSRF guard: every request the page makes (main document, redirects,
/// scripts, images, form posts) is allowed only if its host resolves to public addresses.
/// The iptables rules from firewall/render-egress.sh are the second, network-level layer.
/// One instance per render, so DNS answers are cached only for the lifetime of one page.
/// </summary>
public sealed class EgressGuard
{
    private readonly ConcurrentDictionary<string, Task<HostVerdict>> _cache = new(StringComparer.OrdinalIgnoreCase);

    public Task<HostVerdict> CheckHostAsync(string host) => _cache.GetOrAdd(host, ResolveAsync);

    private static async Task<HostVerdict> ResolveAsync(string host)
    {
        var h = host.Trim('[', ']').TrimEnd('.');

        if (IPAddress.TryParse(h, out var literal))
        {
            return IpRules.IsPublic(literal) ? HostVerdict.Allowed : HostVerdict.Internal;
        }

        if (h.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || h.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || h.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
            || h.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
        {
            return HostVerdict.Internal;
        }

        IPAddress[] addresses;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            addresses = await Dns.GetHostAddressesAsync(h, cts.Token);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            return HostVerdict.DnsFailed;
        }

        if (addresses.Length == 0)
        {
            return HostVerdict.DnsFailed;
        }

        return addresses.All(IpRules.IsPublic) ? HostVerdict.Allowed : HostVerdict.Internal;
    }
}

public static class IpRules
{
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            var blocked =
                b[0] == 0                                        // 0.0.0.0/8
                || b[0] == 10                                    // 10.0.0.0/8
                || b[0] == 127                                   // loopback
                || b[0] >= 224                                   // multicast + reserved + broadcast
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)    // 100.64.0.0/10 carrier NAT
                || (b[0] == 169 && b[1] == 254)                  // link-local, cloud metadata
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)     // 172.16.0.0/12 (incl. Docker)
                || (b[0] == 192 && b[1] == 168)                  // 192.168.0.0/16
                || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2)  // 192.0.0.0/24, 192.0.2.0/24
                || (b[0] == 198 && b[1] is 18 or 19)             // 198.18.0.0/15 benchmarking
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)    // documentation
                || (b[0] == 203 && b[1] == 0 && b[2] == 113);    // documentation
            return !blocked;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6Any)
                || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal)
            {
                return false;
            }

            var b = ip.GetAddressBytes();
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
            {
                return false; // 2001:db8::/32 documentation
            }

            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b)
            {
                return false; // 64:ff9b::/96 NAT64 can point back into private IPv4
            }

            return true;
        }

        return false;
    }
}
