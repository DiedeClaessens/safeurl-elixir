defmodule SafeURL.DNSResolver do
  @moduledoc """
  In some cases you might want to use a custom strategy
  for DNS resolution. You can do so by passing your own
  implementation of `SafeURL.DNSResolver` in the global
  or local config.

  By default, `SafeURL.DNS` looks up the A and AAAA records
  with the `DNS` package, but you can replace it with a
  wrapper that uses different configuration or a completely
  different implementation altogether.

  A resolver has to return every address the host resolves
  to: `SafeURL` validates all of them and rejects the URL if
  any one is not allowed.


  ## Use-cases

    * Using a specific DNS server
    * Avoiding network access in specific environments
    * Mocking DNS resolution in tests


  ## Usage

  Start by creating a module that implements the
  `DNSResolver` behaviour. Currently, this means adding
  only one `c:resolve/1` callback that takes a host and
  returns a list of resolved IPs.

  A resolver must return every address of every family the
  host has. Returning only the A records would let a host
  whose AAAA record points at an internal address through,
  which is what `SafeURL.DNS` avoids by querying both.

  As an example, suppose you wanted to use
  [Cloudflare's DNS](https://1.1.1.1/dns/), you can do
  that by wrapping `DNS` with your own settings in a new
  module:

      defmodule CloudflareDNS do
        @behaviour SafeURL.DNSResolver

        @impl true
        def resolve(domain) do
          with {:ok, ipv4} <- query(domain, :a),
               {:ok, ipv6} <- query(domain, :aaaa) do
            {:ok, ipv4 ++ ipv6}
          end
        end

        defp query(domain, type) do
          case DNS.resolve(domain, type, {"1.1.1.1", 53}, :udp) do
            {:ok, ips} -> {:ok, ips}
            {:error, _reason} -> {:ok, []}
          end
        end
      end

  To use it, simply pass it in the global config:

      config :safeurl, dns_module: CloudflareDNS

  You can also directly set the `:dns_module` in method options:

      SafeURL.allowed?("https://example.com", dns_module: CloudflareDNS)


  ## Testing

  This is especially useful in tests where you want to
  ensure your HTTP Client wrapper with `SafeURL` is
  working as expected.

  You can override the `:dns_module` config to ensure
  a specific IP is resolved for a domain or no network
  requests are made:

      defmodule TestDNSResolver do
        @behaviour SafeURL.DNSResolver

        @impl true
        def resolve("google.com"), do: {:ok, [{192, 168, 1, 10}]}
        def resolve("github.com"), do: {:ok, [{192, 168, 1, 20}]}
        def resolve(_domain),      do: {:ok, [{192, 168, 1, 99}]}
      end

  A resolver that returns an empty list, or an error, makes
  the URL fail validation with `{:error, :unresolved_host}`.

  """

  @callback resolve(host :: String.t()) :: {:ok, [:inet.ip_address()]} | {:error, term()}
end
