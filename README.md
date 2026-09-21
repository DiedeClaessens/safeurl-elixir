# SafeURL

[![Build Status][badge-github]][github-build]
[![Version][badge-version]][hexpm]
[![Downloads][badge-downloads]][hexpm]
[![License][badge-license]][github-license]

> SSRF Protection in Elixir 🛡️

SafeURL is a library that aids developers in protecting against a class of vulnerabilities
known as Server Side Request Forgery. It does this by validating a URL against a configurable
allow or block list before making an HTTP request.

See the [Documentation][docs] on HexDocs.

<br>

## Installation

To get started, add `safeurl` to your project dependencies in `mix.exs`. Optionally, you may
also add [`HTTPoison`][lib-httpoison] to your dependencies for making requests directly
through SafeURL:

```elixir
def deps do
  [
    {:safeurl, "~> 1.0"},
    {:httpoison, "~> 2.2"},  # Optional
  ]
end
```

To use SafeURL with your favorite HTTP Client, see the [HTTP Clients][readme-http] section.

<br>

## Usage

`SafeURL` blocks private/reserved IP addresses are by default, and users can add additional
CIDR ranges to the blocklist, or alternatively allow specific CIDR ranges to which the
application is allowed to make requests.

You can use `allowed?/2` or `validate/2` to check if a URL is safe to call, and
[`pin/2`][docs-pin] to get a URL that connects to the very address that passed. If you have the
[`HTTPoison`][lib-httpoison] application available, you can also call
[`SafeURL.HTTPoison.get/3`][docs-get] which will
validate the host automatically before making a web request, and return an error otherwise.

```elixir
iex> SafeURL.allowed?("https://includesecurity.com")
true

iex> SafeURL.validate("http://google.com/", schemes: ~w[https])
{:error, :unsafe_scheme}

iex> SafeURL.validate("http://230.10.10.10/")
{:error, :unsafe_reserved}

iex> SafeURL.validate("http://230.10.10.10/", block_reserved: false)
:ok

# When HTTPoison is available:

iex> SafeURL.HTTPoison.get("https://10.0.0.1/ssrf.txt")
{:error, :unsafe_reserved}

iex> SafeURL.HTTPoison.get("https://google.com/")
{:ok, %HTTPoison.Response{...}}
```

<br>

## Configuration

`SafeURL` can be configured to customize and override validation behaviour by passing the
following options:

- `:block_reserved` - Block reserved/private IP ranges. Defaults to `true`.

- `:blocklist` - List of CIDR ranges to block. This is additive with `:block_reserved`.
  Defaults to `[]`.

- `:allowlist` - List of CIDR ranges to allow. If specified, blocklist will be ignored.
  Defaults to `[]`.

- `:schemes` - List of allowed URL schemes. Defaults to `["http, "https"]`.

- `:dns_module` - Any module that implements the `SafeURL.DNSResolver` behaviour.
  Defaults to `SafeURL.DNS`, which looks up A and AAAA records with the [`:dns`][lib-dns] package.

- `:detailed_error` - Return specific error if validation fails. If set to `false`, `validate/2` will return `{:error, :restricted}` regardless of the reason. Defaults to `true`.

These options can be passed to the function directly or set globally in your `config.exs`
file:

```elixir
config :safeurl,
  block_reserved: true,
  blocklist: ~w[100.0.0.0/16],
  schemes: ~w[https],
  dns_module: MyCustomDNSResolver
```

Find detailed documentation on [HexDocs][docs].

<br>

## HTTP Clients

While SafeURL already provides a convenient [`SafeURL.HTTPoison.get/3`][docs-get] method to validate hosts
before making GET HTTP requests, you can also write your own wrappers, helpers or
middleware to work with the HTTP Client of your choice.

Validating a URL and then handing the hostname to an HTTP client resolves it twice, and the
second lookup can return a different address than the one that was checked. Use
[`pin/2`][docs-pin] so your client connects to the address that passed, and keep the hostname
for the `Host` header, the server name and the certificate check. See
[Pinning the validated address](#pinning-the-validated-address).

### HTTPoison

[`SafeURL.HTTPoison.get/3`][docs-get] already pins the request, sends the hostname as the
`host` header and rebuilds hackney's TLS options from that hostname, so the certificate is
still verified against the name. For the other verbs, wrap it the same way:

```elixir
defmodule CustomClient do
  def request(method, url, body, headers \\ [], opts \\ []) do
    {safeurl_opts, opts} = Keyword.pop(opts, :safeurl, [])

    with {:ok, pinned} <- SafeURL.pin(url, safeurl_opts) do
      HTTPoison.request(method, pinned.url, body, host_header(headers, pinned), opts)
    end
  end

  defp host_header(headers, pinned) do
    [{"host", pinned.hostname} | Enum.reject(headers, fn {name, _} -> name == "host" end)]
  end
end
```

Passing your own `:ssl_options` to hackney replaces its TLS defaults rather than adding to
them, so a wrapper that needs to pin an `https` request should build the full set from the
hostname the way `SafeURL.HTTPoison.get/3` does, or leave `https` to it.

And you can use it as:

```elixir
iex> CustomClient.request(:get, "http://230.10.10.10/data.json", "", [], safeurl: [block_reserved: false], recv_timeout: 500)
{:ok, %HTTPoison.Response{...}}
```

### Tesla

For [Tesla][lib-tesla], `SafeURL` provides a helper middleware out-of-the-box, which you can plug anywhere you're using `Tesla`.
It pins the request where it can do so without weakening TLS, which means any request without TLS, and
`https` with `Tesla.Adapter.Hackney`. With another adapter an `https` request is validated but not pinned,
so call [`pin/2`][docs-pin] yourself and pass the hostname through that adapter's connect options.
Place it after `Tesla.Middleware.FollowRedirects` if you follow redirects, so that every hop is validated:

```elixir
defmodule DocumentService do
  use Tesla

  plug Tesla.Middleware.BaseUrl, "https://document-service/"
  plug Tesla.Middleware.JSON
  plug SafeURL.TeslaMiddleware, schemes: ~w[https], allowlist: ["10.0.0.0/24"]

  def fetch(id) do
    get("/documents/#{id}")
  end
end
```

<br>

## Pinning the validated address

Validating a hostname and then handing that hostname to an HTTP client resolves it twice,
and the second lookup can return a different address than the one that was checked (DNS
rebinding). `pin/2` returns the URL with the host replaced by the validated address, together
with the original hostname for the `Host` header, SNI and certificate verification:

```elixir
iex> SafeURL.pin("https://includesecurity.com/robots.txt")
{:ok,
 %{
   url: "https://192.0.78.24/robots.txt",
   hostname: "includesecurity.com",
   address: {192, 0, 78, 24},
   scheme: "https",
   port: 443
 }}
```

Only the first validated address is returned; the others were validated too.

With [Req][lib-req], for example:

```elixir
with {:ok, %{url: url, hostname: hostname}} <- SafeURL.pin(url) do
  Req.get(url, connect_options: [hostname: hostname])
end
```

Every address the host resolves to, IPv4 and IPv6, has to pass validation, and a host without
any address is rejected with `:unresolved_host`.

<br>

## Custom DNS Resolver

In some cases you might want to use a custom strategy for DNS resolution. You can do so by
passing your own implementation of [`SafeURL.DNSResolver`][docs-dns] in the global or local
config.

Example use-cases of this are:

- Using a specific DNS server
- Avoiding network access in specific environments
- Mocking DNS resolution in tests

You can do so by implementing `DNSResolver`:

```elixir
defmodule TestDNSResolver do
  @behaviour SafeURL.DNSResolver

  @impl true
  def resolve("google.com"), do: {:ok, [{192, 168, 1, 10}]}
  def resolve("github.com"), do: {:ok, [{192, 168, 1, 20}]}
  def resolve(_domain),      do: {:ok, [{192, 168, 1, 99}]}
end
```

```elixir
config :safeurl, dns_module: TestDNSResolver
```

For more examples, see [`SafeURL.DNSResolver`][docs-dns] docs.

<br>

## Contributing

- [Fork][github-fork], Enhance, Send PR
- Lock issues with any bugs or feature requests
- Implement something from Roadmap
- Spread the word :heart:

<br>

## About

SafeURL is officially maintained by the team at [Slab][slab]. It was originally created by Nick Fox at
[Include Security][includesecurity].

<br>

[badge-github]: https://github.com/slab/safeurl-elixir/actions/workflows/ci.yml/badge.svg
[badge-version]: https://img.shields.io/hexpm/v/safeurl.svg
[badge-license]: https://img.shields.io/hexpm/l/safeurl.svg
[badge-downloads]: https://img.shields.io/hexpm/dt/safeurl.svg
[hexpm]: https://hex.pm/packages/safeurl
[github-build]: https://github.com/slab/safeurl-elixir/actions/workflows/ci.yml
[github-license]: https://github.com/slab/safeurl-elixir/blob/main/LICENSE
[github-fork]: https://github.com/slab/safeurl-elixir/fork
[slab]: https://slab.com/
[includesecurity]: https://github.com/IncludeSecurity
[readme-http]: #http-clients
[docs]: https://hexdocs.pm/safeurl
[docs-get]: https://hexdocs.pm/safeurl/SafeURL.HTTPoison.html#get/3
[docs-dns]: https://hexdocs.pm/safeurl/SafeURL.DNSResolver.html
[docs-pin]: https://hexdocs.pm/safeurl/SafeURL.html#pin/2
[lib-req]: https://hexdocs.pm/req
[lib-dns]: https://github.com/tungd/elixir-dns
[lib-tesla]: https://github.com/elixir-tesla/tesla
[lib-httpoison]: https://github.com/edgurgel/httpoison
