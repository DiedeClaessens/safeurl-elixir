# Migrating to v1.1

`v1.1.0` fixes two advisories against every earlier release,
[CVE-2026-77866](https://cna.erlef.org/cves/CVE-2026-77866.html) and
[CVE-2026-77972](https://cna.erlef.org/cves/CVE-2026-77972.html). It stays on
the `1.x` line so that `{:safeurl, "~> 1.0"}` picks the fix up, but it does
reject some URLs that `v1.0.0` accepted. All of those were the holes.

## Every resolved address is checked

`v1.0.0` looked at the first IPv4 address of a host and treated everything else
as matching no range. An address written in IPv6 form passed even when its IPv4
form was blocked, IPv6 entries in a blocklist never matched, and a host with no
A record was accepted whatever it pointed at.

Now the host is resolved once and every address it has, in both families, has
to pass. IPv4-mapped (`::ffff:10.0.0.1`) and IPv4-compatible (`::10.0.0.1`)
addresses are checked as the IPv4 address they carry, and the reserved list
covers the IPv6 blocks IANA marks as not globally reachable.

**What changes for you:** a host whose AAAA record points into a reserved range
is now rejected, where before only its A record was judged.

## A host that resolves to nothing is rejected

`v1.0.0` passed `nil` into the range check for such a host, which matched
nothing and so allowed the request. These now fail with the new error
`{:error, :unresolved_host}`, which is part of `t:SafeURL.error/0`. Handle it
wherever you match on specific errors, or set `detailed_error: false` and match
on `{:error, :restricted}`.

This also catches hosts your resolver cannot answer for, such as names that
only exist in `/etc/hosts` or internationalised names that were not converted
to their ASCII form first.

## The default resolver queries A and AAAA

`:dns_module` now defaults to `SafeURL.DNS` rather than `DNS`. A resolver has
to return every address of every family for the guarantee above to hold, so if
you pass your own, make sure it does. `SafeURL.DNS` also bounds each lookup,
five seconds by default:

```elixir
config :safeurl, SafeURL.DNS, timeout: :timer.seconds(2)
```

The `c:SafeURL.DNSResolver.resolve/1` callback's typespec widened from
`{:error, :inet_res.res_error()}` to `{:error, term()}`. Existing
implementations keep working.

## Requests go to the address that passed

`validate/2` only ever returned a verdict, so the hostname was handed to an
HTTP client which resolved it a second time. A name that answered with a public
address for the check could answer with an internal one for the request.

`SafeURL.pin/2` returns the URL with the validated address in place of the
host, plus the hostname for the `Host` header, the server name and the
certificate check:

```elixir
with {:ok, %{url: url, hostname: hostname}} <- SafeURL.pin("https://example.com/data") do
  Req.get(url, connect_options: [hostname: hostname])
end
```

`SafeURL.HTTPoison.get/3` does this for you. `SafeURL.TeslaMiddleware` does it
for requests without TLS and for `https` with `Tesla.Adapter.Hackney`; with any
other adapter it validates but cannot pin, because keeping certificate
verification pointed at the hostname is spelled differently by each one.

**What changes for you:** nothing in the call, but the destination is reached
at the checked address. If you pass your own `:ssl_options` or `:insecure` to
`SafeURL.HTTPoison.get/3`, securing the connection stays yours.

## Redirects are not followed for you

`SafeURL.HTTPoison.get/3` used to pass `:follow_redirect` straight to hackney,
which then requested whatever destination the server named, without validating
it. That option now raises, whether it is given directly or under `:hackney`.
Follow the redirect yourself by validating the location that came back and
requesting it.

`SafeURL.TeslaMiddleware` raises the same way when the adapter is configured to
follow redirects itself, because it does that after the middleware has run. Put
the middleware after `Tesla.Middleware.FollowRedirects` instead, so that every
hop passes through it. The other order validates the first request only.

## The reserved list widened

`192.0.0.0/29` became `192.0.0.0/24`, which is what IANA reserves. If you route
traffic in `192.0.0.8` through `192.0.0.255`, allow it explicitly.
