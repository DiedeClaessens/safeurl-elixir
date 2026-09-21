defmodule SafeURL.Client do
  @moduledoc false

  # Shared by the HTTP clients this library ships. They turn a pinned
  # destination into what a client needs so that the request reaches the
  # validated address while the hostname still governs what the destination
  # sees and what its certificate is checked against.

  # hackney derives its TLS options from the host it is given, so once a request
  # is pinned to an address it would offer that address as the server name and
  # verify the certificate against it. These are hackney's own defaults, rebuilt
  # from the hostname instead.
  def hackney_ssl_options(hostname) do
    hostname
    |> to_charlist()
    |> :hackney_ssl.check_hostname_opts()
    |> Kernel.++(:hackney_ssl.cipher_opts())
  end

  # The caller has said how the connection should be secured, so nothing is
  # rebuilt for them.
  def tls_configured?(options) do
    Keyword.has_key?(options, :ssl_options) or Keyword.has_key?(options, :insecure)
  end

  # A redirect names a destination the server chose, which this library never
  # got to validate, so a client that would follow one on its own is refused.
  def check_no_redirects!(options, where) do
    if Keyword.get(options, :follow_redirect, false) do
      raise ArgumentError, """
      :follow_redirect cannot be used with #{where}, because the destination of \
      a redirect is chosen by the server and would be requested without being \
      validated. Follow the redirect yourself, by validating the location that \
      came back and requesting it.\
      """
    end

    :ok
  end

  # The destination's own authority, which is the hostname plus the port when
  # it is not the scheme's default.
  def put_host_header(headers, pinned) when is_map(headers) do
    headers
    |> Map.reject(&host_header?/1)
    |> Map.put("host", authority(pinned))
  end

  def put_host_header(headers, pinned) do
    [{"host", authority(pinned)} | Enum.reject(headers, &host_header?/1)]
  end

  defp authority(pinned) do
    if pinned.port == URI.default_port(pinned.scheme) do
      pinned.hostname
    else
      "#{pinned.hostname}:#{pinned.port}"
    end
  end

  defp host_header?({name, _value}) do
    String.downcase(to_string(name)) == "host"
  end
end
