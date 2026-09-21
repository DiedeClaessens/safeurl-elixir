if Code.ensure_loaded?(HTTPoison) do
  defmodule SafeURL.HTTPoison do
    @moduledoc since: "1.0.0"
    @moduledoc """
    A utility module that should be a drop-in replacement for `HTTPoison`. Only
    supports `get/3`.
    """

    alias SafeURL.Client

    @where "SafeURL.HTTPoison.get/3"

    @doc since: "1.0.0"
    @doc """
    Validate a URL and execute a GET request using `HTTPoison`.

    If the URL is safe, this function will execute the request using
    `HTTPoison`, returning the result directly. Otherwise, it will
    return error.

    The request is sent to the address that passed validation rather than to
    the hostname, so the name cannot resolve to a different address between the
    check and the request (see [`Pinning`](SafeURL.html#module-pinning)). The
    hostname is still what the destination sees in the `host` header, and what
    hackney offers as the server name and verifies the certificate against.
    Supplying your own `:ssl_options` or `:insecure` leaves that setup to you.

    Validation options go under `:safeurl`, the same ones
    [`SafeURL.pin/2`](SafeURL.html#pin/2) takes:

        SafeURL.HTTPoison.get(url, [], safeurl: [allowlist: ~w[10.0.0.0/8]])

    Everything else in `headers` and `options` is passed directly to
    `HTTPoison` when the request is executed, except for `:follow_redirect`: a redirect names a
    destination that was never validated, so following it would step around
    the check. Passing it, directly or under `:hackney`, raises
    `ArgumentError`.

    ## Examples

        iex> SafeURL.HTTPoison.get("https://10.0.0.1/ssrf.txt")
        {:error, :unsafe_reserved}

        iex> SafeURL.HTTPoison.get("https://google.com/")
        {:ok, %HTTPoison.Response{...}}

    """
    @spec get(binary(), HTTPoison.headers(), Keyword.t()) ::
            {:ok, HTTPoison.Response.t()}
            | {:error, HTTPoison.Error.t()}
            | {:error, SafeURL.error()}
            | {:error, :restricted}
    def get(url, headers \\ [], options \\ []) do
      {safeurl_options, options} = Keyword.pop(options, :safeurl, [])
      check_no_redirects!(options)

      with {:ok, pinned} <- SafeURL.pin(url, safeurl_options) do
        HTTPoison.get(
          pinned.url,
          Client.put_host_header(headers, pinned),
          put_tls_options(options, pinned)
        )
      end
    end

    # hackney honours the option under :hackney as well as at the top level.
    defp check_no_redirects!(options) do
      Client.check_no_redirects!(options, @where)
      Client.check_no_redirects!(Keyword.get(options, :hackney, []), @where)
    end

    defp put_tls_options(options, pinned) do
      hackney = Keyword.get(options, :hackney, [])

      if pinned.scheme == "https" and not Client.tls_configured?(hackney) do
        ssl_options = Client.hackney_ssl_options(pinned.hostname)
        Keyword.put(options, :hackney, Keyword.put(hackney, :ssl_options, ssl_options))
      else
        options
      end
    end
  end
end
