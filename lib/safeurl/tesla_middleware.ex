if Code.ensure_loaded?(Tesla) do
  defmodule SafeURL.TeslaMiddleware do
    @moduledoc since: "1.0.0"
    @moduledoc """
    Tesla middleware for validating URLs.

    ## Examples

        iex> Tesla.client([SafeURL.TeslaMiddleware]) |> Tesla.get("http://localhost/")
        {:error, :unsafe_reserved}

    ## Pinning

    Where it can, the middleware also sends the request to the address that
    passed validation instead of to the hostname, so the name cannot resolve to
    a different address between the check and the request (see
    [`Pinning`](SafeURL.html#module-pinning)). The destination still sees the
    hostname in the `Host` header.

    Doing that over TLS means telling the adapter to keep verifying the
    certificate against the hostname, which every adapter spells differently,
    so pinning applies to:

      * any request without TLS, whatever the adapter, and
      * `Tesla.Adapter.Hackney` over TLS.

    With any other adapter an `https` request is validated but not pinned, and
    the rebinding window stays open. To close it there, call `SafeURL.pin/2`
    yourself and pass the hostname through your adapter's connect options.

    ## Redirects

    A redirect names a destination the server chose, so it has to be validated
    like any other. Place this middleware *after* `Tesla.Middleware.FollowRedirects`
    and every hop passes through it:

        plug Tesla.Middleware.FollowRedirects
        plug SafeURL.TeslaMiddleware

    The other order validates the first request only.
    """
    @behaviour Tesla.Middleware

    alias SafeURL.Client

    @where "SafeURL.TeslaMiddleware"

    def call(%Tesla.Env{url: url} = env, next, options) do
      check_no_redirects!(env)

      with {:ok, pinned} <- SafeURL.pin(url, options) do
        env
        |> pin(pinned)
        |> Tesla.run(next)
      end
    end

    # An adapter that follows redirects itself does so after this middleware
    # has run, so the destination it picks is never validated. It can be asked
    # to on the client or on the single request.
    defp check_no_redirects!(env) do
      {_module, options} = adapter(env)

      Client.check_no_redirects!(options, @where)
      Client.check_no_redirects!(Keyword.get(env.opts, :adapter, []), @where)
    end

    defp pin(env, pinned) do
      {module, adapter_options} = adapter(env)

      cond do
        pinned.scheme != "https" -> repoint(env, pinned, [])
        module != Tesla.Adapter.Hackney -> env
        Client.tls_configured?(adapter_options) -> repoint(env, pinned, [])
        true -> repoint(env, pinned, ssl_options: Client.hackney_ssl_options(pinned.hostname))
      end
    end

    # A caller who configured TLS themselves, on the client or on the request,
    # keeps it, the same way supplying :ssl_options to
    # SafeURL.HTTPoison.get/3 leaves that setup to them.
    defp repoint(env, pinned, tls_options) do
      %{
        env
        | url: pinned.url,
          headers: Client.put_host_header(env.headers, pinned),
          opts: put_adapter_options(env.opts, tls_options)
      }
    end

    defp put_adapter_options(opts, []) do
      opts
    end

    defp put_adapter_options(opts, tls_options) do
      Keyword.update(opts, :adapter, tls_options, &Keyword.merge(tls_options, &1))
    end

    # Tesla resolves the adapter before the middleware stack runs, so the
    # client carries the one this request will actually use, along with the
    # options it was configured with.
    defp adapter(env) do
      case env.__client__ do
        %Tesla.Client{adapter: {module, _fun, [options]}} when is_list(options) ->
          {module, options}

        %Tesla.Client{adapter: {module, _fun, _args}} ->
          {module, []}

        _other ->
          {nil, []}
      end
    end
  end
end
