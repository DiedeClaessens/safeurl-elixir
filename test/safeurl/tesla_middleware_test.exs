defmodule SafeURL.TeslaMiddlewareTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias SafeURL.TeslaMiddleware

  defmodule RedirectDNSResolver do
    @behaviour SafeURL.DNSResolver

    @impl true
    def resolve("public.example"), do: {:ok, [{93, 184, 216, 34}]}
    def resolve(_host), do: {:ok, [{10, 0, 0, 1}]}
  end

  test "can pass options" do
    Tesla.Mock.mock(fn _ -> %Tesla.Env{status: 200} end)

    client =
      Tesla.client(
        [{TeslaMiddleware, [allowlist: ["127.0.0.0/16"], dns_module: TestDNSResolver]}],
        Tesla.Mock
      )

    assert {:ok, %{status: 200}} = Tesla.get(client, "http://blocked_but_allowlisted")
  end

  test "sends the request to the validated address and keeps the hostname" do
    Tesla.Mock.mock(fn env ->
      assert env.url == "http://127.0.0.1/data"
      assert Tesla.get_header(env, "host") == "blocked_but_allowlisted"
      %Tesla.Env{status: 200}
    end)

    client = allowlisted_client()

    assert {:ok, %{status: 200}} = Tesla.get(client, "http://blocked_but_allowlisted/data")
  end

  test "replaces a host header the caller set" do
    Tesla.Mock.mock(fn env ->
      assert Tesla.get_headers(env, "host") == ["blocked_but_allowlisted"]
      %Tesla.Env{status: 200}
    end)

    client = allowlisted_client()

    assert {:ok, %{status: 200}} =
             Tesla.get(client, "http://blocked_but_allowlisted/data",
               headers: [{"Host", "spoofed"}]
             )
  end

  test "leaves an https request alone when the adapter cannot keep verifying the hostname" do
    Tesla.Mock.mock(fn env ->
      assert env.url == "https://blocked_but_allowlisted/data"
      assert Tesla.get_header(env, "host") == nil
      %Tesla.Env{status: 200}
    end)

    client = allowlisted_client()

    assert {:ok, %{status: 200}} = Tesla.get(client, "https://blocked_but_allowlisted/data")
  end

  defp allowlisted_client do
    Tesla.client(
      [{TeslaMiddleware, [allowlist: ["127.0.0.0/16"], dns_module: TestDNSResolver]}],
      Tesla.Mock
    )
  end

  test "validates every hop when it runs after the redirect middleware" do
    Tesla.Mock.mock(fn
      %{url: "http://93.184.216.34/start"} = env ->
        assert Tesla.get_header(env, "host") == "public.example"
        %Tesla.Env{status: 301, headers: [{"location", "http://internal.example/next"}]}

      %{url: url} ->
        flunk("the redirect to #{url} was requested without being validated")
    end)

    client =
      Tesla.client(
        [
          Tesla.Middleware.FollowRedirects,
          {TeslaMiddleware, dns_module: RedirectDNSResolver}
        ],
        Tesla.Mock
      )

    assert {:error, :unsafe_reserved} = Tesla.get(client, "http://public.example/start")
  end

  test "refuses an adapter that follows redirects on its own" do
    client =
      Tesla.client(
        [{TeslaMiddleware, dns_module: RedirectDNSResolver}],
        {Tesla.Adapter.Hackney, follow_redirect: true}
      )

    assert_raise ArgumentError, ~r/:follow_redirect cannot be used/, fn ->
      Tesla.get(client, "http://public.example/start")
    end
  end

  test "sends the port in the host header when it is not the default" do
    Tesla.Mock.mock(fn env ->
      assert env.url == "http://93.184.216.34:8080/data"
      assert Tesla.get_header(env, "host") == "public.example:8080"
      %Tesla.Env{status: 200}
    end)

    client = Tesla.client([{TeslaMiddleware, dns_module: RedirectDNSResolver}], Tesla.Mock)

    assert {:ok, %{status: 200}} = Tesla.get(client, "http://public.example:8080/data")
  end

  test "rebuilds the TLS options of a hackney client from the hostname" do
    env = hackney_env([])

    assert {:ok, pinned} = TeslaMiddleware.call(env, [], dns_module: RedirectDNSResolver)
    assert pinned.url == "https://93.184.216.34/data"
    assert pinned.opts[:adapter][:ssl_options] != nil
  end

  test "keeps TLS options the client was configured with" do
    env = hackney_env(ssl_options: [verify: :verify_none])

    assert {:ok, pinned} = TeslaMiddleware.call(env, [], dns_module: RedirectDNSResolver)
    assert pinned.url == "https://93.184.216.34/data"
    assert pinned.opts[:adapter] == nil
  end

  defp hackney_env(adapter_options) do
    %Tesla.Env{
      url: "https://public.example/data",
      __client__: %Tesla.Client{adapter: {Tesla.Adapter.Hackney, :call, [adapter_options]}}
    }
  end

  test "works with other middleware" do
    client =
      Tesla.client([Tesla.Middleware.Logger, {TeslaMiddleware, dns_module: TestDNSResolver}])

    assert capture_log(fn ->
             assert {:error, :unsafe_reserved} = Tesla.get(client, "http://blocked")
           end) =~ "http://blocked -> error: :unsafe_reserved"
  end
end
