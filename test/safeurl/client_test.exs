defmodule SafeURL.ClientTest do
  use ExUnit.Case, async: true

  alias SafeURL.Client

  @pinned %{
    url: "https://93.184.216.34/data",
    hostname: "public.example",
    address: {93, 184, 216, 34},
    scheme: "https",
    port: 443
  }

  describe "put_host_header/2" do
    test "sets the hostname and drops one the caller sent" do
      headers = [{"Host", "spoofed"}, {"accept", "application/json"}]

      assert Client.put_host_header(headers, @pinned) ==
               [{"host", "public.example"}, {"accept", "application/json"}]
    end

    test "adds the port when it is not the scheme default" do
      assert [{"host", "public.example:8443"}] =
               Client.put_host_header([], %{@pinned | port: 8443})
    end

    test "works on the map form" do
      assert %{"host" => "public.example"} =
               Client.put_host_header(%{"HOST" => "spoofed"}, @pinned)
    end
  end

  describe "hackney_ssl_options/1" do
    test "verifies the certificate against the hostname, not the pinned address" do
      options = Client.hackney_ssl_options("public.example")

      assert Keyword.get(options, :verify) == :verify_peer
      assert Keyword.get(options, :server_name_indication) == ~c"public.example"
      assert Keyword.has_key?(options, :cacerts)
    end
  end

  describe "check_no_redirects!/2" do
    test "passes when the caller did not ask for redirects" do
      assert :ok = Client.check_no_redirects!([], "somewhere")
      assert :ok = Client.check_no_redirects!([follow_redirect: false], "somewhere")
    end

    test "raises when it did" do
      assert_raise ArgumentError, ~r/:follow_redirect cannot be used with somewhere/, fn ->
        Client.check_no_redirects!([follow_redirect: true], "somewhere")
      end
    end
  end
end
