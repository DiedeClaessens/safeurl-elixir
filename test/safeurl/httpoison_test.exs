defmodule SafeURL.HTTPoisonTest do
  use ExUnit.Case, async: true

  test "refuses to validate a request whose redirects it cannot follow" do
    assert_raise ArgumentError, ~r/:follow_redirect cannot be used/, fn ->
      SafeURL.HTTPoison.get("https://includesecurity.com/", [], follow_redirect: true)
    end
  end

  test "refuses redirects asked for through the hackney options" do
    assert_raise ArgumentError, ~r/:follow_redirect cannot be used/, fn ->
      SafeURL.HTTPoison.get("https://includesecurity.com/", [], hackney: [follow_redirect: true])
    end
  end

  test "rejects an unsafe URL before any request is made" do
    assert {:error, :unsafe_reserved} = SafeURL.HTTPoison.get("https://10.0.0.1/ssrf.txt")
  end

  test "validates with the options the caller passes" do
    options = [safeurl: [dns_module: TestDNSResolver, allowlist: ["127.0.0.0/16"]]]

    assert {:error, %HTTPoison.Error{}} =
             SafeURL.HTTPoison.get("http://allowlisted:9/", [], options)

    assert {:error, :unsafe_reserved} =
             SafeURL.HTTPoison.get("http://allowlisted:9/", [],
               safeurl: [dns_module: TestDNSResolver]
             )
  end
end
