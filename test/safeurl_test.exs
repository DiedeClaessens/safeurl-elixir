defmodule SafeURLTest do
  use ExUnit.Case

  defmodule TestDNSResolver do
    @behaviour SafeURL.DNSResolver

    @impl true
    def resolve("mixed.example"), do: {:ok, [{192, 0, 78, 24}, {10, 0, 0, 1}]}
    def resolve("v6-only.example"), do: {:ok, [{0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}]}

    def resolve("v6-internal.example"),
      do: {:ok, [{192, 0, 78, 24}, {0xFD00, 0, 0, 0, 0, 0, 0, 1}]}

    def resolve("empty.example"), do: {:ok, []}
    def resolve("missing.example"), do: {:error, :nxdomain}
    def resolve(_domain), do: {:ok, [{192, 0, 78, 24}]}
  end

  describe "validate/2?" do
    test "returns true for only allowed schemes" do
      opts = [dns_module: TestDNSResolver]
      assert :ok = SafeURL.validate("http://includesecurity.com", opts)
      assert :ok = SafeURL.validate("https://includesecurity.com", opts)
      assert {:error, :unsafe_scheme} = SafeURL.validate("ftp://includesecurity.com", opts)

      opts = [schemes: ~w[ftp], dns_module: TestDNSResolver]
      assert :ok = SafeURL.validate("ftp://includesecurity.com", opts)
      assert {:error, :unsafe_scheme} = SafeURL.validate("http://includesecurity.com", opts)
    end

    test "returns false for reserved ranges" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://0.0.0.0/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://10.0.0.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://127.0.0.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://169.254.9.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://192.168.1.1/")
    end

    test "returns false for reserved IPv6 ranges" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[fd00::1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[fe80::1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[64:ff9b::a00:1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[2002:a00:1::]/")
    end

    test "checks an IPv4-mapped IPv6 address as the IPv4 address it carries" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::ffff:10.0.0.1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::ffff:a00:1]/")

      assert {:error, :unsafe_blocklist} =
               SafeURL.validate("http://[::ffff:5.5.5.5]/", blocklist: ["5.5.0.0/16"])

      assert :ok = SafeURL.validate("http://[::ffff:8.8.8.8]/")
    end

    test "every resolved address has to pass" do
      opts = [dns_module: TestDNSResolver]
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://mixed.example", opts)
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://v6-internal.example", opts)
      assert :ok = SafeURL.validate("http://v6-only.example", opts)
    end

    test "rejects a host without any address" do
      opts = [dns_module: TestDNSResolver]
      assert {:error, :unresolved_host} = SafeURL.validate("http://empty.example", opts)
      assert {:error, :unresolved_host} = SafeURL.validate("http://missing.example", opts)
      assert {:error, :unresolved_host} = SafeURL.validate("http:///path", opts)
      assert {:error, :unresolved_host} = SafeURL.validate("not a url", schemes: [nil])
    end

    test "returns true for reserved ranges if overridden" do
      opts = [block_reserved: false]

      assert :ok = SafeURL.validate("http://0.0.0.0/", opts)
      assert :ok = SafeURL.validate("http://10.0.0.1/", opts)
      assert :ok = SafeURL.validate("http://127.0.0.1/", opts)
      assert :ok = SafeURL.validate("http://169.254.9.1/", opts)
      assert :ok = SafeURL.validate("http://192.168.1.1/", opts)
    end

    test "blocking custom IP ranges" do
      opts = [blocklist: ["5.5.0.0/16", "100.0.0.0/24"], dns_module: TestDNSResolver]

      assert :ok = SafeURL.validate("http://includesecurity.com", opts)
      assert :ok = SafeURL.validate("http://3.3.3.3", opts)
      assert {:error, :unsafe_blocklist} = SafeURL.validate("http://5.5.5.5", opts)
      assert {:error, :unsafe_blocklist} = SafeURL.validate("http://100.0.0.50", opts)
    end

    test "only allows IPs in the allowlist when present" do
      opts = [allowlist: ["10.0.0.0/24"], dns_module: TestDNSResolver]

      assert :ok = SafeURL.validate("http://10.0.0.1/", opts)
      assert {:error, :unsafe_allowlist} = SafeURL.validate("http://72.254.45.178", opts)
      assert {:error, :unsafe_allowlist} = SafeURL.validate("https://includesecurity.com", opts)
    end

    test "detailed_errors can be switched off" do
      opts = [blocklist: ["5.5.0.0/16"], dns_module: TestDNSResolver, detailed_error: false]
      assert {:error, :restricted} = SafeURL.validate("ftp://includesecurity.com", opts)
      assert {:error, :restricted} = SafeURL.validate("http://5.5.5.5", opts)
      assert {:error, :restricted} = SafeURL.validate("http://0.0.0.0/", opts)
    end
  end

  describe "pin/2" do
    test "replaces the host with the validated address and keeps the hostname" do
      assert {:ok,
              %{
                url: "https://192.0.78.24:8443/data?x=1",
                hostname: "includesecurity.com",
                address: {192, 0, 78, 24}
              }} =
               SafeURL.pin("https://includesecurity.com:8443/data?x=1",
                 dns_module: TestDNSResolver
               )
    end

    test "keeps an address literal" do
      assert {:ok, %{url: "http://3.3.3.3/", hostname: "3.3.3.3", address: {3, 3, 3, 3}}} =
               SafeURL.pin("http://3.3.3.3/")
    end

    test "brackets an IPv6 address" do
      assert {:ok, %{url: "https://[2606:4700::1111]/", hostname: "v6-only.example"}} =
               SafeURL.pin("https://v6-only.example/", dns_module: TestDNSResolver)
    end

    test "returns the validation error" do
      assert {:error, :unsafe_reserved} = SafeURL.pin("http://10.0.0.1/")
      assert {:error, :restricted} = SafeURL.pin("http://10.0.0.1/", detailed_error: false)
    end
  end
end
