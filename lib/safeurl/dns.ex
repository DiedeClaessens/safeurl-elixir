defmodule SafeURL.DNS do
  @moduledoc since: "1.1.0"
  @moduledoc """
  The default `SafeURL.DNSResolver`: looks up both the A and the AAAA
  records of a host with the `:dns` package, IPv4 addresses first.

  A host without records in either family resolves to `{:error, :nxdomain}`.
  """

  @behaviour SafeURL.DNSResolver

  @impl SafeURL.DNSResolver
  def resolve(host) do
    case records(host, :a) ++ records(host, :aaaa) do
      [] -> {:error, :nxdomain}
      ips -> {:ok, ips}
    end
  end

  defp records(host, type) do
    case DNS.resolve(host, type) do
      {:ok, ips} -> ips
      {:error, _reason} -> []
    end
  end
end
