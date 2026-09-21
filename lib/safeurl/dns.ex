defmodule SafeURL.DNS do
  @moduledoc since: "1.1.0"
  @moduledoc """
  The default `SafeURL.DNSResolver`: looks up both the A and the AAAA
  records of a host with the `:dns` package, IPv4 addresses first.

  A host without records in either family resolves to `{:error, :nxdomain}`.

  Both lookups are bounded by `:timeout` (5 seconds by default), which can
  be configured with

      config :safeurl, SafeURL.DNS, timeout: :timer.seconds(2)

  """

  @behaviour SafeURL.DNSResolver

  @default_timeout :timer.seconds(5)

  @impl SafeURL.DNSResolver
  def resolve(host) do
    case records(host, :a) ++ records(host, :aaaa) do
      [] -> {:error, :nxdomain}
      ips -> {:ok, ips}
    end
  end

  # DNS.resolve/4 waits forever by default, which would hang the caller on a
  # server that accepts the query and never answers.
  defp records(host, type) do
    case DNS.resolve(host, type, [], timeout()) do
      {:ok, ips} -> ips
      {:error, _reason} -> []
    end
  end

  defp timeout do
    :safeurl
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(:timeout, @default_timeout)
  end
end
