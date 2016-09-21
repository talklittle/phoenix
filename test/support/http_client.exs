defmodule Phoenix.Integration.HTTPClient do
  @doc """
  Performs HTTP Request and returns Response

    * method - The http method, for example :get, :post, :put, etc
    * url - The string url, for example "http://example.com"
    * headers - The map of headers
    * body - The optional string body. If the body is a map, it is converted
      to a URI encoded string of parameters

  ## Examples

      iex> HTTPClient.request(:get, "http://127.0.0.1", %{})
      {:ok, %Response{..})

      iex> HTTPClient.request(:post, "http://127.0.0.1", %{}, param1: "val1")
      {:ok, %Response{..})

      iex> HTTPClient.request(:get, "http://unknownhost", %{}, param1: "val1")
      {:error, ...}

  """
  def request(method, url, headers, body \\ "", httpc_request_options \\ [])
  def request(method, url, headers, body, httpc_request_options) when is_map body do
    request(method, url, headers, URI.encode_query(body), httpc_request_options)
  end
  def request(method, url, headers, body, httpc_request_options) do
    url     = String.to_char_list(url)
    headers = headers |> Map.put_new("content-type", "text/html")
    ct_type = headers["content-type"] |> String.to_char_list

    header = Enum.map headers, fn {k, v} ->
      {String.to_char_list(k), String.to_char_list(v)}
    end

    # Generate a random profile per request to avoid reuse
    profile = :crypto.strong_rand_bytes(4) |> Base.encode16 |> String.to_atom
    {:ok, pid} = :inets.start(:httpc, profile: profile)

    set_httpc_ipfamily(url, profile)

    resp =
      case method do
        :get -> :httpc.request(:get, {url, header}, [], [body_format: :binary] ++ httpc_request_options, pid)
        _    -> :httpc.request(method, {url, header, ct_type, body}, [], [body_format: :binary] ++ httpc_request_options, pid)
      end

    :inets.stop(:httpc, pid)
    format_resp(resp)
  end

  defp set_httpc_ipfamily(url_char_list, profile) do
    uri = URI.parse(to_string(url_char_list))
    ip = ip_for_inet_parse(uri.host)
    case :inet.parse_address(ip) do
      {:ok, {_, _, _, _, _, _, _, _}} ->
        :ok = :httpc.set_options([ipfamily: :inet6], profile)
      _ ->
        :ok = :httpc.set_options([ipfamily: :inet], profile)
    end
  end

  # cleanup IPv6 addresses like "[::1]" -> '::1'
  defp ip_for_inet_parse(ip) do
    ip =
      if String.starts_with?(ip, "[") and String.ends_with?(ip, "]") do
        String.slice(ip, 1..-2)
      else
        ip
      end
    to_char_list(ip)
  end

  defp format_resp({:ok, {{_http, status, _status_phrase}, headers, body}}) do
    {:ok, %{status: status, headers: headers, body: body}}
  end
  defp format_resp({:error, reason}), do: {:error, reason}
end
