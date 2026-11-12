defmodule VintageNetWizard.Web.EndpointTest do
  # The wizard's listeners must only speak HTTP/1.1 (see Web.Endpoint). These
  # tests replace the web server that test_helper.exs starts on the configured
  # port, so they can't run alongside other tests.
  use ExUnit.Case, async: false

  alias VintageNetWizard.Web.Endpoint

  @path "/api/v1/configuration/status"

  # The test certificate comes from a throwaway CA that clients don't know.
  @tls_client [verify: :verify_none]

  setup_all do
    %{ssl: test_certificate!()}
  end

  setup do
    stop_endpoint()

    on_exit(fn ->
      # Leave a plain HTTP server running, as test_helper.exs does, for the
      # other tests.
      stop_endpoint()
      :ok = Endpoint.start_server()
    end)
  end

  describe "HTTPS listener (ssl: keyfile + certfile, as firmware-nerves runs it)" do
    setup %{ssl: ssl} do
      :ok = Endpoint.start_server(ssl: ssl)
    end

    test "serves HTTP/1.1, also to clients that offer h2 first" do
      for protocols <- [[:http1], [:http2, :http1]] do
        assert {:ok, conn} = connect(:https, protocols)
        assert Mint.HTTP.protocol(conn) == :http1
        assert get(conn, @path) == {:ok, {200, ~s("not_configured")}}
      end
    end

    test "does not negotiate h2 with ALPN" do
      assert {:error, %Mint.TransportError{reason: reason}} = connect(:https, [:http2])
      assert {:tls_alert, {:no_application_protocol, _}} = reason
    end

    test "does not negotiate h2 with NPN" do
      assert {:ok, socket} =
               :ssl.connect(
                 ~c"localhost",
                 port(),
                 [
                   versions: [:"tlsv1.2"],
                   client_preferred_next_protocols: {:client, ["h2"], "http/1.1"}
                 ] ++ @tls_client
               )

      refute :ssl.negotiated_protocol(socket) == {:ok, "h2"}
      :ssl.close(socket)
    end

    test "does not upgrade to h2c" do
      assert {:ok, socket} =
               :ssl.connect(
                 ~c"localhost",
                 port(),
                 [:binary, active: false, alpn_advertised_protocols: ["http/1.1"]] ++ @tls_client
               )

      :ok = :ssl.send(socket, h2c_upgrade_request())
      assert {:ok, "HTTP/1.1 " <> response} = :ssl.recv(socket, 0, 5_000)
      refute response =~ ~r/^101 /
      :ssl.close(socket)
    end
  end

  describe "HTTP listener (no ssl)" do
    setup do
      :ok = Endpoint.start_server()
    end

    test "serves HTTP/1.1" do
      assert {:ok, conn} = connect(:http, [:http1])
      assert get(conn, @path) == {:ok, {200, ~s("not_configured")}}
    end

    test "refuses h2c with prior knowledge" do
      # Mint sends the HTTP/2 preface without waiting for the server, so the
      # refusal only shows up when it reads the answer...
      assert {:ok, conn} = connect(:http, [:http2])
      assert {:error, _} = get(conn, @path)

      # ...which is an HTTP/1.1 error instead of the server's SETTINGS frame.
      assert {:ok, socket} = :gen_tcp.connect(~c"localhost", port(), [:binary, active: false])
      :ok = :gen_tcp.send(socket, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
      assert {:ok, "HTTP/1.1 501 " <> _} = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.close(socket)
    end

    test "answers Upgrade: h2c requests over HTTP/1.1" do
      assert {:ok, socket} = :gen_tcp.connect(~c"localhost", port(), [:binary, active: false])
      :ok = :gen_tcp.send(socket, h2c_upgrade_request())
      assert {:ok, "HTTP/1.1 200 " <> _} = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.close(socket)
    end
  end

  defp port(), do: Application.fetch_env!(:vintage_net_wizard, :port)

  defp connect(scheme, protocols) do
    transport_opts = if scheme == :https, do: @tls_client, else: []

    Mint.HTTP.connect(scheme, "localhost", port(),
      protocols: protocols,
      mode: :passive,
      transport_opts: transport_opts
    )
  end

  # GET over a Mint connection, then close it.
  defp get(conn, path) do
    {:ok, conn, ref} = Mint.HTTP.request(conn, "GET", path, [], nil)
    result = receive_response(conn, ref, %{status: nil, body: ""})
    _ = Mint.HTTP.close(conn)
    result
  end

  defp receive_response(conn, ref, acc) do
    case Mint.HTTP.recv(conn, 0, 5_000) do
      {:ok, conn, responses} ->
        acc =
          Enum.reduce(responses, acc, fn
            {:status, ^ref, status}, acc -> %{acc | status: status}
            {:data, ^ref, data}, acc -> %{acc | body: acc.body <> data}
            {:done, ^ref}, acc -> Map.put(acc, :done, true)
            _headers, acc -> acc
          end)

        if acc[:done],
          do: {:ok, {acc.status, acc.body}},
          else: receive_response(conn, ref, acc)

      {:error, _conn, error, _responses} ->
        {:error, error}
    end
  end

  # HTTP/1.1 request asking to switch to h2c (RFC 7540, 3.2). HTTP2-Settings
  # carries SETTINGS_MAX_CONCURRENT_STREAMS = 100.
  defp h2c_upgrade_request() do
    "GET #{@path} HTTP/1.1\r\n" <>
      "host: localhost\r\n" <>
      "connection: Upgrade, HTTP2-Settings\r\n" <>
      "upgrade: h2c\r\n" <>
      "http2-settings: AAMAAABk\r\n" <>
      "\r\n"
  end

  # RSA key and certificate (from a throwaway CA) in PEM files, which is what
  # firmware-nerves passes to VintageNetWizard.run_wizard/1.
  defp test_certificate!() do
    dir = Path.join(System.tmp_dir!(), "vnw-endpoint-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    rsa = [key: {:rsa, 2048, 65_537}, digest: :sha256]
    chain = :public_key.pkix_test_data(%{root: rsa, peer: rsa})
    {key_type, key_der} = Keyword.fetch!(chain, :key)
    keyfile = Path.join(dir, "wizard.key")
    certfile = Path.join(dir, "wizard.crt")

    File.write!(keyfile, :public_key.pem_encode([{key_type, key_der, :not_encrypted}]))

    File.write!(
      certfile,
      :public_key.pem_encode([{:Certificate, Keyword.fetch!(chain, :cert), :not_encrypted}])
    )

    [keyfile: keyfile, certfile: certfile]
  end

  defp stop_endpoint() do
    if DynamicSupervisor.count_children(Endpoint).active > 0 do
      :ok = Endpoint.stop_server(:shutdown)
    end

    wait_for_port_release(100)
  end

  # Ranch's listening socket closes a moment after its process exits, so a new
  # listener on the same port can hit :eaddrinuse. Wait until it can bind.
  defp wait_for_port_release(attempts) do
    case :gen_tcp.listen(port(), reuseaddr: true) do
      {:ok, socket} ->
        :gen_tcp.close(socket)

      {:error, :eaddrinuse} when attempts > 0 ->
        Process.sleep(10)
        wait_for_port_release(attempts - 1)
    end
  end
end
