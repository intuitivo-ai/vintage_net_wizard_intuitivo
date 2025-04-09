defmodule VintageNetWizard.Web.Router do
  @moduledoc false

  @combined_pattern ~r/^((\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+)(,((\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+))*$/
  @ip_regex ~r/^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/

  use Plug.Router
  use Plug.Debugger, otp_app: :vintage_net_wizard
  require Logger

  alias VintageNetWizard.{
    BackendServer,
    Web.Endpoint,
    WiFiConfiguration
  }

  # Create a pipeline for authenticated routes
  defp authenticate(conn, _opts) do
    conn |> VintageNetWizard.Plugs.ApiKeyAuth.call([])
  end

  plug(Plug.Static, from: {:vintage_net_wizard, "priv/static"}, at: "/")
  plug(Plug.Parsers, parsers: [Plug.Parsers.URLENCODED, :json], json_decoder: Jason)
  # Esta ruta es consultada por el frontend para actualizar su lista de puntos de acceso.
  plug(VintageNetWizard.Plugs.Activity, excluding: ["/api/v1/access_points"])
  plug(:match)
  plug(:dispatch, builder_opts())

  defp validate_and_split(input) when is_binary(input) do
    if Regex.match?(@combined_pattern, input) do
      {:ok, input}
    else
      {:error, "Invalid format"}
    end
  end

  defp valid_ip?(ip) when is_binary(ip) do
    Regex.match?(@ip_regex, ip)
  end

  # Protect specific routes with authentication
  # For example, to protect the root route:
  get "/" do
    conn = authenticate(conn, [])
    if conn.halted do
      conn
    else
      case BackendServer.configurations() do
        [] ->
          redirect(conn, "/networks")

        configs ->
          render_page(conn, "index.html", opts,
            configs: configs,
            configuration_status: configuration_status_details(),
            format_security: &WiFiConfiguration.security_name/1,
            get_key_mgmt: &WiFiConfiguration.get_key_mgmt/1
          )
      end
    end
  end

  post "/ssid/:ssid" do
    password = conn.body_params["password"]
    params = Map.put(conn.body_params, "ssid", ssid)

    case WiFiConfiguration.json_to_network_config(params) do
      {:ok, wifi_config} ->
        :ok = BackendServer.save(wifi_config)
        redirect(conn, "/")

      error ->
        {:ok, key_mgmt} = WiFiConfiguration.key_mgmt_from_string(conn.body_params["key_mgmt"])
        error_message = password_error_message(error)

        render_password_page(conn, key_mgmt, opts,
          ssid: ssid,
          error: error_message,
          password: password,
          user: conn.body_params["user"]
        )
    end
  end

  get "/ssid/:ssid" do
    key_mgmt =
      case BackendServer.access_points()
           |> Enum.find(&(&1.ssid == ssid)) do
        nil ->
          BackendServer.configurations()
          |> Enum.find(&(&1.ssid == ssid))
          |> Map.get(:key_mgmt)

        result ->
          get_key_mgmt_from_ap(result)
      end

    render_password_page(conn, key_mgmt, opts, ssid: ssid, password: "", error: "", user: "")
  end

  get "/redirect" do
    redirect_with_dnsname(conn)
  end

  get "/ncsi.txt" do
    redirect_with_dnsname(conn)
  end

  get "/connecttest.txt" do
    redirect_with_dnsname(conn)
  end

  get "/generate_204" do
    redirect_with_dnsname(conn)
  end

  get "/hotspot-detect.html" do
    render_page(conn, "apple_captive_portal.html", opts, dns_name: get_redirect_dnsname(conn))
  end

  get "/library/test/success.html" do
    render_page(conn, "apple_captive_portal.html", opts, dns_name: get_redirect_dnsname(conn))
  end

  get "/networks" do
    render_page(conn, "networks.html", opts, configuration_status: configuration_status_details(), error_ntp: "", method: "dhcp", error_address: "", error_netmask: "", error_gateway: "", error_name_servers: "")
  end

  get "/networks/new" do
    render_page(conn, "network_new.html", opts)
  end

  post "/networks/new" do
    ssid = Map.get(conn.body_params, "ssid")

    case Map.get(conn.body_params, "key_mgmt") do
      "none" ->
        {:ok, config} = WiFiConfiguration.json_to_network_config(conn.body_params)
        :ok = BackendServer.save(config)

        redirect(conn, "/")

      key_mgmt ->
        key_mgmt = String.to_existing_atom(key_mgmt)
        render_password_page(conn, key_mgmt, opts, ssid: ssid, password: "", error: "", user: "")
    end
  end

  post "/apn/new" do
    apn = Map.get(conn.body_params, "apn")

    BackendServer.save_apn(apn)
    redirect(conn, "/")

  end

  post "/ntp/new" do
    servesntp = Map.get(conn.body_params, "servesntp")

    case validate_and_split(servesntp) do
      {:ok, result} -> BackendServer.save_ntp(result)
                      redirect(conn, "/")
      {:error, message} -> render_page(conn, "networks.html", opts, configuration_status: configuration_status_details(), error_ntp: message, method: "dhcp", error_address: "", error_netmask: "", error_gateway: "", error_name_servers: "")
    end
  end

  post "/add/config_wifi" do

    method = Map.get(conn.body_params, "method", "dhcp")

    case method do
      "dhcp" ->
        BackendServer.save_method(%{method: :dhcp})

        redirect(conn, "/")

      "static" ->

        address = Map.get(conn.body_params, "address")

        netmask = Map.get(conn.body_params, "netmask")

        gateway = Map.get(conn.body_params, "gateway")

        name_servers = Map.get(conn.body_params, "name_servers")

        error_address = if valid_ip?(address) do
          ""
        else
          "Invalid Format"
        end

        error_netmask = if valid_ip?(netmask) do
          ""
        else
          "Invalid Format"
        end

        error_gateway = if valid_ip?(gateway) do
          ""
        else
          "Invalid Format"
        end

        error_name_servers =case validate_and_split(name_servers) do
          {:ok, _result} -> ""
          {:error, message} -> message
        end

        if error_address == "" and error_netmask == "" and error_gateway == "" and error_name_servers == "" do
          BackendServer.save_method(%{
            method: :static,
            address: address,
            netmask: netmask,
            gateway: gateway,
            name_servers: String.split(name_servers, ",")
          })

          redirect(conn, "/")
        else
          render_page(conn, "networks.html", opts, configuration_status: configuration_status_details(), error_ntp: "", method: method, error_address: error_address, error_netmask: error_netmask, error_gateway: error_gateway, error_name_servers: error_name_servers)
        end
    end
  end

  post "/lock/change" do

    lock = Map.get(conn.body_params, "lock_select")
    BackendServer.save_lock(lock)

    redirect(conn, "/")

  end

  post "/sharing/change" do

    internet_select = Map.get(conn.body_params, "internet_select")
    BackendServer.save_internet(internet_select)

    redirect(conn, "/")

  end

  get "/apply" do
    render_page(conn, "apply.html", opts, ssid: VintageNetWizard.APMode.ssid())
  end

  get "/complete" do
    :ok = BackendServer.complete()

    _ =
      Task.Supervisor.start_child(VintageNetWizard.TaskSupervisor, fn ->
        # We don't want to stop the server before we
        # send the response back.
        :timer.sleep(3000)
        Endpoint.stop_server(:shutdown)
      end)

    render_page(conn, "complete.html", opts)
  end

  # Handle API routes with authentication
  match "/api/v1/*path" do
    # First authenticate
    conn = VintageNetWizard.Plugs.ApiKeyAuth.call(conn, [])

    if conn.halted do
      # The API Key auth plug already sent a response
      conn
    else
      # Get the path segments from the path param
      path_segments = conn.path_params["path"] || []

      # Log for debugging
      Logger.debug("API v1 routing - path_segments: #{inspect(path_segments)}, path_params: #{inspect(conn.path_params)}")

      # Create a new path string
      new_path = "/" <> Enum.join(path_segments, "/")

      # Set up the connection for the API module
      conn = %{conn |
        path_info: path_segments,
        request_path: new_path,
        params: Map.drop(conn.params, ["path"]),
        path_params: Map.drop(conn.path_params, ["path"])
      }

      # Forward to the API module
      opts = VintageNetWizard.Web.ApiV1.init([])
      VintageNetWizard.Web.ApiV1.call(conn, opts)
    end
  end

  match "/api/v2/*path" do
    # First authenticate
    conn = VintageNetWizard.Plugs.ApiKeyAuth.call(conn, [])

    if conn.halted do
      # The API Key auth plug already sent a response
      conn
    else
      # Get the path segments from the path param
      path_segments = conn.path_params["path"] || []

      # Log for debugging
      Logger.debug("API v2 routing - path_segments: #{inspect(path_segments)}, path_params: #{inspect(conn.path_params)}")

      # Create a new path string
      new_path = "/" <> Enum.join(path_segments, "/")

      # Set up the connection for the API module
      conn = %{conn |
        path_info: path_segments,
        request_path: new_path,
        params: Map.drop(conn.params, ["path"]),
        path_params: Map.drop(conn.path_params, ["path"])
      }

      # Forward to the API module
      opts = VintageNetWizard.Web.ApiV2.init([])
      VintageNetWizard.Web.ApiV2.call(conn, opts)
    end
  end

  # Add a test route to verify authentication
  get "/auth_test" do
    conn = put_resp_content_type(conn, "application/json")

    try do
      conn = VintageNetWizard.Plugs.ApiKeyAuth.call(conn, [])

      if conn.halted do
        # Auth failed, but response was already sent by the plug
        conn
      else
        # Auth successful
        # Get claims from conn.assigns if they exist
        claims = conn.assigns[:jwt_claims] || %{}

        device_info = BackendServer.device_info()

        # Get system MAC address
        system_mac = case Enum.find(device_info, fn {label, _} -> label == "WiFi Address" end) do
          {_, mac} when is_binary(mac) -> mac
          _ -> "unknown"
        end

        # Respond with success info
        send_resp(conn, 200, Jason.encode!(%{
          authenticated: true,
          token_mac: claims["mac_address"],
          system_mac: system_mac,
          claims: claims
        }))
      end
    rescue
      e ->
        Logger.error("Authentication test error: #{inspect(e)}")
        send_resp(conn, 500, Jason.encode!(%{error: "Internal server error", details: inspect(e)}))
    end
  end

  match _ do
    send_resp(conn, 404, "oops")
  end

  defp redirect_with_dnsname(conn) do
    conn
    |> put_resp_header("location", get_redirect_dnsname(conn))
    |> send_resp(302, "")
  end

  defp get_redirect_dnsname(conn, to \\ nil) do
    dns_name = Application.get_env(:vintage_net_wizard, :dns_name, "wifi.config")

    port = if conn.port != 80 and conn.port != 443, do: ":#{conn.port}", else: ""

    "#{conn.scheme}://#{dns_name}#{port}#{to}"
  end

  defp redirect(conn, to) do
    conn
    |> put_resp_header("location", to)
    |> send_resp(302, "")
  end

  defp render_page(conn, page, opts, info \\ []) do
    info = [device_info: BackendServer.device_info(), ui: get_ui_config(opts)] ++ info

    resp =
      page
      |> template_file()
      |> EEx.eval_file(info, engine: Phoenix.HTML.Engine)
      # credo:disable-for-next-line
      |> Phoenix.HTML.Engine.encode_to_iodata!()

    send_resp(conn, 200, resp)
  end

  defp get_ui_config(opts) do
    default_ui_config = %{
      title: "Intuitivo Setup",
      title_color: "#11151A",
      button_color: "#007bff"
    }

    ui =
      opts
      |> Keyword.get(:ui, [])
      |> Enum.into(%{})

    Map.merge(default_ui_config, ui)
  end

  defp render_password_page(conn, :wpa_psk, opts, info) do
    render_page(conn, "configure_password.html", opts, info)
  end

  defp render_password_page(conn, :wpa_eap, opts, info) do
    render_page(conn, "configure_enterprise.html", opts, info)
  end

  defp template_file(page) do
    Application.app_dir(:vintage_net_wizard, ["priv", "templates", "#{page}.eex"])
  end

  defp password_error_message({:error, :password_required}), do: "Password required."

  defp password_error_message({:error, :password_too_short}),
    do: "Password is too short, must be greater than or equal to 8 characters."

  defp password_error_message({:error, :password_too_long}),
    do: "Password is too long, must be less than or equal to 64 characters."

  defp password_error_message({:error, :invalid_characters}),
    do: "Password as invalid characters double check you typed it correctly."

  defp get_key_mgmt_from_ap(%{flags: []}) do
    :none
  end

  defp get_key_mgmt_from_ap(%{flags: flags}) do
    cond do
      :psk in flags ->
        :wpa_psk

      :eap in flags ->
        :wpa_eap

      true ->
        :none
    end
  end

  defp configuration_status_details() do
    case BackendServer.configuration_status() do
      :good ->
        %{
          value: "Working",
          class: "text-success",
          title: "Device successfully connected to a network in the applied configuration"
        }

      :bad ->
        %{
          value: "Not Working",
          class: "text-danger",
          title:
            "Device was unable to connect to any network in the configuration due to bad password or a timeout while attempting."
        }

      :not_configured ->
        %{
          value: "Not configured yet",
          class: "text-warning",
          title: "Device waiting to be configured."
        }
    end
  end
end
