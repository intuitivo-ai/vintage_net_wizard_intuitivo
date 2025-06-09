defmodule VintageNetWizard.Web.ApiV2 do
  @moduledoc """
  V2 API endpoints for VintageNetWizard

  This module provides enhanced API endpoints with richer metadata and consistent response formats.
  All responses include timestamps and detailed status information.

  ## Endpoints

  ### GET /health
    Health check endpoint to verify API availability.

  ### GET /networks/scan
    Scan for available WiFi networks.

  ### GET /configuration/status
    Get detailed configuration status.

  ### POST /lock
    Control lock state.

  ### PUT /lock-type
    Update lock type configuration.

  ### PUT /config
    Update complete device configuration including WiFi networks with priorities.

    #### WiFi Networks Priority Handling:
    - Each network can optionally include a "priority" field (integer, starting from 1)
    - If no priority is specified, networks are assigned automatic priorities in order (1, 2, 3...)
    - Lower numbers have higher priority (1 = highest priority, 2 = second priority, etc.)
    - The first network added without explicit priority becomes the primary/default network
    - Networks are sorted by priority before being applied to the system

    Example:
    ```json
    {
      "wifi": {
        "networks": [
          {"ssid": "Home-WiFi", "password": "secret123", "priority": 1},
          {"ssid": "Backup-WiFi", "password": "backup456"},  // Gets priority 2
          {"ssid": "Guest-WiFi", "password": "guest789", "priority": 3}
        ]
      }
    }
    ```
  """

  use Plug.Router

  require Logger

  import Plug.Conn, only: [
    merge_resp_headers: 2,
    put_resp_content_type: 2,
    send_resp: 3
  ]

  @valid_lock_types ["retrofit", "imbera", "southco", "duenorth"]

  @cors_headers [
    {"access-control-allow-origin", "*"},
    {"access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS"},
    {"access-control-allow-headers", "content-type, authorization"},
    {"access-control-max-age", "86400"}
  ]

  @type error_type ::
    {:error, :invalid_state | :missing_state | :missing_config | :password_required} |
    {:error, :invalid_config, [String.t()]}

  alias Plug.Conn
  alias VintageNetWizard.BackendServer
  alias VintageNetWizard.Web.Endpoint
  alias VintageNetWizard.WiFiConfiguration

  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:match)
  plug(:dispatch)

  get "/health" do

    Logger.info("API_V2_GET_HEALTH_REQUEST")

    device_info = BackendServer.device_info()

    # Extract values from the device_info list
    mac_address = device_info
                 |> Enum.find(fn {label, _} -> label == "WiFi Address" end)
                 |> elem(1)

    firmware_version = device_info
                     |> Enum.find(fn {label, _} -> label == "Firmware version" end)
                     |> elem(1)

    Logger.info("API_V2_SEND_HEALTH_REQUEST")

    send_json(conn, 200, %{
      status: "ok",
      version: "2.0.0",
      mac_address: mac_address,
      firmware_version: firmware_version,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  get "/networks/scan" do

    Logger.info("API_V2_GET_NETWORKS_SCAN_REQUEST")

    networks =
      BackendServer.access_points()
      |> VintageNetWiFi.summarize_access_points()
      |> Enum.map(fn ap ->
        %{
          ssid: ap.ssid,
          signal_percent: ap.signal_percent,
          frequency: ap.frequency,
          band: ap.band,
          channel: ap.channel,
          flags: Enum.map(ap.flags, &to_string/1)
        }
      end)

    send_json(conn, 200, %{networks: networks})
  end

  get "/configuration/status" do

    Logger.info("API_V2_GET_CONFIGURATION_STATUS_REQUEST")

    status = BackendServer.configuration_status()

    response = %{
      status: status,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      details: BackendServer.configuration_status_details(status)
    }

    send_json(conn, 200, response)
  end

  get "/cameras" do
    cameras = BackendServer.get_cameras()  # Using existing function
    send_json(conn, 200, %{cameras: cameras})
  end

  post "/cameras/initialize" do
    #BackendServer.init_cameras()  # Using existing function

    In2Firmware.Services.Operations.re_init_http()

    response = %{
      status: "success",
      message: "Cameras initialized successfully",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    send_json(conn, 200, response)
  end

  post "/reboot" do
    # Ejecutar la función de reinicio
    BackendServer.reboot()

    # Enviar respuesta OK
    send_json(conn, 200, %{status: "success", message: "Rebooting device..."})
  end

  get "/door" do
    door_status = BackendServer.get_door()

    response = %{
      status: door_status["door"],
      lastChanged: door_status["timestamp"]
    }

    send_json(conn, 200, response)
  end

  get "/lock" do
    lock_status = BackendServer.get_lock()
    lock_type = BackendServer.get_lock_type()

    response = %{
      status: lock_status.lock || "locked",
      lastChanged: lock_status.timestamp || DateTime.utc_now() |> DateTime.to_iso8601(),
      type: lock_type["lock_type"] || "retrofit",
      isWorking: lock_status.working
    }

    send_json(conn, 200, response)
  end

  post "/lock" do
    case get_body(conn) do
      %{"desired_state" => desired_state} when desired_state in ["locked", "unlocked"] ->
        should_lock = desired_state == "locked"
        BackendServer.change_lock(should_lock)

        response = %{
          status: "success",
          message: "Lock state changed successfully",
          current_state: desired_state,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }
        send_json(conn, 200, response)

      %{"desired_state" => _invalid} ->
        send_error_response(conn, {:error, :invalid_state})

      _ ->
        send_error_response(conn, {:error, :missing_state})
    end
  end

  put "/lock-type" do
    case get_body(conn) do
      %{"lockType" => lock_type} when lock_type in @valid_lock_types ->
        BackendServer.save_lock(lock_type)

        response = %{
          status: "success",
          message: "Lock type updated successfully",
          current_type: lock_type,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        send_json(conn, 200, response)

      %{"lockType" => _invalid} ->
        response = %{
          error: "validation_error",
          code: "INVALID_LOCK_TYPE",
          message: "lockType must be one of: retrofit, imbera, southco",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        send_json(conn, 400, response)

      _ ->
        response = %{
          error: "validation_error",
          code: "MISSING_LOCK_TYPE",
          message: "lockType is required",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        send_json(conn, 400, response)
    end
  end

  get "/config" do

    Logger.info("API_V2_GET_CONFIG_REQUEST")

    config = BackendServer.get_board_config()  # Using existing function
    send_json(conn, 200, config)
  end

  put "/complete" do

    Logger.info("API_V2_PUT_COMPLETE_REQUEST")

    :ok = BackendServer.complete()
    BackendServer.stop_cameras()

    _ =
      Task.Supervisor.start_child(VintageNetWizard.TaskSupervisor, fn ->
        # We don't want to stop the server before we
        # send the response back.
        :timer.sleep(3000)
        Endpoint.stop_server(:shutdown)
      end)

    response = %{
      status: "success",
      message: "Configuration completed and server stopping",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }
    send_json(conn, 200, response)
  end


  put "/config" do

    Logger.info("API_V2_PUT_CONFIG_REQUEST #{inspect(get_body(conn))}")

    case get_body(conn) do
      config when is_map(config) and map_size(config) > 0 ->
        with :ok <- validate_config(config),
             :ok <- apply_config(config) do
          response = %{
            status: "success",
            message: "Configuration updated successfully",
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
          }
          send_json(conn, 200, response)
        else
          {:error, errors} ->
            send_error_response(conn, {:error, :invalid_config, errors})
        end

      _ ->
        send_error_response(conn, {:error, :missing_config})
    end
  end

  # Configuration validation and application helpers
  defp validate_config(config) do
    with {:ok, _} <- validate_lock_type(config),
         {:ok, _} <- validate_wifi_config(config),
         {:ok, _} <- validate_mobile_network(config),
         {:ok, _} <- validate_hotspot_output(config),
         {:ok, _} <- validate_nama_config(config),
         {:ok, _} <- validate_ntp_config(config) do
      :ok
    else
      {:error, error} -> {:error, [error]}
    end
  end

  defp validate_lock_type(%{"lockType" => type}) when type in ["retrofit", "imbera", "southco"], do: {:ok, type}
  defp validate_lock_type(_), do: {:error, "Invalid lock type"}

  defp validate_wifi_config(%{"wifi" => %{"method" => method} = wifi}) when method in ["dhcp", "static"] do
    case method do
      "static" -> validate_static_config(wifi)
      "dhcp" -> {:ok, wifi}
    end
  end
  defp validate_wifi_config(%{"wifi" => _}), do: {:error, "Invalid WiFi configuration"}
  defp validate_wifi_config(_), do: {:ok, nil}  # Optional field

  defp validate_static_config(%{"static_config" => config}) do
    with true <- is_valid_ip?(config["address"]),
         true <- is_valid_ip?(config["netmask"]),
         true <- is_valid_ip?(config["gateway"]),
         true <- is_valid_nameservers?(config["name_servers"]) do
      {:ok, config}
    else
      false -> {:error, "Invalid static IP configuration"}
    end
  end

  defp validate_mobile_network(%{"mobileNetwork" => %{"apn" => apn}}) when is_binary(apn), do: {:ok, apn}
  defp validate_mobile_network(%{"mobileNetwork" => %{"apn" => ""}}), do: {:ok, nil}
  defp validate_mobile_network(%{"mobileNetwork" => _}), do: {:error, "Invalid mobile network configuration"}
  defp validate_mobile_network(_), do: {:ok, nil}  # Optional field

  defp validate_hotspot_output(%{"hotspotOutput" => output}) when output in ["wlan0_to_eth0", "eth0_to_wlan0", "wwan0_to_eth0", "wwan0_to_wlan0", "disabled"], do: {:ok, output}
  defp validate_hotspot_output(%{"hotspotOutput" => ""}), do: {:ok, nil}
  defp validate_hotspot_output(%{"hotspotOutput" => _}), do: {:error, "Invalid hotspot output"}
  defp validate_hotspot_output(_), do: {:ok, nil}  # Optional field

  defp validate_nama_config(%{"nama" => %{"profile" => profile}}) when is_integer(profile), do: {:ok, profile}
  defp validate_nama_config(%{"nama" => _}), do: {:error, "Invalid NAMA configuration"}
  defp validate_nama_config(_), do: {:ok, nil}  # Optional field

  defp validate_ntp_config(%{"ntp" => ntp}) when is_binary(ntp) do
    if ntp == "" do
      {:ok, nil}
    else
      # Regex para validar IPs o hostnames, uno o más separados por comas
      ip_regex = ~r/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\w+(?:\.\w+)+)(?:,(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\w+(?:\.\w+)+))*$/

      if String.match?(ntp, ip_regex) do
        {:ok, ntp}
      else
        {:error, "Invalid NTP format - must be one or more comma-separated IP addresses or hostnames"}
      end
    end
  end
  defp validate_ntp_config(%{"ntp" => _}), do: {:error, "Invalid NTP configuration"}
  defp validate_ntp_config(_), do: {:ok, nil}  # Optional field

  defp apply_config(config) do
    # Apply each configuration section if present
    with :ok <- maybe_apply_lock_type(config),
         :ok <- maybe_apply_wifi_config(config),
         :ok <- maybe_apply_mobile_network(config),
         :ok <- maybe_apply_hotspot_output(config),
         :ok <- maybe_apply_nama_config(config),
         :ok <- maybe_apply_ntp_config(config) do
      :ok
    end
  end

  defp maybe_apply_lock_type(%{"lockType" => type}) when not is_nil(type) do
    BackendServer.save_lock(type)
    :ok
  end
  defp maybe_apply_lock_type(_), do: :ok

  defp maybe_apply_wifi_config(%{"wifi" => wifi}) when not is_nil(wifi) do
    # Apply network method and configurations
    case wifi["method"] do
      "static" ->
        BackendServer.save_method(%{
          method: :static,
          address: wifi["static_config"]["address"],
          netmask: wifi["static_config"]["netmask"],
          gateway: wifi["static_config"]["gateway"],
          name_servers: String.split(wifi["static_config"]["name_servers"], ",")
        })
      "dhcp" ->
        BackendServer.save_method(%{method: :dhcp})
    end

    # Handle WiFi networks - detect additions and deletions
    case wifi["networks"] do
      networks when is_list(networks) ->
        # Get current configurations to detect deletions
        current_configs = BackendServer.configurations()
        current_ssids = Enum.map(current_configs, & &1.ssid) |> MapSet.new()
        new_ssids = Enum.map(networks, & &1["ssid"]) |> MapSet.new()

        # Find SSIDs that were deleted (in current but not in new)
        deleted_ssids = MapSet.difference(current_ssids, new_ssids)

        # Delete removed networks
        Enum.each(deleted_ssids, fn ssid ->
          BackendServer.delete_configuration(ssid)
        end)

        # Add/update new networks
        if networks != [] do
          # Convert networks to the format expected by BackendServer
          network_configs = Enum.map(networks, fn network ->
            {:ok, cfg} = WiFiConfiguration.json_to_network_config(network)
            # Save individual configuration
            BackendServer.save(cfg)
            cfg
          end)

          # Handle priority order - assign automatic priorities if not specified
          networks_with_priority = assign_network_priorities(networks)

          # Extract priority order for set_priority_order
          priority_order = Enum.map(networks_with_priority, & &1["ssid"])

          # Set the priority order using the existing function
          :ok = BackendServer.set_priority_order(priority_order)

          Logger.info("API_V2_WIFI_NETWORKS_PRIORITY_ORDER_SET: #{inspect(priority_order)}")

          # Also save all networks at once to .psk_wifi.json file
          BackendServer.save_wifi_networks(networks_with_priority)
        else
          # If no networks provided, save empty list and clear all WiFi configurations
          Logger.info("API_V2_CLEARING_ALL_WIFI_NETWORKS")
          BackendServer.save_wifi_networks([])

          # Ensure all current configurations are explicitly cleared
          current_configs = BackendServer.configurations()
          Enum.each(current_configs, fn config ->
            BackendServer.delete_configuration(config.ssid)
          end)
        end
      _ -> :ok
    end

    # When no networks are configured, use apply() with a fake configuration that will fail
    # This ensures the timeout timer is activated and will return to AP mode automatically
    current_configs = BackendServer.configurations()
    if current_configs == [] do
      Logger.info("API_V2_NO_WIFI_NETWORKS_CREATING_FAKE_CONFIG_TO_TRIGGER_TIMEOUT")

      # Create a fake configuration that will definitely fail to connect
      # This triggers the apply() -> timeout -> back to AP mode flow
      fake_config = %{
        ssid: "__INTUITIVO_FAKE_FAIL__",
        mode: :infrastructure,
        key_mgmt: :none
      }

      # Save the fake configuration temporarily
      BackendServer.save(fake_config)

      # Apply it - this will start the timeout timer
      case BackendServer.apply() do
        :ok ->
          Logger.info("API_V2_FAKE_CONFIG_APPLIED_TIMEOUT_TIMER_ACTIVATED")
          # Immediately delete the fake configuration so it doesn't persist
          BackendServer.delete_configuration(fake_config.ssid)
          # Also ensure empty list is saved to .psk_wifi.json file
          BackendServer.save_wifi_networks([])

          # Clean up VintageNet configuration to prevent persistence of fake config
          # Configure VintageNet with empty networks to overwrite the fake config
          ap_ifname = BackendServer.get_ap_ifname()
          VintageNet.configure(ap_ifname, %{
            type: VintageNetWiFi,
            vintage_net_wifi: %{networks: []},
            ipv4: %{method: :dhcp}
          })
          Logger.info("API_V2_VINTAGE_NET_CLEANED_OF_FAKE_CONFIG")
          :ok
        {:error, reason} = error ->
          Logger.error("API_V2_FAILED_TO_APPLY_FAKE_CONFIG: #{inspect(reason)}")
          # Clean up fake config even on error
          BackendServer.delete_configuration(fake_config.ssid)
          BackendServer.save_wifi_networks([])

          # Clean up VintageNet configuration even on error
          ap_ifname = BackendServer.get_ap_ifname()
          VintageNet.configure(ap_ifname, %{
            type: VintageNetWiFi,
            vintage_net_wifi: %{networks: []},
            ipv4: %{method: :dhcp}
          })
          Logger.info("API_V2_VINTAGE_NET_CLEANED_OF_FAKE_CONFIG_AFTER_ERROR")
          error
      end
    else
      # Apply configurations normally when networks exist
      case BackendServer.apply() do
        :ok ->
          Logger.info("API_V2_WIFI_CONFIGURATIONS_APPLIED_SUCCESSFULLY")
          :ok
        {:error, reason} = error ->
          Logger.error("API_V2_FAILED_TO_APPLY_WIFI_CONFIGURATIONS: #{inspect(reason)}")
          error
      end
    end

  end
  defp maybe_apply_wifi_config(_), do: :ok

  defp maybe_apply_mobile_network(%{"mobileNetwork" => %{"apn" => apn}}) when not is_nil(apn) do
    BackendServer.save_apn(apn)
    :ok
  end
  defp maybe_apply_mobile_network(_), do: :ok

  defp maybe_apply_hotspot_output(%{"hotspotOutput" => output}) when not is_nil(output) do
    BackendServer.save_internet(output)
    :ok
  end
  defp maybe_apply_hotspot_output(_), do: :ok

  defp maybe_apply_nama_config(%{"nama" => %{"profile" => profile}}) when not is_nil(profile) do
    BackendServer.change_profile(profile)
    :ok
  end
  defp maybe_apply_nama_config(_), do: :ok

  defp maybe_apply_ntp_config(%{"ntp" => ntp}) when not is_nil(ntp) do
    BackendServer.save_ntp(ntp)
    :ok
  end
  defp maybe_apply_ntp_config(_), do: :ok

  defp is_valid_ip?(ip) when is_binary(ip) do
    Regex.match?(~r/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/, ip)
  end
  defp is_valid_ip?(_), do: false

  defp is_valid_nameservers?(servers) when is_binary(servers) do
    servers
    |> String.split(",")
    |> Enum.all?(&is_valid_ip?/1)
  end
  defp is_valid_nameservers?(_), do: false

  # Helper functions
  defp send_json(conn, status_code, json) when is_binary(json) do
    conn
    |> put_resp_content_type("application/json")
    |> merge_resp_headers(@cors_headers)
    |> send_resp(status_code, json)
  end

  defp send_json(conn, status_code, data) when is_map(data) do
    send_json(conn, status_code, Jason.encode!(data))
  end

  defp enhance_access_points(access_points) do
    access_points
    |> VintageNetWiFi.summarize_access_points()
    |> Enum.map(fn ap ->
      ap
      |> Map.from_struct()
      |> Map.put(:scan_time, DateTime.utc_now() |> DateTime.to_iso8601())
      |> Map.put(:security_details, extract_security_details(ap.flags))
      |> Map.put(:signal_quality, calculate_signal_quality(ap.signal_percent))
    end)
  end

  defp extract_security_details(flags) do
    %{
      is_secure: Enum.any?(flags, &(&1 in [:wpa2, :wpa])),
      authentication_types: Enum.filter(flags, &(&1 in [:psk, :eap])),
      encryption_types: Enum.filter(flags, &(&1 in [:ccmp, :tkip]))
    }
  end

  defp calculate_signal_quality(signal_percent) when is_integer(signal_percent) do
    cond do
      signal_percent >= 80 -> "excellent"
      signal_percent >= 60 -> "good"
      signal_percent >= 40 -> "fair"
      signal_percent >= 20 -> "poor"
      true -> "very_poor"
    end
  end

  defp send_error_response(conn, error) do
    {status, response} = error_details(error)
    send_json(conn, status, response)
  end

  defp error_details({:error, :password_required}) do
    {400, %{
      error: "validation_error",
      code: "PASSWORD_REQUIRED",
      message: "A password is required for this network",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :invalid_ip}) do
    {400, %{
      error: "validation_error",
      code: "INVALID_IP",
      message: "Invalid IP address format",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :invalid_nameservers}) do
    {400, %{
      error: "validation_error",
      code: "INVALID_NAMESERVERS",
      message: "Invalid nameserver format",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :invalid_apn}) do
    {400, %{
      error: "validation_error",
      code: "INVALID_APN",
      message: "Invalid APN format",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :missing_state}) do
    {400, %{
      error: "validation_error",
      code: "MISSING_STATE",
      message: "desired_state is required",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :invalid_state}) do
    {400, %{
      error: "validation_error",
      code: "INVALID_STATE",
      message: "desired_state must be either 'locked' or 'unlocked'",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :invalid_config, errors}) do
    {400, %{
      error: "validation_error",
      code: "INVALID_CONFIG",
      message: "Configuration validation failed",
      errors: errors,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  defp error_details({:error, :missing_config}) do
    {400, %{
      error: "validation_error",
      code: "MISSING_CONFIG",
      message: "Configuration is required",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }}
  end

  # Add more error_details clauses as needed

  defp get_body(%Conn{body_params: %{"_json" => body}}), do: body
  defp get_body(%Conn{body_params: body}), do: body

  # Add OPTIONS handler for CORS preflight requests
  options _ do
    conn
    |> merge_resp_headers(@cors_headers)
    |> send_resp(204, "")
  end

  defp assign_network_priorities(networks) do
    # Sort networks by existing priority if present, or assign by order
    networks_with_explicit_priority =
      networks
      |> Enum.with_index(1)  # Start from 1
      |> Enum.map(fn {network, index} ->
        priority = case network["priority"] do
          p when is_integer(p) and p > 0 -> p
          p when is_binary(p) ->
            case Integer.parse(p) do
              {parsed_p, ""} when parsed_p > 0 -> parsed_p
              _ -> index  # Use index if priority is invalid
            end
          _ -> index  # Use index if no priority specified
        end
        Map.put(network, "priority", priority)
      end)

    # Sort by priority to ensure correct order
    Enum.sort_by(networks_with_explicit_priority, & &1["priority"])
  end

end
