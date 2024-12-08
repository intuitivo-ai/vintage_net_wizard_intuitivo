defmodule VintageNetWizard.Web.ApiV2 do
  @moduledoc """
  V2 API endpoints for VintageNetWizard

  This module provides enhanced API endpoints with richer metadata and consistent response formats.
  All responses include timestamps and detailed status information.
  """

  use Plug.Router

  alias Plug.Conn
  alias VintageNetWizard.BackendServer
  alias VintageNetWizard.WiFiConfiguration

  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:match)
  plug(:dispatch)

  @doc """
  Health check endpoint to verify API availability.

  Returns:
      {
        "status": "ok",
        "version": "2.0.0",
        "mac_address": "00:11:22:33:44:55",  # MAC address of the WiFi interface
        "firmware_version": "1.2.3",          # Current firmware version
        "timestamp": "2024-03-20T15:30:00Z"
      }
  """
  get "/health" do
    device_info = BackendServer.device_info()

    # Extract values from the device_info list
    mac_address = device_info
                 |> Enum.find(fn {label, _} -> label == "WiFi Address" end)
                 |> elem(1)

    firmware_version = device_info
                      |> Enum.find(fn {label, _} -> label == "Firmware version" end)
                      |> elem(1)

    send_json(conn, 200, %{
      status: "ok",
      version: "2.0.0",
      mac_address: mac_address,
      firmware_version: firmware_version,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  @doc """
  Scan for available WiFi networks.

  Returns:
      {
        "networks": [
          {
            "ssid": "NetworkName",
            "signal_percent": 75,
            "frequency": 2437,
            "band": "wifi_2_4_ghz",
            "channel": 6,
            "flags": ["wpa2", "psk", "ccmp", "ess"]
          }
        ]
      }
  """
  get "/networks/scan" do
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

  @doc """
  Get detailed configuration status.

  Returns:
      {
        "status": "good",
        "timestamp": "2024-03-20T15:30:00Z",
        "details": "Network configured and connected"
      }

  Status can be:
  - "good" - Network is configured and connected
  - "bad" - Network is configured but not connected
  - "not_configured" - No network configuration present
  """
  get "/configuration/status" do
    status = BackendServer.configuration_status()

    response = %{
      status: status,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      details: configuration_status_details(status)
    }

    send_json(conn, 200, Jason.encode!(response))
  end

  @doc """
  Get status of all connected cameras.

  Returns:
      {
        "cameras": [
          {
            "id": "cam1",
            "name": "Front Camera",
            "status": "online",
            "streamUrl": "rtsp://device-ip:8554/cam1"
          }
        ]
      }

  Status values:
  - "online" - Camera is connected and streaming
  - "offline" - Camera is disconnected or not responding
  """
  get "/cameras" do
    device_ip = VintageNet.get(["interface", "wlan0", "addresses"])
                |> List.first()
                |> Map.get(:address, "localhost")

    cameras = BackendServer.get_cameras(device_ip)  # Using existing function
    send_json(conn, 200, %{cameras: cameras})
  end

  @doc """
  Initialize cameras.

  Response:
      {
        "status": "success",
        "message": "Cameras initialized successfully",
        "timestamp": "2024-03-20T15:30:00Z"
      }
  """
  post "/cameras/initialize" do
    BackendServer.init_cameras()  # Using existing function

    response = %{
      status: "success",
      message: "Cameras initialized successfully",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    send_json(conn, 200, response)
  end

  @doc """
  Get door sensor status.

  Returns:
      {
        "status": "open" | "closed",
        "lastChanged": "2024-03-20T15:30:00Z"
      }

  Status values:
  - "open" - Door is currently open
  - "closed" - Door is currently closed
  """
  get "/door" do
    door_status = BackendServer.get_door()

    response = %{
      status: if(door_status.door, do: "open", else: "closed"),
      lastChanged: door_status.timestamp || DateTime.utc_now() |> DateTime.to_iso8601()
    }

    send_json(conn, 200, response)
  end

  @doc """
  Get lock status and details.

  Returns:
      {
        "status": "locked" | "unlocked",
        "lastChanged": "2024-03-20T15:30:00Z",
        "type": "retrofit" | "imbera" | "southco",
        "isWorking": true
      }

  Status values:
  - "locked" - Lock is engaged
  - "unlocked" - Lock is disengaged

  Type values:
  - "retrofit" - Retrofit lock mechanism
  - "imbera" - Imbera native lock
  - "southco" - Southco electronic lock
  """
  get "/lock" do
    lock_status = BackendServer.get_lock()
    lock_type = BackendServer.get_lock_type()

    response = %{
      status: if(lock_status.lock, do: "locked", else: "unlocked"),
      lastChanged: lock_status.timestamp,
      type: lock_type.lock_type_select,
      isWorking: lock_status.working
    }

    send_json(conn, 200, response)
  end

  @doc """
  Control lock state.

  Request body:
      {
        "desired_state": "locked" | "unlocked"
      }

  Success response:
      {
        "status": "success",
        "message": "Lock state changed successfully",
        "current_state": "locked" | "unlocked",
        "timestamp": "2024-03-20T15:30:00Z"
      }

  Error response (400):
      {
        "error": "validation_error",
        "code": "INVALID_STATE",
        "message": "desired_state must be either 'locked' or 'unlocked'",
        "timestamp": "2024-03-20T15:30:00Z"
      }
  """
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

  @doc """
  Update lock type configuration.

  Request body:
      {
        "lockType": "retrofit" | "imbera" | "southco"
      }

  Success response:
      {
        "status": "success",
        "message": "Lock type updated successfully",
        "current_type": "retrofit" | "imbera" | "southco",
        "timestamp": "2024-03-20T15:30:00Z"
      }

  Error response (400):
      {
        "error": "validation_error",
        "code": "INVALID_LOCK_TYPE",
        "message": "lockType must be one of: retrofit, imbera, southco",
        "timestamp": "2024-03-20T15:30:00Z"
      }
  """
  put "/lock-type" do
    valid_types = ["retrofit", "imbera", "southco"]

    case get_body(conn) do
      %{"lockType" => lock_type} when lock_type in valid_types ->
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

  @doc """
  Get complete board configuration including lock, network, and system settings.

  Returns:
      {
        "lockType": "retrofit" | "imbera" | "southco",
        "wifi": {
          "networks": [
            {
              "ssid": "string",
              "password": "string"
            }
          ],
          "primary_network": "string",
          "method": "dhcp" | "static",
          "static_config": {
            "address": "string",
            "netmask": "string",
            "gateway": "string",
            "name_servers": "string"
          }
        },
        "mobileNetwork": {
          "apn": "string"
        },
        "hotspotOutput": "wifi" | "ethernet",
        "nama": {
          "enabled": boolean,
          "profile": "string"
        },
        "ntp": "string"
      }
  """
  get "/config" do
    config = BackendServer.get_board_config()  # Using existing function
    send_json(conn, 200, config)
  end

  @doc """
  Update board configuration.

  Request body:
      {
        "lockType": "retrofit" | "imbera" | "southco",
        "wifi": {
          "networks": [
            {
              "ssid": "string",
              "password": "string"
            }
          ],
          "primary_network": "string",
          "method": "dhcp" | "static",
          "static_config": {
            "address": "string",
            "netmask": "string",
            "gateway": "string",
            "name_servers": "string"
          }
        },
        "mobileNetwork": {
          "apn": "string"
        },
        "hotspotOutput": "wifi" | "ethernet",
        "nama": {
          "enabled": boolean,
          "profile": "string"
        },
        "ntp": "string"
      }

  Success response:
      {
        "status": "success",
        "message": "Configuration updated successfully",
        "timestamp": "2024-03-20T15:30:00Z"
      }

  Error response (400):
      {
        "error": "validation_error",
        "code": "INVALID_CONFIG",
        "message": "Invalid configuration provided",
        "details": ["specific error details"],
        "timestamp": "2024-03-20T15:30:00Z"
      }
  """
  put "/config" do
    case get_body(conn) do
      %{} = config ->
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

  defp validate_lock_type(%{lockType: type}) when type in ["retrofit", "imbera", "southco"], do: {:ok, type}
  defp validate_lock_type(%{lockType: _}), do: {:error, "Invalid lock type"}
  defp validate_lock_type(_), do: {:ok, nil}  # Optional field

  defp validate_wifi_config(%{wifi: %{method: method} = wifi}) when method in ["dhcp", "static"] do
    case method do
      "static" -> validate_static_config(wifi)
      "dhcp" -> {:ok, wifi}
    end
  end
  defp validate_wifi_config(%{wifi: _}), do: {:error, "Invalid WiFi configuration"}
  defp validate_wifi_config(_), do: {:ok, nil}  # Optional field

  defp validate_static_config(%{static_config: config}) do
    with true <- is_valid_ip?(config.address),
         true <- is_valid_ip?(config.netmask),
         true <- is_valid_ip?(config.gateway),
         true <- is_valid_nameservers?(config.name_servers) do
      {:ok, config}
    else
      false -> {:error, "Invalid static IP configuration"}
    end
  end

  defp validate_mobile_network(%{mobileNetwork: %{apn: apn}}) when is_binary(apn), do: {:ok, apn}
  defp validate_mobile_network(%{mobileNetwork: _}), do: {:error, "Invalid mobile network configuration"}
  defp validate_mobile_network(_), do: {:ok, nil}  # Optional field

  defp validate_hotspot_output(%{hotspotOutput: output}) when output in ["wifi", "ethernet"], do: {:ok, output}
  defp validate_hotspot_output(%{hotspotOutput: _}), do: {:error, "Invalid hotspot output"}
  defp validate_hotspot_output(_), do: {:ok, nil}  # Optional field

  defp validate_nama_config(%{nama: %{enabled: enabled, profile: profile}})
       when is_boolean(enabled) and is_binary(profile), do: {:ok, {enabled, profile}}
  defp validate_nama_config(%{nama: _}), do: {:error, "Invalid NAMA configuration"}
  defp validate_nama_config(_), do: {:ok, nil}  # Optional field

  defp validate_ntp_config(%{ntp: ntp}) when is_binary(ntp), do: {:ok, ntp}
  defp validate_ntp_config(%{ntp: _}), do: {:error, "Invalid NTP configuration"}
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

  defp maybe_apply_lock_type(%{lockType: type}) when not is_nil(type) do
    BackendServer.save_lock(type)
    :ok
  end
  defp maybe_apply_lock_type(_), do: :ok

  defp maybe_apply_wifi_config(%{wifi: wifi}) when not is_nil(wifi) do
    # Apply network method and configurations
    case wifi.method do
      "static" ->
        BackendServer.save_method(%{
          method: :static,
          address: wifi.static_config.address,
          netmask: wifi.static_config.netmask,
          gateway: wifi.static_config.gateway,
          name_servers: String.split(wifi.static_config.name_servers, ",")
        })
      "dhcp" ->
        BackendServer.save_method(%{method: :dhcp})
    end

    # Apply WiFi networks if provided
    if wifi.networks do
      Enum.each(wifi.networks, fn network ->
        BackendServer.save(%{
          ssid: network.ssid,
          psk: network.password,
          key_mgmt: if(network.password == "", do: :none, else: :wpa_psk)
        })
      end)
    end

    :ok
  end
  defp maybe_apply_wifi_config(_), do: :ok

  defp maybe_apply_mobile_network(%{mobileNetwork: %{apn: apn}}) when not is_nil(apn) do
    BackendServer.save_apn(apn)
    :ok
  end
  defp maybe_apply_mobile_network(_), do: :ok

  defp maybe_apply_hotspot_output(%{hotspotOutput: output}) when not is_nil(output) do
    BackendServer.save_internet(output)
    :ok
  end
  defp maybe_apply_hotspot_output(_), do: :ok

  defp maybe_apply_nama_config(%{nama: %{enabled: enabled}}) when not is_nil(enabled) do
    # Assuming there's a function to enable/disable NAMA
    # BackendServer.set_nama_enabled(enabled)
    :ok
  end
  defp maybe_apply_nama_config(_), do: :ok

  defp maybe_apply_ntp_config(%{ntp: ntp}) when not is_nil(ntp) do
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
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status_code, json)
  end

  defp send_json(conn, status_code, data) when is_map(data) do
    send_json(conn, status_code, Jason.encode!(data))
  end

  @doc """
  Enhances access point information with additional metadata.

  Adds:
  - scan_time: ISO8601 timestamp of when the scan occurred
  - security_details: Detailed security information
  - signal_quality: Human-readable signal strength
  """
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

  @doc """
  Extracts detailed security information from access point flags.

  Returns a map containing:
  - is_secure: Boolean indicating encryption presence
  - authentication_types: List of auth methods
  - encryption_types: List of encryption protocols
  """
  defp extract_security_details(flags) do
    %{
      is_secure: Enum.any?(flags, &(&1 in [:wpa2, :wpa])),
      authentication_types: Enum.filter(flags, &(&1 in [:psk, :eap])),
      encryption_types: Enum.filter(flags, &(&1 in [:ccmp, :tkip]))
    }
  end

  @doc """
  Converts signal percentage to human-readable quality level.

  Ranges:
  - 80-100%: "excellent"
  - 60-79%: "good"
  - 40-59%: "fair"
  - 20-39%: "poor"
  - 0-19%: "very_poor"
  """
  defp calculate_signal_quality(signal_percent) when is_integer(signal_percent) do
    cond do
      signal_percent >= 80 -> "excellent"
      signal_percent >= 60 -> "good"
      signal_percent >= 40 -> "fair"
      signal_percent >= 20 -> "poor"
      true -> "very_poor"
    end
  end

  defp configuration_status_details(:not_configured), do: "No network configuration present"
  defp configuration_status_details(:good), do: "Network configured and connected"
  defp configuration_status_details(:bad), do: "Network configuration present but not connected"

  defp send_error_response(conn, error) do
    {status, response} = error_details(error)
    send_json(conn, status, response)
  end

  @doc """
  Maps error types to appropriate HTTP responses.

  Each error response includes:
  - error: Error category
  - code: Specific error code
  - message: Human-readable error description
  - timestamp: When the error occurred
  """
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

  # Add more error_details clauses as needed

  defp get_body(%Conn{body_params: %{"_json" => body}}), do: body
  defp get_body(%Conn{body_params: body}), do: body

  defp put_resp_header(conn, key, value) do
    Plug.Conn.put_resp_header(conn, key, value)
  end
end
