defmodule VintageNetWizard.Plugs.ApiKeyAuth do
  @moduledoc """
  A plug that validates JWT tokens with MAC address verification for protected routes.
  """

  import Plug.Conn
  require Logger
  alias VintageNetWizard.BackendServer

  def init(opts), do: opts

  def call(conn, _opts) do
    # Normal authentication flow
    case get_token(conn) do
      {:ok, token} ->
        case verify_jwt(token) do
          {:ok, claims} ->
            # Verificamos que el payload contenga mac_address
            case Map.get(claims, "mac_address") do
              nil ->
                Logger.warn("JWT missing mac_address field")
                conn
                |> send_unauthorized("JWT missing mac_address field")
                |> halt()
              mac_address ->
                # Verificamos que el mac_address coincida con el del sistema
                case verify_mac_address(mac_address) do
                  :ok ->
                    conn
                    |> assign(:authenticated, true)
                    |> assign(:jwt_claims, claims)
                  {:error, reason} ->
                    Logger.warn("MAC address verification failed: #{reason}")
                    conn
                    |> send_unauthorized("MAC address error: #{reason}")
                    |> halt()
                end
            end
          {:error, reason} ->
            Logger.warn("JWT verification failed: #{reason}")
            conn
            |> send_unauthorized("JWT verification failed: #{reason}")
            |> halt()
        end
      {:error, reason} ->
        Logger.warn("Authorization error: #{reason}")
        conn
        |> send_unauthorized("Authorization error: #{reason}")
        |> halt()
    end
  end

  # Obtener el token del header Authorization
  defp get_token(conn) do
    auth_header = get_req_header(conn, "authorization")

    case auth_header do
      # Caso 1: "Bearer " + token (formato estándar)
      ["Bearer " <> token] when is_binary(token) and byte_size(token) > 0 ->
        {:ok, String.trim(token)}

      # Caso 2: Intenta extraer el token si comienza con "Bearer"
      [header] when is_binary(header) ->
        header = String.trim(header)
        if String.starts_with?(header, "Bearer") do
          [_, token] = String.split(header, "Bearer", parts: 2)
          {:ok, String.trim(token)}
        else
          # Si no hay "Bearer", intentamos usar el header completo como token
          {:ok, header}
        end

      # Caso 3: Header de autorización vacío o ausente
      [] ->
        {:error, "authorization_header_missing"}

      # Caso 4: Cualquier otro formato no reconocido
      _ ->
        {:error, "invalid_authorization_format"}
    end
  end

  defp verify_jwt(token) do
    # Obtenemos la clave de crypto de in2_firmware
    secret = Application.get_env(:in2_firmware, :key_crypto)

    # Check if secret is nil and handle it properly
    if is_nil(secret) do
      Logger.error("API key is not configured! Please set :in2_firmware, :key_crypto in your config.")
      {:error, "api_key_not_configured"}
    else
      # Método simple para verificar JWT con JOSE
      try do
        # Use a simpler approach for JOSE verification
        jwk = %{"kty" => "oct", "k" => Base.url_encode64(secret, padding: false)}

        # Parse the JWT - accept both HS256 and HS512 for flexibility
        case JOSE.JWT.verify_strict(jwk, ["HS256", "HS512"], token) do
          {true, %{fields: claims}, _} ->
            # Verificar la caducidad si existe
            current_time = :os.system_time(:seconds)
            if Map.has_key?(claims, "exp") and claims["exp"] < current_time do
              Logger.warn("Token expired, exp: #{claims["exp"]}, current: #{current_time}")
              {:error, "token_expired"}
            else
              {:ok, claims}
            end
          {false, _, _} ->
            Logger.warn("Invalid JWT signature")
            {:error, "invalid_signature"}
          {:error, reason} ->
            Logger.warn("Error during JWT verification: #{inspect(reason)}")
            {:error, "verification_error"}
        end
      rescue
        e ->
          Logger.error("Error validating JWT: #{inspect(e)}")
          {:error, "malformed_token"}
      end
    end
  end

  defp verify_mac_address(token_mac) do
    # Obtener el MAC address del sistema
    device_info = BackendServer.device_info()

    system_mac = case Enum.find(device_info, fn {label, _} -> label == "WiFi Address" end) do
      {_, mac} when is_binary(mac) and mac != "" ->
        mac
      _ ->
        # Fallback to other methods of getting MAC address
        Logger.warn("WiFi Address not found in device_info, trying alternative methods")
        case System.cmd("ifconfig", ["en0"], stderr_to_stdout: true) do
          {output, 0} ->
            case Regex.run(~r/ether\s+([0-9a-fA-F:]+)/, output) do
              [_, mac] -> mac
              _ -> "00:00:00:00:00:00" # Fallback value
            end
          _ ->
            Logger.error("Could not determine MAC address")
            "00:00:00:00:00:00" # Fallback value
        end
    end

    # Normal verification flow
    # Normalizar ambos MAC addresses para la comparación
    normalized_token_mac = normalize_mac(token_mac)
    normalized_system_mac = normalize_mac(system_mac)

    if normalized_token_mac == normalized_system_mac do
      :ok
    else
      {:error, "mac_address_mismatch"}
    end
  end

  defp normalize_mac(mac) when is_binary(mac) do
    mac
    |> String.downcase()
    |> String.replace(~r/[:-]/, "")
  end

  defp send_unauthorized(conn, message) do
    Logger.warn("Sending 401 unauthorized: #{message}")
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: message}))
  end
end
