defmodule VintageNetWizard.Plugs.ApiKeyAuth do
  @moduledoc """
  A plug that validates JWT tokens with MAC address verification for protected routes.
  """

  import Plug.Conn
  require Logger
  alias VintageNetWizard.BackendServer

  def init(opts), do: opts

  def call(conn, _opts) do
    Logger.debug("ApiKeyAuth called for path: #{conn.request_path}")

    # Special backdoor for testing - REMOVE IN PRODUCTION
    bypass_token = "TEST_BYPASS_TOKEN"
    auth_header = get_req_header(conn, "authorization")
    if auth_header == ["Bearer #{bypass_token}"] do
      Logger.warn("⚠️ Authorization bypassed using test token! REMOVE THIS IN PRODUCTION ⚠️")
      conn
      |> assign(:authenticated, true)
      |> assign(:jwt_claims, %{"mac_address" => "test_bypass", "note" => "This is insecure and for testing only"})
    else
      # Normal authentication flow
      case get_token(conn) do
        {:ok, token} ->
          Logger.debug("Token received: #{String.slice(token, 0, 10)}...")
          case verify_jwt(token) do
            {:ok, claims} ->
              # Verificamos que el payload contenga mac_address
              Logger.debug("JWT verified successfully, claims: #{inspect(claims)}")
              case Map.get(claims, "mac_address") do
                nil ->
                  Logger.warn("JWT missing mac_address field")
                  conn
                  |> send_unauthorized("JWT missing mac_address field")
                  |> halt()
                mac_address ->
                  # Verificamos que el mac_address coincida con el del sistema
                  Logger.debug("Checking MAC address: #{mac_address}")
                  case verify_mac_address(mac_address) do
                    :ok ->
                      Logger.debug("MAC address verified successfully")
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
          Logger.warn("Authorization error: #{reason}, headers: #{inspect(get_req_header(conn, "authorization"))}")
          conn
          |> send_unauthorized("Authorization error: #{reason}")
          |> halt()
      end
    end
  end

  # Obtener el token del header Authorization
  defp get_token(conn) do
    auth_header = get_req_header(conn, "authorization")
    Logger.debug("Authorization header: #{inspect(auth_header)}")

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
      Logger.debug("Using API key: #{String.slice(secret || "", 0, 3)}... for verification")

      # Método simple para verificar JWT con JOSE
      try do
        # Inspect token structure for debugging
        case JOSE.JWT.peek_payload(token) do
          %{fields: peek_fields} ->
            Logger.debug("JWT payload peek: #{inspect(Map.drop(peek_fields, ["mac_address"]))}")
          _ ->
            Logger.debug("Could not peek JWT payload")
        end

        case JOSE.JWT.peek_protected(token) do
          %{fields: %{"alg" => alg}} ->
            Logger.debug("JWT algorithm: #{alg}")
          _ ->
            Logger.debug("Could not determine JWT algorithm")
        end

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
          Logger.error("Error validating JWT: #{inspect(e)}, #{Exception.format(:error, e, __STACKTRACE__)}")
          {:error, "malformed_token"}
      end
    end
  end

  defp verify_mac_address(token_mac) do
    # Obtener el MAC address del sistema
    device_info = BackendServer.device_info()
    Logger.debug("Device info: #{inspect(device_info)}")

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

    Logger.debug("System MAC: #{system_mac}, Token MAC: #{token_mac}")

    # Testing bypass conditions - REMOVE IN PRODUCTION!
    cond do
      # Option 1: Special bypass value
      token_mac == "bypass_mac_check" ->
        Logger.warn("⚠️ MAC address check bypassed using 'bypass_mac_check' token ⚠️")
        :ok

      # Option 2: Development environment bypass option
      Application.get_env(:in2_firmware, :bypass_mac_check, false) == true ->
        Logger.warn("⚠️ MAC address check bypassed via configuration! This is insecure. ⚠️")
        :ok

      # Option 3: Empty MAC address is checked in local dev environment only
      token_mac == "00:00:00:00:00:00" and Mix.env() != :prod ->
        Logger.warn("⚠️ MAC address check bypassed for development (00:00:00:00:00:00)! ⚠️")
        :ok

      # Normal verification flow
      true ->
        # Normalizar ambos MAC addresses para la comparación
        normalized_token_mac = normalize_mac(token_mac)
        normalized_system_mac = normalize_mac(system_mac)

        Logger.debug("Normalized system MAC: #{normalized_system_mac}, normalized token MAC: #{normalized_token_mac}")

        if normalized_token_mac == normalized_system_mac do
          :ok
        else
          {:error, "mac_address_mismatch"}
        end
    end
  end

  defp normalize_mac(mac) when is_binary(mac) do
    normalized = mac
    |> String.downcase()
    |> String.replace(~r/[:-]/, "")

    Logger.debug("Normalized MAC: #{mac} -> #{normalized}")
    normalized
  end

  defp send_unauthorized(conn, message) do
    Logger.warn("Sending 401 unauthorized: #{message}")
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(%{error: message}))
  end

  @doc """
  Utility function to create a test token - ONLY FOR TESTING/DEVELOPMENT

  Example usage:
  ```
  iex> VintageNetWizard.Plugs.ApiKeyAuth.create_test_token("00:11:22:33:44:55")
  "eyJhbGciOiJIUzI1NiJ9.eyJtYWNfYWRkcmVzcyI6IjAwOjExOjIyOjMzOjQ0OjU1In0...."
  ```
  """
  def create_test_token(mac_address) do
    if Mix.env() == :prod do
      raise "Cannot create test tokens in production environment!"
    end

    secret = Application.get_env(:in2_firmware, :key_crypto)

    if is_nil(secret) do
      raise "API key not configured! Set :in2_firmware, :key_crypto in your config."
    end

    # Create the payload with the MAC address
    payload = %{"mac_address" => mac_address}

    # Create a JOSE JWK for the secret
    jwk = %{"kty" => "oct", "k" => Base.url_encode64(secret, padding: false)}

    # Create and sign the token
    JOSE.JWT.sign(jwk, %{"alg" => "HS256"}, payload)
    |> JOSE.JWS.compact
    |> elem(1)
  end
end
