defmodule VintageNetWizard.Web.ApiV1 do
  @moduledoc false
  require Logger

  use Plug.Router

  alias Plug.Conn
  alias VintageNetWizard.BackendServer
  alias VintageNetWizard.Web.Endpoint
  alias VintageNetWizard.WiFiConfiguration
  alias In2Firmware.Services.Operations
  alias In2Firmware.Services.Lock

  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:match)
  plug(:dispatch)

  get "/door" do

    door_status = BackendServer.get_door()

    response = %{
      status: door_status["door"],
      lastChanged: door_status["timestamp"]
    }

    send_json(conn, 200, Jason.encode!(response))
  end

  get "/status_lock" do

    lock_status = BackendServer.get_lock()

    response = %{
      status: lock_status.lock || "locked",
      isWorking: lock_status.working
    }

    send_json(conn, 200, Jason.encode!(response))
  end

  get "/get_ntp_apn" do
    config = BackendServer.get_board_config()

    send_json(conn, 200, Jason.encode!(config))
  end

  get "/get_imbera_all" do
    config = BackendServer.get_board_config()

    send_json(conn, 200, Jason.encode!(config))
  end

  get "/lock_type" do

    lock_type = BackendServer.get_lock_type()

    response = %{
      type: lock_type["lock_type"] || "retrofit"
    }

    send_json(conn, 200, Jason.encode!(response))
  end

  get "/configuration/status" do
    with status <- BackendServer.configuration_status(),
         {:ok, json_status} <- Jason.encode(status) do
      send_json(conn, 200, json_status)
    end
  end

  get "/access_points" do
    {:ok, access_points} =
      BackendServer.access_points()
      |> to_json()

    send_json(conn, 200, access_points)
  end

  put "/lock" do

    BackendServer.change_lock(false)

    send_json(conn, 204, "")
  end

  put "/clear" do

    #Lock.open_lock("operator")
    Operations.init_trx_op()

    send_json(conn, 204, "")
  end

  put "/nama_change" do
    result = conn
    |> get_body()
    |> Map.get("value", false)

    Logger.info("Nama change #{inspect(result)}")
    Lock.activate_nama(result)

    send_json(conn, 204, "")
  end

  put "/ssids" do
    conn
    |> get_body()
    |> BackendServer.set_priority_order()

    send_json(conn, 204, "")
  end

  get "/complete" do
    :ok = BackendServer.complete()

    _ =
      Task.Supervisor.start_child(VintageNetWizard.TaskSupervisor, fn ->
        # We don't want to stop the server before we
        # send the response back.
        :timer.sleep(3000)
        #Endpoint.stop_server(:shutdown)
      end)

    send_json(conn, 202, "")
  end

  get "/configurations" do
    {:ok, json} =
      BackendServer.configurations()
      |> Jason.encode()

    send_json(conn, 200, json)
  end

  get "/init_cams" do

    BackendServer.init_cameras()

    send_json(conn, 200, Jason.encode!(%{"state" => "ok"}))
  end

  get "/stop_cams" do

    #BackendServer.stop_cameras()

    send_json(conn, 200, Jason.encode!(%{"state" => "ok"}))
  end

  post "/cam" do

    result = conn
    |> get_body()

    case File.read("/root/cam#{result["cam_index"]}/frame#{result["format_index"]}.jpg") do
      {:ok, binary} -> send_imagen(conn, 200, binary)
      {:error, _posix} -> send_json(conn, 204, "")
    end

  end


  post "/apply" do
    case BackendServer.apply() do
      :ok ->
        send_json(conn, 202, "")

      {:error, :no_configurations} ->
        json =
          %{
            error: "no_configurations",
            message: "Please provide configurations to apply."
          }
          |> Jason.encode!()

        send_json(conn, 404, json)
    end
  end

  put "/:ssid/configuration" do
    with {:ok, cfg} <- configuration_from_params(conn, ssid),
         :ok <- BackendServer.save(cfg) do
      send_json(conn, 204, "")
    else
      error ->
        send_json(conn, 400, make_error_message(error))
    end
  end

  delete "/:ssid/configuration" do
    :ok = BackendServer.delete_configuration(ssid)

    send_json(conn, 200, "")
  end

  defp send_json(conn, status_code, json) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status_code, json)
  end

  defp get_body(%Conn{body_params: %{"_json" => body}}) do
    body
  end

  defp get_body(%Conn{body_params: body}), do: body

  defp to_json(access_points) do
    access_points
    |> VintageNetWiFi.summarize_access_points()
    |> Enum.map(&Map.from_struct/1)
    |> Jason.encode()
  end

  defp configuration_from_params(conn, ssid) do
    conn
    |> get_body()
    |> Map.put("ssid", ssid)
    |> WiFiConfiguration.json_to_network_config()
  end

  defp make_error_message({:error, :password_required}) do
    Jason.encode!(%{
      error: "password_required",
      message: "A password is required."
    })
  end

  defp make_error_message({:error, :password_too_short}) do
    Jason.encode!(%{
      error: "password_too_short",
      message: "The minimum length for a password is 8."
    })
  end

  defp make_error_message({:error, :password_too_long}) do
    Jason.encode!(%{
      error: "password_too_long",
      message: "The maximum length for a password is 63."
    })
  end

  defp make_error_message({:error, :invalid_characters}) do
    Jason.encode!(%{
      error: "invalid_characters",
      message: "The password provided has invalid characters."
    })
  end

  defp make_error_message({:error, :user_required}) do
    Jason.encode!(%{
      error: "user_required",
      message: "A user is required."
    })
  end

  defp send_imagen(conn, status_code, binary) do
    conn
    |> put_resp_content_type("image/jpeg")
    |> send_resp(status_code, binary)
  end

end
