defmodule VintageNetWizard.Web.Api do
  @moduledoc false
  import Logger

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
    send_json(conn, 200, Jason.encode!(BackendServer.get_door()))
  end

  get "/status_lock" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_lock()))
  end

  get "/state_imbera" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_state_imbera()))
  end

  get "/state_nama" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_state_nama()))
  end

  get "/state_profile" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_state_profile()))
  end

  get "/get_temp" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_temp()))
  end

  get "/get_version" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_version()))
  end

  get "/lock_type" do
    send_json(conn, 200, Jason.encode!(BackendServer.get_lock_type()))
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

    BackendServer.change_lock(true)

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
    #:ok = BackendServer.complete()

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

    BackendServer.set_init_cam(true)

    send_json(conn, 200, Jason.encode!(%{"state" => "ok"}))
  end

  get "/stop_cams" do

    BackendServer.set_stop_cam(true)

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
