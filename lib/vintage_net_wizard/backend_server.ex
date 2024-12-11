defmodule VintageNetWizard.BackendServer do
  @moduledoc """
  Server for managing a VintageNet.Backend implementation
  """
  use GenServer
  require Logger

  alias VintageNetWiFi.AccessPoint
  alias VintageNetWizard.{APMode, Backend}

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
      subscriber: pid() | nil,
      backend: module() | nil,
      backend_state: term() | nil,
      configurations: map(),
      device_info: list(),
      ap_ifname: String.t() | nil,
      ifname: String.t() | nil,
      internet_select: String.t() | nil,
      state_nama: %{enabled: boolean()},
      state_profile: %{profile: integer()},
      state_temperature: %{temperature: String.t()},
      state_version: %{version: String.t()},
      state_comm: boolean(),
      init_cam: boolean(),
      door: %{door: boolean(), timestamp: String.t()},
      lock: %{lock: boolean(), working: boolean(), timestamp: String.t()},
      lock_type: %{lock_type: String.t()},
      apn: String.t(),
      ntp: String.t()
    }

    defstruct subscriber: nil,
              backend: nil,
              backend_state: nil,
              configurations: %{},
              device_info: [],
              ap_ifname: nil,
              ifname: nil,
              internet_select: "disabled",
              state_nama: %{enabled: false},
              state_profile: %{profile: 1},
              state_temperature: %{temperature: "unknown"},
              state_version: %{version: ""},
              state_comm: true,
              init_cam: false,
              door: %{door: false, timestamp: DateTime.utc_now() |> DateTime.to_iso8601()},
              lock: %{lock: false, working: true, timestamp: DateTime.utc_now() |> DateTime.to_iso8601()},
              lock_type: %{lock_type: "retrofit"},
              apn: "",
              ntp: ""
  end

  @spec child_spec(any(), any(), keyword()) :: map()
  def child_spec(backend, ifname, opts \\ []) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [backend, ifname, opts]},
      restart: :transient
    }
  end

  @spec start_link(backend :: module(), VintageNet.ifname(), [Backend.opt()]) ::
          GenServer.on_start()
  def start_link(backend, ifname, opts \\ []) do
    GenServer.start_link(__MODULE__, [backend, ifname, opts], name: __MODULE__)
  end

  @doc """
  Subscribe to messages from the backend
  """
  @spec subscribe() :: :ok
  def subscribe() do
    GenServer.cast(__MODULE__, {:subscribe, self()})
  end

  @spec start_cams_ap(any()) :: :ok
  def start_cams_ap(value) do
    GenServer.cast(__MODULE__, {:start_cams_ap, value})
  end
  @doc """
  Return information about the device for the web page's footer
  """
  @spec device_info() :: [{String.t(), String.t()}]
  def device_info() do
    GenServer.call(__MODULE__, :device_info)
  end

  @doc """
  Delete the configuration by `ssid`
  """
  @spec delete_configuration(String.t()) :: :ok
  def delete_configuration(ssid) do
    GenServer.call(__MODULE__, {:delete_configuration, ssid})
  end

  @doc """
  List out access points
  """
  @spec access_points() :: [AccessPoint.t()]
  def access_points() do
    GenServer.call(__MODULE__, :access_points)
  end

  @doc """
  Pass list of SSIDs (`priority_order`), sort the configurations
  to match that order.
  """
  @spec set_priority_order([String.t()]) :: :ok
  def set_priority_order(priority_order) do
    GenServer.call(__MODULE__, {:set_priority_order, priority_order})
  end

  @doc """
  Get the current state of the WiFi configuration
  """
  @spec configuration_state() :: map()
  def configuration_state() do
    GenServer.call(__MODULE__, :configuration_state)
  end

  @doc """
  Start scanning for WiFi access points
  """
  @spec start_scan() :: :ok
  def start_scan() do
    GenServer.call(__MODULE__, :start_scan)
  end

  @doc """
  Stop scanning for WiFi access points
  """
  @spec stop_scan() :: :ok
  def stop_scan() do
    GenServer.call(__MODULE__, :stop_scan)
  end

  @doc """
  Save a network configuration to the backend.
  The network configuration is a map that can be included in the `:network`
  field of a `VintageNetWiFi` configuration.
  """
  @spec save(map()) :: :ok | {:error, any()}
  def save(config) do
    GenServer.call(__MODULE__, {:save, config})
  end

  @doc """
  Get complete board configuration
  """
  @spec get_board_config() :: map()
  def get_board_config() do
    GenServer.call(__MODULE__, :get_board_config)
  end

  def save_method(config) do
    GenServer.cast(__MODULE__, {:save_method, config})
  end

  def save_lock(lock) do
    GenServer.cast(__MODULE__, {:save_lock, lock})
  end

  def save_internet(save_internet) do
    GenServer.cast(__MODULE__, {:save_internet, save_internet})
  end

  def save_ntp(ntps) do
    GenServer.cast(__MODULE__, {:save_ntp, ntps})
  end

  def save_apn(apn) do
    GenServer.cast(__MODULE__, {:save_apn, apn})
  end

  def change_profile(profile) do
    GenServer.cast(__MODULE__, {:change_profile, profile})
  end

  @doc """
  Get a list of the current configurations
  """
  @spec configurations() :: [map()]
  def configurations() do
    GenServer.call(__MODULE__, :configurations)
  end

  @doc """
  Get the current configuration status
  """
  @spec configuration_status() :: :good | :bad | :not_configured
  def configuration_status() do
    GenServer.call(__MODULE__, :configuration_status)
  end

  @doc """
  Apply the configurations saved in the backend to
  the system.
  """
  @spec apply() :: :ok | {:error, :no_configurations}
  def apply() do
    GenServer.call(__MODULE__, :apply)
  end

  @doc """
  Reset the backend to an initial default state.
  """
  @spec reset() :: :ok
  def reset() do
    GenServer.call(__MODULE__, :reset)
  end

  @doc """
  """
  @spec complete() :: :ok
  def complete() do
    GenServer.call(__MODULE__, :complete)
  end

  def set_door(door) do
    GenServer.cast(__MODULE__, {:set_door, door})
  end

  def set_lock(lock) do
    GenServer.cast(__MODULE__, {:set_lock, lock})
  end

  def set_lock_type(lock_type) do
    GenServer.cast(__MODULE__, {:set_lock_type, lock_type})
  end

  def set_state_imbera(state_imbera) do
    GenServer.cast(__MODULE__, {:set_state_imbera, state_imbera})
  end

  def set_state_nama(state_nama) do
    GenServer.cast(__MODULE__, {:set_state_nama, state_nama})
  end

  def set_state_profile(state_profile) do
    GenServer.cast(__MODULE__, {:set_state_profile, state_profile})
  end

  def set_temp(temp) do
    GenServer.cast(__MODULE__, {:set_temp, temp})
  end

  def set_version(version) do
    GenServer.cast(__MODULE__, {:set_version, version})
  end

  def change_lock(value) do
    GenServer.cast(__MODULE__, {:change_lock, value})
  end

  def set_state_comm(value) do
    GenServer.cast(__MODULE__, {:set_state_comm, value})
  end

  def get_door() do
    GenServer.call(__MODULE__, :get_door)
  end

  def get_state_imbera() do
    GenServer.call(__MODULE__, :get_state_imbera)
  end

  def get_temp() do
    GenServer.call(__MODULE__, :get_temp)
  end

  def get_version() do
    GenServer.call(__MODULE__, :get_version)
  end

  def get_lock() do
    GenServer.call(__MODULE__, :get_lock)
  end

  def get_lock_type() do
    GenServer.call(__MODULE__, :get_lock_type)
  end

  def get_change_lock() do
    GenServer.call(__MODULE__, :get_change_lock)
  end

  def stop_cameras() do
    GenServer.cast(__MODULE__, :stop_cameras)
  end

   @doc """
  Initialize cameras
  """
  @spec init_cameras() :: :ok
  def init_cameras() do
    GenServer.cast(__MODULE__, :init_cameras)
  end

  @impl GenServer
  def init([backend, ifname, opts]) do
    device_info = Keyword.get(opts, :device_info, [])

    configurations =
      opts
      |> Keyword.get(:configurations, [])
      |> Enum.into(%{}, fn config -> {config.ssid, config} end)

    ap_ifname = Keyword.fetch!(opts, :ap_ifname)

    send(self(), :get_ntp)
    send(self(), :get_apn)
    send(self(), :get_internet_select)
    {:ok,
     %State{
       configurations: configurations,
       backend: backend,
       # Scanning is done by ifname
       backend_state: backend.init(ifname, ap_ifname),
       device_info: device_info,
       ifname: ifname,
       ap_ifname: ap_ifname
     }}
  end

  @impl GenServer
  def handle_call(:get_lock, _from, %State{state_comm: state_comm} = state) do

    Logger.info("get_lock from backend_server #{inspect(state.lock)} -> #{inspect(state_comm)}")

    lock = if state_comm do
      state.lock
    else
      # Cuando state_comm es false, actualizamos working a false manteniendo el resto igual
      %{state.lock | working: false}
    end

    {:reply, lock, state}
  end

  @impl GenServer
  def handle_call(
        :get_lock_type,
        _from,
          state
      ) do

    {:reply, state.lock_type, state}
  end

  @impl GenServer
  def handle_call(
        :get_change_lock,
        _from,
          state
      ) do

    {:reply, state.lock, state}
  end

  @impl GenServer
  def handle_call(
        :get_door,
        _from,
          state
      ) do

    {:reply, state.door, state}
  end

  @impl GenServer
  def handle_call(
        :access_points,
        _from,
        %State{backend: backend, backend_state: backend_state} = state
      ) do
    access_points = backend.access_points(backend_state)
    {:reply, access_points, state}
  end

  def handle_call(
        :start_scan,
        _from,
        %State{backend: backend, backend_state: backend_state} = state
      ) do

    new_backend_state = backend.start_scan(backend_state)

    {:reply, :ok, %{state | backend_state: new_backend_state}}
  end


  def handle_call(
        :stop_scan,
        _from,
        %State{backend: backend, backend_state: backend_state} = state
      ) do
    new_backend_state = backend.stop_scan(backend_state)

    {:reply, :ok, %{state | backend_state: new_backend_state}}
  end

  def handle_call(
        {:set_priority_order, priority_order},
        _from,
        %State{configurations: configurations} = state
      ) do
    indexed_priority_order = Enum.with_index(priority_order)

    new_configurations =
      Enum.map(configurations, fn {ssid, config} ->
        priority = get_priority_for_ssid(indexed_priority_order, ssid)

        {ssid, Map.put(config, :priority, priority)}
      end)
      |> Enum.into(%{})

    {:reply, :ok, %{state | configurations: new_configurations}}
  end

  def handle_call(
        :configuration_status,
        _from,
        %State{backend: backend, backend_state: backend_state} = state
      ) do
    status = backend.configuration_status(backend_state)
    {:reply, status, state}
  end

  def handle_call(
        {:save, config},
        _from,
        %{configurations: configs, backend: backend, backend_state: backend_state} = state
      ) do
    access_points = backend.access_points(backend_state)
    not_hidden? = Enum.any?(access_points, &(&1.ssid == config.ssid))
    # Scan if ssid is hidden
    full_config = if not_hidden?, do: config, else: Map.put(config, :scan_ssid, 1)

    {:reply, :ok, %{state | configurations: Map.put(configs, config.ssid, full_config)}}
  end

  def handle_call(
        :device_info,
        _from,
        state
      ) do
    {:reply, state.device_info, state}
  end

  def handle_call(:configurations, _from, %State{configurations: configs} = state) do
    cleaned_configs =
      configs
      |> build_config_list()
      |> Enum.map(&clean_config/1)

    {:reply, cleaned_configs, state}
  end

  def handle_call(
        :apply,
        _from,
        %State{configurations: wifi_configs} = state
      )
      when wifi_configs == %{} do
    {:reply, {:error, :no_configurations}, state}
  end

  def handle_call(
        :apply,
        _from,
        %State{
          backend: backend,
          configurations: wifi_configs,
          backend_state: backend_state,
          ifname: ifname
        } = state
      ) do
    old_connection = old_connection(ifname)

    case backend.apply(build_config_list(wifi_configs), backend_state) do
      {:ok, new_backend_state} ->
        updated_state = %{state | backend_state: new_backend_state}
        # If applying the new configuration does not change the connection,
        # send a message to that effect so the Wizard does not timeout
        # waiting for one from VintageNet
        maybe_send_connection_info(updated_state, old_connection)
        {:reply, :ok, updated_state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  def handle_call(:get_board_config, _from, %State{backend: backend, backend_state: backend_state} = state) do

    status = backend.configuration_status(backend_state)

    config = %{
      lockType: state.lock_type["lock_type"],
      wifi: %{
        networks: get_wifi_networks(state),
        method: get_network_method(),
        static_config: get_static_config()
      },
      mobileNetwork: %{
        apn: state.apn
      },
      hotspotOutput: state.internet_select || "disabled",
      nama: %{
        enabled: state.state_nama.enabled || false,
        profile: state.state_profile.profile,
        temperature: state.state_temperature.temperature || "unknown",
        version: state.state_version.version || ""
      },
      ntp: state.ntp,
      status_wifi: %{status: status, timestamp: DateTime.utc_now() |> DateTime.to_iso8601(), details: configuration_status_details(status)}
    }
    {:reply, config, state}
  end

  def handle_call(:reset, _from, %State{backend: backend, backend_state: backend_state} = state) do
    new_state = backend.reset(backend_state)
    {:reply, :ok, %{state | configurations: %{}, backend_state: new_state}}
  end

  def handle_call({:delete_configuration, ssid}, _from, %State{configurations: configs} = state) do
    {:reply, :ok, %{state | configurations: Map.delete(configs, ssid)}}
  end

  def handle_call(:configuration_state, _from, state) do
    {:reply, state, state}
  end

  def handle_call(
        :complete,
        _from,
        %State{backend_state: %{data: %{configuration_status: :good}}} = state
      ) do
    # As the configuration status is good, we are already completed setup and the configurations
    # have been blanked in `handle_info/3` - calling complete on the backend will disconnect us and
    # write over the saved configuration. Do nothing.
    :ok = deconfigure_ap_ifname(state)
    {:reply, :ok, state}
  end

  def handle_call(
        :complete,
        _from,
        %State{backend: backend, configurations: wifi_configs, backend_state: backend_state} =
          state
      ) do
    {:ok, new_backend_state} =
      backend.complete(build_config_list(wifi_configs), backend_state)

    :ok = deconfigure_ap_ifname(state)
    {:reply, :ok, %{state | backend_state: new_backend_state}}
  end

  @impl GenServer
  def handle_cast({:start_cams_ap, value}, state) do

    In2Firmware.Services.Operations.ReviewHW.get_lock_type()
    In2Firmware.Services.Operations.ReviewHW.get_profile()
    In2Firmware.Services.Operations.ReviewHW.get_version()
    In2Firmware.Services.Operations.ReviewHW.get_state_comm()

    if value == :ap do
      send(self(), :init_stream_gst)
    else
      Process.send_after(self(), :init_stream_gst, 10_000)
    end

    {:noreply,  state}
  end

  @impl GenServer
  def handle_cast(:init_cameras, state) do

    StreamServerIntuitivo.ServerManager.start_server(
      "camera0",           # Unique name for this stream
      "127.0.0.1",    # TCP host (camera IP)
      6000,               # TCP port
      11000                # HTTP port where the stream will be available
    )

    StreamServerIntuitivo.ServerManager.start_server(
      "camera1",           # Unique name for this stream
      "127.0.0.1",    # TCP host (camera IP)
      6001,               # TCP port
      11001                # HTTP port where the stream will be available
    )

    StreamServerIntuitivo.ServerManager.start_server(
      "camera2",           # Unique name for this stream
      "127.0.0.1",    # TCP host (camera IP)
      6002,               # TCP port
      11002                # HTTP port where the stream will be available
    )

    {:noreply,  state}
  end

  @impl GenServer
  def handle_cast(:stop_cameras, state) do

    Logger.info("stop_cameras from backend_server")

    StreamServerIntuitivo.ServerManager.stop_server("camera0")
    StreamServerIntuitivo.ServerManager.stop_server("camera1")
    StreamServerIntuitivo.ServerManager.stop_server("camera2")

    In2Firmware.Services.Operations.ReviewHW.stop_cameras()

    {:noreply,  state}
  end

  @impl GenServer
  def handle_cast({:set_door, door}, state) do
    {:noreply, %{state | door: door}}
  end

  @impl GenServer
  def handle_cast({:set_lock, lock}, state) do
    # Aseguramos que el mapa lock tenga todas las claves necesarias
    complete_lock = %{
      lock: lock["lock"] || "locked",
      working: lock["working"],
      timestamp: lock["timestamp"] || DateTime.utc_now() |> DateTime.to_iso8601()
    }

    Logger.info("complete_lock: #{inspect(complete_lock)}")

    {:noreply, %{state | lock: complete_lock}}
  end

  @impl GenServer
  def handle_cast({:set_lock_type, lock_type}, state) do
    {:noreply, %{state | lock_type: lock_type}}
  end

  @impl GenServer
  def handle_cast({:set_state_imbera, state_imbera}, state) do
    {:noreply, %{state | state_imbera: state_imbera}}
  end

  @impl GenServer
  def handle_cast({:set_state_nama, nama}, state) do
    new_nama = %{enabled: nama}
    {:noreply, %{state | state_nama: new_nama}}
  end

  @impl GenServer
  def handle_cast({:set_state_profile, profile}, state) do

    new_profile = %{profile: profile}
    {:noreply, %{state | state_profile: new_profile}}
  end

  @impl GenServer
  def handle_cast({:set_temp, temperature}, state) do
    Logger.info("temperature: #{inspect(temperature)}")
    new_temperature = %{temperature: temperature}
    {:noreply, %{state | state_temperature: new_temperature}}
  end

  @impl GenServer
  def handle_cast({:set_version, version}, state) do
    # Si version viene como string, lo envolvemos en el mapa
    new_version = %{version: version}
    {:noreply, %{state | state_version: new_version}}
  end

  @impl GenServer
  def handle_cast({:set_state_comm, state_comm}, state) do

    Logger.info("state_comm: #{inspect(state_comm)}")

    {:noreply, %{state | state_comm: state_comm}}
  end

  @impl GenServer
  def handle_cast({:change_lock, value}, state) do

    In2Firmware.Services.Operations.ReviewHW.change_lock(value)

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_method, value}, state) do

    Logger.info("config: #{inspect(value)}")

    config = Jason.encode!(value)

    File.write("/root/config_wifi.txt", config, [:write])

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_lock, value}, state) do

    Logger.info("New lock TYPE: #{inspect(value)}")

    if state.lock_type["lock_type"] != value do
      In2Firmware.Services.Operations.Utils.set_lock_type(value)
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_apn, apn}, state) do

    Logger.info("apn: #{inspect(apn)}")

    if apn != "" do
      File.write("/root/apn.txt", apn, [:write])

      In2Firmware.check_cellular_connection(In2Firmware.target())
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_internet, internet}, state) do

    Logger.info("internet: #{inspect(internet)}")

    if internet != "" and internet != "disabled" do
      File.write("/root/internet.txt", internet, [:write])

      In2Firmware.check_sharing_connection()
    else
      File.write("/root/internet.txt", "", [:write])
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_ntp, ntps}, state) do

    Logger.info("NTPS: #{inspect(ntps)}")

    if ntps != "" do
      File.write("/root/ntps.txt", ntps, [:write])

    result = File.read("/root/ntps.txt")

    case result do
      {:ok, binary} -> if binary != "" do
        servers = String.split(binary, ",")
        NervesTime.set_ntp_servers(servers)
      end
      {:error, _posix} -> ""
    end
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:change_profile, profile}, state) do

    Logger.info("profile: #{inspect(profile)}")

    In2Firmware.Services.Operations.ReviewHW.set_profile(profile)

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:subscribe, subscriber}, state) do
    {:noreply, %{state | subscriber: subscriber}}
  end

  @impl GenServer
  def handle_info(
        info,
        %State{
          subscriber: subscriber,
          backend: backend,
          backend_state: backend_state
        } = state
      ) do
    case backend.handle_info(info, backend_state) do
      {:reply, message, new_backend_state} ->
        maybe_send(subscriber, {VintageNetWizard, message})
        {:noreply, %{state | backend_state: new_backend_state}}

      {:noreply, %{state: :idle, data: %{configuration_status: :good}} = new_backend_state} ->
        # idle state with good configuration means we've completed setup
        # and wizard has been shut down. So let's clear configurations
        # so aren't hanging around in memory

        {:noreply, %{state | configurations: %{}, backend_state: new_backend_state}}

      {:noreply, new_backend_state} ->
        {:noreply, %{state | backend_state: new_backend_state}}
    end
  end

  @impl GenServer
  def handle_info(:get_ntp, state) do

    result = File.read("/root/ntps.txt")

    list = case result do
      {:ok, binary} -> binary
      {:error, _posix} -> ""
    end

    {:noreply, %{state | ntp: list}}
  end

  @impl GenServer
  def handle_info(:get_apn, state) do

    result = File.read("/root/apn.txt")

    apn = case result do
      {:ok, binary} -> binary
      {:error, _posix} -> ""
    end

    {:noreply, %{state | apn: apn}}
  end

  @impl GenServer
  def handle_info(:get_internet_select, state) do

    result = File.read("/root/internet.txt")

    internet_select = case result do
      {:ok, binary} -> binary
      {:error, _posix} -> ""
    end

    {:noreply, %{state | internet_select: internet_select}}
  end

  defp build_config_list(configs) do
    configs
    |> Enum.into([], &elem(&1, 1))
    |> Enum.sort(fn config1, config2 ->
      config1_priority = get_in(config1, [:priority])
      config2_priority = get_in(config2, [:priority])

      case {config1_priority, config2_priority} do
        {nil, nil} -> false
        {nil, _} -> false
        {_, nil} -> true
        {p1, p2} -> p1 <= p2
      end
    end)
  end

  defp maybe_send(nil, _message), do: :ok
  defp maybe_send(pid, message), do: send(pid, message)

  defp get_priority_for_ssid(priority_order_list, ssid) do
    priority_index =
      Enum.find(priority_order_list, fn
        {^ssid, _} -> true
        _ -> false
      end)
      |> elem(1)

    priority_index + 1
  end

  defp clean_config(config) do
    Map.drop(config, [:psk, :password])
  end

  defp old_connection(ifname) do
    [{_, connection}] = VintageNet.get_by_prefix(["interface", ifname, "connection"])

    connection
  end

  defp maybe_send_connection_info(%State{ifname: ifname}, old_connection) do
    [{_, new_connection}] = VintageNet.get_by_prefix(["interface", ifname, "connection"])

    if old_connection == new_connection do
      info =
        {VintageNet, ["interface", ifname, "connection"], old_connection, new_connection, %{}}

      send(self(), info)
    else
      :ok
    end
  end

  defp deconfigure_ap_ifname(state) do
    if state.ifname != state.ap_ifname do
      VintageNet.deconfigure(state.ap_ifname)
    else
      if state.ifname do
        networks = build_config_list(state.configurations)
        APMode.exit_ap_mode(state.ifname, networks)
      else
        :ok
      end
    end
  end

  # Helper functions for board config
  defp get_wifi_networks(state) do
    state.configurations
    |> Map.values()
    |> Enum.map(fn config ->
      key_mgmt = case config[:key_mgmt] do
        :wpa_psk -> "wpa-psk"
        :wpa2_psk -> "wpa2-psk"
        :wpa_eap -> "wpa-eap"
        :none -> "none"
        nil -> "none"
        other -> to_string(other)
      end

      %{
        ssid: config.ssid,
        password: config[:psk] || "",
        key_mgmt: key_mgmt
      }
    end)
  end

  defp get_network_method() do
    result = File.read("/root/config_wifi.txt")

    case result do
      {:ok, binary} -> if binary != "" do
        {:ok, decoded_map} = Jason.decode(binary)
        case decoded_map["method"] do
          "dhcp" -> "dhcp"
          "static" -> "static"
        end
      else
        "dhcp"
      end
      {:error, _posix} -> "dhcp"
    end
  end

  defp get_static_config() do
    result = File.read("/root/config_wifi.txt")

    case result do
      {:ok, binary} -> if binary != "" do
        {:ok, decoded_map} = Jason.decode(binary)
        case decoded_map["method"] do
          "dhcp" -> %{}
          "static" -> %{
            address: decoded_map["address"],
            netmask: decoded_map["netmask"],
            gateway: decoded_map["gateway"],
            name_servers: decoded_map["name_servers"]
        }
        end
      else
        %{}
      end
      {:error, _posix} -> %{}
    end
  end


  def get_cameras() do
    device_ip = VintageNet.get(["interface", "wlan0", "addresses"])
                |> Enum.find(fn addr -> addr.family == :inet end)
                |> case do
                  nil -> "localhost"
                  addr -> addr.address
                         |> Tuple.to_list()
                         |> Enum.join(".")
                         |> to_string()
                end

    [
      %{
        id: "cam0",
        name: "Upper Central Camera",
        status: if(StreamServerIntuitivo.ServerManager.get_server("camera0"), do: "online", else: "offline"),
        streamUrl: "http://#{device_ip}:11000"
      },
      %{
        id: "cam1",
        name: "Upper Lateral Camera",
        status: if(StreamServerIntuitivo.ServerManager.get_server("camera1"), do: "online", else: "offline"),
        streamUrl: "http://#{device_ip}:11001"
      },
      %{
        id: "cam2",
        name: "Lateral Retractable Camera",
        status: if(StreamServerIntuitivo.ServerManager.get_server("camera2"), do: "online", else: "offline"),
        streamUrl: "http://#{device_ip}:11002"
      }
    ]
  end

  def configuration_status_details(:not_configured), do: "No network configuration present"
  def configuration_status_details(:good), do: "Network configured and connected"
  def configuration_status_details(:bad), do: "Network configuration present but not connected"

end
