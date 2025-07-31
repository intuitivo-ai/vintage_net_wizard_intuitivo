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
  Force a manual scan for access points (useful for problematic hardware)
  """
  @spec force_scan() :: :ok
  def force_scan() do
    GenServer.cast(__MODULE__, :force_scan)
  end

  @doc """
  Get access points from the backend
  """
  @spec access_points() :: [VintageNetWiFi.AccessPoint.t()]
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
  Save WiFi networks with passwords to persistent file
  """
  @spec save_wifi_networks(list()) :: :ok
  def save_wifi_networks(networks) do
    GenServer.cast(__MODULE__, {:save_wifi_networks, networks})
  end

  @doc """
  Get WiFi networks with passwords from persistent file
  """
  @spec get_wifi_networks_with_passwords() :: list()
  def get_wifi_networks_with_passwords() do
    GenServer.call(__MODULE__, :get_wifi_networks_with_passwords)
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

  def reboot do
    GenServer.cast(__MODULE__, :reboot)
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

  @doc """
  Get the WiFi networks configurations
  """
  @spec get_wifi_networks() :: list()
  def get_wifi_networks() do
    GenServer.call(__MODULE__, :get_wifi_networks)
  end

  @doc """
  Get the AP interface name
  """
  @spec get_ap_ifname() :: String.t()
  def get_ap_ifname() do
    GenServer.call(__MODULE__, :get_ap_ifname)
  end

  @doc """
  Get the complete state for debugging purposes
  """
  @spec get_configuration_state() :: State.t()
  def get_configuration_state() do
    GenServer.call(__MODULE__, :configuration_state)
  end

  @impl GenServer
  def handle_call(:get_lock, _from, %State{state_comm: state_comm} = state) do

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
    Logger.info("BACKEND_SERVER: Access points requested - Found #{length(access_points)} networks")
    
    if length(access_points) == 0 do
      Logger.warn("BACKEND_SERVER: No access points found - this may indicate scanning issues with hardware")
      Logger.info("BACKEND_SERVER: Triggering additional scan attempt")
      # Force a scan if no access points are found
      case VintageNet.scan(state.ifname) do
        :ok -> Logger.info("BACKEND_SERVER: Additional scan triggered successfully")
        {:error, reason} -> Logger.error("BACKEND_SERVER: Additional scan failed: #{inspect(reason)}")
      end
    end
    
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

    # Also save to .psk_wifi.json file with password
    updated_configs = Map.put(configs, config.ssid, full_config)
    save_networks_to_file(updated_configs)

    {:reply, :ok, %{state | configurations: updated_configs}}
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
    Logger.warning("BACKEND_SERVER: Apply failed - No configurations found")
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
    Logger.info("BACKEND_SERVER: Apply starting - Backend state: #{inspect(backend_state.state)}, Configs: #{map_size(wifi_configs)}")
    
    old_connection = old_connection(ifname)

    case backend.apply(build_config_list(wifi_configs), backend_state) do
      {:ok, new_backend_state} ->
        Logger.info("BACKEND_SERVER: Apply successful - New backend state: #{inspect(new_backend_state.state)}")
        updated_state = %{state | backend_state: new_backend_state}
        # If applying the new configuration does not change the connection,
        # send a message to that effect so the Wizard does not timeout
        # waiting for one from VintageNet
        maybe_send_connection_info(updated_state, old_connection)
        {:reply, :ok, updated_state}

      {:error, _} = error ->
        Logger.error("BACKEND_SERVER: Apply failed - Error: #{inspect(error)}, Backend state: #{inspect(backend_state.state)}")
        {:reply, error, state}
    end
  end

  def handle_call(:get_board_config, _from, %State{backend: backend, backend_state: backend_state} = state) do

    status = backend.configuration_status(backend_state)

    result = case File.read("/root/.secret_wifi.txt") do
      {:ok, content} ->
        # Intenta decodificar el contenido como JSON
        case Jason.decode(content) do
          {:ok, json_data} ->
            # Si es JSON válido, usa directamente los campos ssid y password
            %{
              ssid: json_data["ssid"] || "",
              password: json_data["password"] || ""
            }

          {:error, _} ->
            %{ssid: "", password: ""}
        end

      {:error, _reason} ->
        # Si hay un error al leer el archivo, devolver valores vacíos
        %{ssid: "", password: ""}
    end

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
      wifihotspotOutput: %{
        ssid: result.ssid,
        password: result.password
      },
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
    # Clear .psk_wifi.json file
    save_networks_to_file(%{})
    {:reply, :ok, %{state | configurations: %{}, backend_state: new_state}}
  end

  def handle_call({:delete_configuration, ssid}, _from, %State{configurations: configs} = state) do
    updated_configs = Map.delete(configs, ssid)
    # Also update .psk_wifi.json file
    save_networks_to_file(updated_configs)
    {:reply, :ok, %{state | configurations: updated_configs}}
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
  def handle_cast({:start_cams_ap, _value}, %State{backend: backend, backend_state: backend_state} = state) do

    Logger.info("BACKEND_SERVER: Starting AP mode - Current backend state: #{inspect(backend_state.state)}")

    In2Firmware.Services.Operations.ReviewHW.get_lock_type()
    In2Firmware.Services.Operations.ReviewHW.get_profile()
    In2Firmware.Services.Operations.ReviewHW.get_version()
    In2Firmware.Services.Operations.ReviewHW.get_state_comm()
    In2Firmware.Services.Operations.ReviewHW.get_init_state()

    # Reset backend state to allow new configurations when entering AP mode
    new_backend_state = backend.reset(backend_state)
    Logger.info("BACKEND_SERVER: Backend state reset to: #{inspect(new_backend_state.state)} for new AP mode session")

    {:noreply, %{state | backend_state: new_backend_state}}
  end

  @impl GenServer
  def handle_cast(:init_cameras, state) do

    # Verifica el estado de la cámara y actúa en consecuencia
    #if StreamServerIntuitivo.ServerManager.get_server("camera0") in [nil, "offline"] do
    #  StreamServerIntuitivo.ServerManager.start_server(
    #    "camera0",           # Unique name for this stream
    #    "127.0.0.1",    # TCP host (camera IP)
    #    6000,               # TCP port
    #    11000                # HTTP port where the stream will be available
    #  )
    #end

    #if StreamServerIntuitivo.ServerManager.get_server("camera1") in [nil, "offline"] do
    #  StreamServerIntuitivo.ServerManager.start_server(
    #    "camera1",           # Unique name for this stream
    #    "127.0.0.1",    # TCP host (camera IP)
    #    6001,               # TCP port
    #    11001                # HTTP port where the stream will be available
    #  )
    #end

    #if StreamServerIntuitivo.ServerManager.get_server("camera2") in [nil, "offline"] do
    #  StreamServerIntuitivo.ServerManager.start_server(
    #    "camera2",           # Unique name for this stream
    #    "127.0.0.1",    # TCP host (camera IP)
    #    6002,               # TCP port
    #    11002                # HTTP port where the stream will be available
    #  )
    #end

    In2Firmware.Services.Operations.re_init_http()

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast(:stop_cameras, state) do

    Logger.info("stop_cameras from backend_server")

    #StreamServerIntuitivo.ServerManager.stop_server("camera0")
    #StreamServerIntuitivo.ServerManager.stop_server("camera1")
    #StreamServerIntuitivo.ServerManager.stop_server("camera2")

    #In2Firmware.Services.Operations.ReviewHW.stop_cameras()

    #In2Firmware.Services.Operations.default_init_cameras()

    In2Firmware.Services.Operations.re_stop_http()
    In2Firmware.Services.Operations.re_stop_tcp()

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

    {:noreply, %{state | state_comm: state_comm}}
  end

  @impl GenServer
  def handle_cast({:change_lock, value}, state) do

    In2Firmware.Services.Operations.ReviewHW.change_lock(value)

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_method, value}, state) do

    config = Jason.encode!(value)

    File.write("/root/config_wifi.txt", config, [:write])

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_lock, value}, state) do

    if state.lock_type["lock_type"] != value do
      In2Firmware.Services.Operations.Utils.set_lock_type(value)
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_apn, apn}, state) do

    if apn != "" do
      File.write("/root/apn.txt", apn, [:write])

      In2Firmware.check_cellular_connection(In2Firmware.target())
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast(:reboot, state) do

    Process.send_after(self(), :reboot_device, 5_000)

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:save_internet, internet}, %State{configurations: configs} = state) do
    new_state = if internet != "" and internet != "disabled" do
      File.write("/root/internet.txt", internet, [:write])
      if internet == "wwan0_to_wlan0" or internet == "eth0_to_wlan0" do
        # Generate random SSID and password for AP mode
        random_ssid = "INTUITIVO_" <> random_string(6)
        random_password = random_password(16)

        # Save credentials to secret file
        save_ap_credentials(random_ssid, random_password)
      else
        In2Firmware.check_sharing_connection("")
      end
      state
    else
      updated_state = if File.exists?("/root/internet.txt") do
        result = File.read("/root/internet.txt")
        case result do
          {:ok, interface} ->
            File.write("/root/internet.txt", "", [:write])
            In2Firmware.check_sharing_connection(interface)
            ap_credentials = get_ap_credentials()
            if ap_credentials.ssid != "" and ap_credentials.password != "" do
              # Modify state directly
              %{state | configurations: Map.delete(configs, ap_credentials.ssid)}
            else
              state
            end
          {:error, _posix} ->
            File.write("/root/internet.txt", "", [:write])
            In2Firmware.check_sharing_connection("")
            ap_credentials = get_ap_credentials()
            if ap_credentials.ssid != "" and ap_credentials.password != "" do
              # Modify state directly
              %{state | configurations: Map.delete(configs, ap_credentials.ssid)}
            else
              state
            end
        end
      else
        File.write("/root/internet.txt", "", [:write])
        In2Firmware.check_sharing_connection("")
        ap_credentials = get_ap_credentials()
        if ap_credentials.ssid != "" and ap_credentials.password != "" do
          # Modify state directly
          %{state | configurations: Map.delete(configs, ap_credentials.ssid)}
        else
          state
        end
      end
      updated_state
    end

    {:noreply, new_state}
  end

  @impl GenServer
  def handle_cast({:save_ntp, ntps}, state) do

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

    In2Firmware.Services.Operations.ReviewHW.set_profile(profile)

    {:noreply, state}
  end

  @impl GenServer
  def handle_cast({:subscribe, subscriber}, state) do
    {:noreply, %{state | subscriber: subscriber}}
  end

  @impl GenServer
  def handle_cast({:save_wifi_networks, networks}, state) do
    # Save networks with passwords to .psk_wifi.json file
    wifi_data = %{
      networks: networks,
      saved_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    json = Jason.encode!(wifi_data, pretty: true)
    File.write("/root/.psk_wifi.json", json, [:write])

    {:noreply, state}
  end

  @impl GenServer
  def handle_call(:get_wifi_networks_with_passwords, _from, state) do
    networks = case File.read("/root/.psk_wifi.json") do
      {:ok, binary} ->
        case Jason.decode(binary) do
          {:ok, %{"networks" => networks}} -> networks
          {:error, _} -> []
        end
      {:error, _} -> []
    end

    {:reply, networks, state}
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
        # 
        # COMMENTED OUT: Don't clear configurations to allow reconfiguration
        # This was causing issues when trying to configure WiFi a second time
        # {:noreply, %{state | configurations: %{}, backend_state: new_backend_state}}
        
        Logger.info("BACKEND_SERVER: Configuration successful, maintaining configurations for potential reconfiguration")
        {:noreply, %{state | backend_state: new_backend_state}}

      {:noreply, new_backend_state} ->
        {:noreply, %{state | backend_state: new_backend_state}}
    end
  end

  defp get_init_values() do


      result = File.read("/root/ntps.txt")

      ntps = case result do
        {:ok, binary} -> binary
        {:error, _posix} -> ""
      end

      result = File.read("/root/apn.txt")

      apn = case result do
        {:ok, binary} -> binary
        {:error, _posix} -> ""
      end

      result = File.read("/root/internet.txt")

      internet_select = case result do
        {:ok, binary} -> binary
        {:error, _posix} -> ""
      end

    %{
      internet_select: internet_select,
      apn: apn,
      ntps: ntps
    }
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
    # Read from .psk_wifi.json file instead of state
    case File.read("/root/.psk_wifi.json") do
      {:ok, binary} ->
        case Jason.decode(binary) do
          {:ok, %{"networks" => networks}} -> networks
          {:error, _} -> []
        end
      {:error, _} ->
        # Fallback to state if file doesn't exist
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
            key_mgmt: key_mgmt,
            priority: config[:priority] || 1
          }
        end)
        |> Enum.sort_by(& &1[:priority])  # Sort by priority
    end
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
    device_ip = Application.get_env(:vintage_net_wizard, :dns_name, "setup.firmware.intuitivo.com")

    [
       #%{
       #  id: "cam0",
       #  name: "Upper Central Camera",
       #  status: "online",
       #  streamUrl: "http://#{device_ip}:11000"
       #},
       #%{
       #  id: "cam1",
       #  name: "Upper Lateral Camera",
       #  status: "online",
       #  streamUrl: "http://#{device_ip}:11001"
       #},
       #%{
       #  id: "cam2",
       #  name: "Lateral Retractable Camera",
       #  status: "online",
       #  streamUrl: "http://#{device_ip}:11002"
       #}

      %{
        id: "cam0",
        name: "Upper Central Camera",
        status: "online",
        host: device_ip,
        port: 11000
      },
      %{
        id: "cam1",
        name: "Upper Lateral Camera",
        status: "online",
        host: device_ip,
        port: 11001
      },
      %{
        id: "cam2",
        name: "Lateral Retractable Camera",
        status: "online",
        host: device_ip,
        port: 11002
      }

    ]
  end

  def configuration_status_details(:not_configured), do: "No network configuration present"
  def configuration_status_details(:good), do: "Network configured and connected"
  def configuration_status_details(:bad), do: "Network configuration present but not connected"

  # Generates a random string of specified length using uppercase letters and numbers
  defp random_string(length) do
    chars = ~w(A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9)
    Enum.take_random(chars, length) |> Enum.join("")
  end

  # Generates a secure random password with specified minimum length
  # including uppercase, lowercase, numbers and special characters
  defp random_password(min_length) do
    # Ensure we have at least one of each character type
    upper = random_string(4)
    lower = String.downcase(random_string(4))
    numbers = Enum.map(1..4, fn _ -> Enum.random(0..9) end) |> Enum.join("")
    special = Enum.take_random(~w(! @ # $ % ^ & * + - _ = ~), 4) |> Enum.join("")

    # Combine and shuffle all characters
    (upper <> lower <> numbers <> special)
    |> String.graphemes()
    |> Enum.shuffle()
    |> Enum.join("")
  end

  # Saves AP credentials to the secret file
  defp save_ap_credentials(ssid, password) do
    credentials = %{
      ssid: ssid,
      password: password,
      key_mgmt: "wpa2-psk",
      generated_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    json = Jason.encode!(credentials, pretty: true)
    File.write("/root/.secret_wifi.txt", json, [:write])
  end

  # Save networks configurations to .psk_wifi.json file
  defp save_networks_to_file(configurations) do
    networks = configurations
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

    wifi_data = %{
      networks: networks,
      saved_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    json = Jason.encode!(wifi_data, pretty: true)
    File.write("/root/.psk_wifi.json", json, [:write])
  end

  def get_ap_credentials() do
    result = File.read("/root/.secret_wifi.txt")

    case result do
      {:ok, binary} ->
        credentials = Jason.decode!(binary)
        # Convert string keys to atoms
        %{
          ssid: credentials["ssid"] || "",
          password: credentials["password"] || "",
          key_mgmt: credentials["key_mgmt"] || "wpa2-psk",
          generated_at: credentials["generated_at"] || ""
        }
      {:error, _posix} -> %{ssid: "", password: ""}
    end
  end

  @impl GenServer
  def init([backend, ifname, opts]) do
    device_info = Keyword.get(opts, :device_info, [])

    configurations =
      opts
      |> Keyword.get(:configurations, [])
      |> Enum.into(%{}, fn config -> {config.ssid, config} end)

    ap_ifname = Keyword.fetch!(opts, :ap_ifname)

    result = get_init_values()

    {:ok,
     %State{
       configurations: configurations,
       backend: backend,
       # Scanning is done by ifname
       backend_state: backend.init(ifname, ap_ifname),
       device_info: device_info,
       ifname: ifname,
       ap_ifname: ap_ifname,
       internet_select: result.internet_select,
       apn: result.apn,
       ntp: result.ntps
     }}
  end

  @impl GenServer
  def handle_call(:get_wifi_networks, _from, state) do
    wifi_networks = get_wifi_networks(state)
    {:reply, wifi_networks, state}
  end

  @impl GenServer
  def handle_call(:get_ap_ifname, _from, %State{ap_ifname: ap_ifname} = state) do
    {:reply, ap_ifname, state}
  end

  @impl GenServer
  def handle_cast(:force_scan, %State{backend: backend, backend_state: backend_state} = state) do
    Logger.info("BACKEND_SERVER: Force scanning for access points")
    
    # Force a scan even if it fails
    case VintageNet.scan(state.ifname) do
      :ok -> 
        Logger.info("BACKEND_SERVER: Force scan successful")
      {:error, reason} ->
        Logger.warn("BACKEND_SERVER: Force scan failed: #{inspect(reason)}")
        # Try one more time with a delay
        Process.sleep(1000)
        case VintageNet.scan(state.ifname) do
          :ok -> Logger.info("BACKEND_SERVER: Force scan successful on retry")
          {:error, retry_reason} -> Logger.error("BACKEND_SERVER: Force scan failed after retry: #{inspect(retry_reason)}")
        end
    end
    
    {:noreply, state}
  end
end
