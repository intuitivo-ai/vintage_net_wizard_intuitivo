defmodule VintageNetWizard.APTimer do
  @moduledoc false

  # Separate timer for AP mode auto-shutdown.
  #
  # The WatchDog controls the HTTP server lifetime (can be :infinity).
  # This timer controls how long the AP stays up (defaults to 15 minutes).
  #
  # When the timer fires, the AP is taken down but the HTTP server keeps running
  # (transitions to server_only mode).
  #
  # Configure via:
  #   config :vintage_net_wizard, ap_timeout: 15     # minutes
  #   config :vintage_net_wizard, ap_timeout: :infinity  # never auto-stop AP

  use GenServer, restart: :transient

  require Logger

  @doc "Start the AP timer"
  def start_link({timeout_minutes, ap_ifname}) do
    GenServer.start_link(__MODULE__, {timeout_minutes, ap_ifname}, name: __MODULE__)
  end

  @doc "Reset the AP timer (e.g. on user activity)"
  def pet do
    if pid = Process.whereis(__MODULE__) do
      GenServer.call(pid, :pet)
    else
      :ok
    end
  end

  @impl GenServer
  def init({:infinity, _ap_ifname}) do
    Logger.info("[APTimer] AP timeout disabled (infinity)")
    {:ok, :infinity}
  end

  def init({timeout_minutes, ap_ifname}) when is_integer(timeout_minutes) and timeout_minutes > 0 do
    timeout_ms = timeout_minutes * 60_000
    Logger.info("[APTimer] AP will auto-stop in #{timeout_minutes} min")
    ref = Process.send_after(self(), :ap_timeout, timeout_ms)
    {:ok, %{timeout_ms: timeout_ms, ap_ifname: ap_ifname, timer_ref: ref}}
  end

  @impl GenServer
  def handle_call(:pet, _from, :infinity) do
    {:reply, :ok, :infinity}
  end

  def handle_call(:pet, _from, %{timeout_ms: timeout_ms} = state) do
    Process.cancel_timer(state.timer_ref, info: false)
    # Flush any stale :ap_timeout that fired before cancel
    receive do
      :ap_timeout -> :ok
    after
      0 -> :ok
    end
    ref = Process.send_after(self(), :ap_timeout, timeout_ms)
    {:reply, :ok, %{state | timer_ref: ref}}
  end

  @impl GenServer
  def handle_info(:ap_timeout, %{ap_ifname: ap_ifname} = state) do
    Logger.info("[APTimer] AP timeout reached — stopping AP mode on #{ap_ifname}")

    # Read the PERSISTED config (pre-AP WiFi networks), not the runtime AP config
    config = VintageNet.get_configuration(ap_ifname)

    networks =
      case get_in(config, [:vintage_net_wifi, :networks]) do
        nil -> []
        nets -> Enum.reject(nets, &(Map.get(&1, :mode) == :ap))
      end

    VintageNetWizard.APMode.exit_ap_mode(ap_ifname, networks)
    {:stop, :normal, state}
  end

  @impl GenServer
  def terminate(:normal, _), do: :ok
end
