defmodule VintageNetWizard.Callbacks do
  @moduledoc """
  Agent for on_exit callbacks and wrapper for firmware-specific callbacks
  configured via application env.

  The Agent part handles lifecycle callbacks (on_exit) used by the Endpoint.
  The firmware wrappers read module references from config to avoid
  compile-time dependencies on In2Firmware modules.

  ## Configuration

      config :vintage_net_wizard,
        firmware_module: In2Firmware,
        operations_module: In2Firmware.Services.Operations,
        review_hw_module: In2Firmware.Services.Operations.ReviewHW,
        operations_utils_module: In2Firmware.Services.Operations.Utils,
        lock_module: In2Firmware.Services.Lock
  """

  use Agent

  require Logger

  # ============================================================================
  # Agent lifecycle (used by Endpoint)
  # ============================================================================

  @type callback :: {:on_exit, {module(), atom(), any()}}
  @type callbacks :: [callback]

  @spec start_link(callbacks) :: GenServer.on_start()
  def start_link(callbacks) do
    callbacks = Enum.reduce(callbacks, [], &validate_callback/2)
    Agent.start_link(fn -> callbacks end, name: __MODULE__)
  end

  @spec list() :: any()
  def list() do
    Agent.get(__MODULE__, & &1)
  end

  @spec on_exit() :: any()
  def on_exit() do
    list()
    |> Keyword.get(:on_exit)
    |> apply_callback()
  end

  defp apply_callback({mod, fun, args}) do
    apply(mod, fun, args)
  rescue
    err ->
      Logger.error("[VintageNetWizard] Failed to run callback: #{inspect(err)}")
  end

  defp apply_callback(invalid), do: {:error, "invalid callback: #{inspect(invalid)}"}

  defp validate_callback({_key, {mod, fun, args}} = callback, acc)
       when is_atom(mod) and is_atom(fun) and is_list(args) do
    [callback | acc]
  end

  defp validate_callback({key, invalid}, acc) do
    Logger.warning(
      "Skipping invalid callback option for #{inspect(key)}\n\tgot: #{inspect(invalid)}\n\texpected: {module, function, [args]}"
    )

    acc
  end

  # ============================================================================
  # Firmware module wrappers (read from config, no compile-time dependency)
  # ============================================================================

  defp mod(key), do: Application.get_env(:vintage_net_wizard, key)

  defp safe_call(config_key, fun, args \\ []) do
    case mod(config_key) do
      nil ->
        Logger.debug("VintageNetWizard.Callbacks: #{config_key} not configured, skipping #{fun}/#{length(args)}")
        :ok

      module ->
        apply(module, fun, args)
    end
  end

  # --- ReviewHW callbacks ---

  def review_hw_get_lock_type, do: safe_call(:review_hw_module, :get_lock_type)
  def review_hw_get_profile, do: safe_call(:review_hw_module, :get_profile)
  def review_hw_get_version, do: safe_call(:review_hw_module, :get_version)
  def review_hw_get_state_comm, do: safe_call(:review_hw_module, :get_state_comm)
  def review_hw_get_init_state, do: safe_call(:review_hw_module, :get_init_state)
  def review_hw_change_lock(value), do: safe_call(:review_hw_module, :change_lock, [value])
  def review_hw_set_profile(profile), do: safe_call(:review_hw_module, :set_profile, [profile])

  # --- Operations callbacks ---

  def operations_re_init_http, do: safe_call(:operations_module, :re_init_http)
  def operations_re_stop_http, do: safe_call(:operations_module, :re_stop_http)
  def operations_re_stop_tcp, do: safe_call(:operations_module, :re_stop_tcp)
  def operations_init_trx_op, do: safe_call(:operations_module, :init_trx_op)

  @doc """
  Returns camera statuses from the Operations GenServer.
  Returns %{0 => true/false/nil, 1 => ..., 2 => ...} or nil if not configured.
  """
  def operations_get_cameras_status do
    case mod(:operations_module) do
      nil -> nil
      module -> module.get_cameras_status()
    end
  end

  # --- Operations.Utils callbacks ---

  def utils_set_lock_type(value), do: safe_call(:operations_utils_module, :set_lock_type, [value])

  # --- Lock callbacks ---

  def lock_activate_nama(value), do: safe_call(:lock_module, :activate_nama, [value])

  # --- Firmware (root module) callbacks ---

  def firmware_check_cellular_connection do
    case mod(:firmware_module) do
      nil ->
        Logger.debug("VintageNetWizard.Callbacks: firmware_module not configured, skipping check_cellular_connection")
        :ok

      module ->
        module.check_cellular_connection(module.target())
    end
  end

  def firmware_check_sharing_connection(interface) do
    safe_call(:firmware_module, :check_sharing_connection, [interface])
  end
end
