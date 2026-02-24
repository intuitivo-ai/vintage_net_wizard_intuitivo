defmodule VintageNetWizard.Callbacks do
  @moduledoc """
  Wrapper for firmware-specific callbacks configured via application env.

  Reads module references from config to avoid compile-time dependencies
  on In2Firmware modules, preventing warnings when building the wizard as
  a separate library.

  ## Configuration

      config :vintage_net_wizard,
        firmware_module: In2Firmware,
        operations_module: In2Firmware.Services.Operations,
        review_hw_module: In2Firmware.Services.Operations.ReviewHW,
        operations_utils_module: In2Firmware.Services.Operations.Utils,
        lock_module: In2Firmware.Services.Lock
  """

  require Logger

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
