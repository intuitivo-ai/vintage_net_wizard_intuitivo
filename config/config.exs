import Config

config :vintage_net,
  resolvconf: "/dev/null",
  persistence: VintageNet.Persistence.Null

config :vintage_net_wizard,
  api_key: System.get_env("FW_SECRET_KEY") ||
  raise("""
  environment variable FW_SECRET_KEY is missing.
  For example: Xqsja2bp+jfreCkl4bRFZoyljM2RL0RC4PNBkTtKXrk=
  """)

import_config "#{Mix.env()}.exs"
