import Config

config :vintage_net,
  resolvconf: "/dev/null",
  persistence: VintageNet.Persistence.Null

config :vintage_net, :basic_auth, 
  username: "operator", 
  password: Application.get_env(:vintage_net, "CONFIG_PWD") || "4dministr4t0r!!"

import_config "#{Mix.env()}.exs"
