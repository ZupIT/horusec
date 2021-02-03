use Mix.Config

# Config that is put into the front-end window.config

config :built_with_elixir, :web,
  # Optional. 
  google_analytics: Map.get(System.get_env(), "GOOGLE_ANALYTICS_KEY")
