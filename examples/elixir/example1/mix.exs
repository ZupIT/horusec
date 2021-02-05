defmodule BuiltWithElixir.Mixfile do
  use Mix.Project

  def project do
    [
      app: :built_with_elixir,
      version: "0.0.1",
      elixir: "~> 1.4",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: [:phoenix, :gettext] ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {BuiltWithElixir.Application, []},
      extra_applications: [:logger, :runtime_tools, :cloudini]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:phoenix, "~> 1.3.0"},
      {:phoenix_pubsub, "~> 1.0"},
      {:phoenix_ecto, "~> 3.2"},
      {:postgrex, ">= 0.0.0"},
      {:phoenix_html, "~> 2.10"},
      {:gettext, "~> 0.11"},
      {:cowboy, "~> 1.0"},
      {:json, "~> 1.0"},
      {:credo, "~> 0.9.1"},
      {:plug_cowboy, "~> 1.0"},
      {:cloudini, "~> 1.2"},
      {:phoenix_live_reload, "~> 1.0", only: :dev},
      {:mix_test_watch, "~> 0.6.0", only: :dev}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to create, migrate and run the seeds file at once:
  #
  #     $ mix ecto.setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      "ecto.setup.dev": ["ecto.create", "ecto.migrate", "run priv/repo/dev-seed.exs"],
      "ecto.reset.dev": ["ecto.drop", "ecto.setup.dev"],
      "ecto.setup.prod": ["ecto.create", "ecto.migrate", "run priv/repo/prod-seed.exs"],
      "ecto.reset.prod": ["ecto.drop", "ecto.setup.prod"],
      test: ["ecto.create --quiet", "ecto.migrate", "test"]
    ]
  end
end
