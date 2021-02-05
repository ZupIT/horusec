Code.load_file("test/stubs/cloudini.ex")

ExUnit.start()

Ecto.Adapters.SQL.Sandbox.mode(BuiltWithElixir.Repo, :manual)
