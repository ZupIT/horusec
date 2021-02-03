alias BuiltWithElixir.Projects

# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     BuiltWithElixir.Repo.insert!(%BuiltWithElixir.SomeSchema{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.
posts =
  with {:ok, body} <- File.read("./priv/repo/dev-posts.json"),
       {:ok, json} <- JSON.decode(body),
       do: json

Enum.map(posts, fn post -> Projects.create_post(post) end)
