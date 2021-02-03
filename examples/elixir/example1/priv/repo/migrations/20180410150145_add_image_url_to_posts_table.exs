defmodule BuiltWithElixir.Repo.Migrations.AddImageUrlToPostsTable do
  use Ecto.Migration

  def change do
    alter table(:posts) do
      add :image_url, :string
    end
  end
end
