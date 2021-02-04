defmodule BuiltWithElixir.Repo.Migrations.UpdateDescriptionLengthOnPosts do
  use Ecto.Migration

  def change do
    alter table(:posts) do
      modify :description, :string, size: 1024
    end
  end
end
