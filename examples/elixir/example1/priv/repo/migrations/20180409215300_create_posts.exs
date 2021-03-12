defmodule BuiltWithElixir.Repo.Migrations.CreatePosts do
  use Ecto.Migration

  def change do
    create table(:posts) do
      add(:title, :string)
      add(:description, :string)
      add(:author, :string)
      add(:website_url, :string)
      add(:github_url, :string)
      add(:type, :string)

      timestamps()
    end
  end
end
