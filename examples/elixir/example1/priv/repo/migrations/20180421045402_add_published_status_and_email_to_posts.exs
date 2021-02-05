defmodule BuiltWithElixir.Repo.Migrations.AddPublishedStatusToPosts do
  use Ecto.Migration

  def change do
    alter table(:posts) do
      add(:published, :boolean, default: false)
      add(:author_email, :string)
    end
  end
end
