defmodule BuiltWithElixirWeb.PostView do
  use BuiltWithElixirWeb, :view
  alias BuiltWithElixirWeb.PostView

  def render("index.json", %{posts: posts}) do
    %{data: render_many(posts, PostView, "post.json")}
  end

  def render("show.json", %{post: post}) do
    %{data: render_one(post, PostView, "post.json")}
  end

  def render("post.json", %{post: post}) do
    %{
      id: post.id,
      title: post.title,
      description: post.description,
      author: post.author,
      website_url: post.website_url,
      github_url: post.github_url,
      type: post.type,
      image_url: post.image_url,
      inserted_at: post.inserted_at
    }
  end
end
