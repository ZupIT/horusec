defmodule BuiltWithElixirWeb.PostController do
  use BuiltWithElixirWeb, :controller

  alias BuiltWithElixir.Projects
  alias BuiltWithElixir.Projects.Post
  alias BuiltWithElixir.Utils.Cloudinary

  action_fallback(BuiltWithElixirWeb.FallbackController)

  @cloudini_client Cloudini.new()
  @cloudini Application.get_env(:built_with_elixir, :cloudini)

  def index(conn, params) do
    posts =
      case params do
        %{"offset" => offset, "limit" => limit} -> Projects.list_posts(offset, limit)
        %{"offset" => offset} -> Projects.list_posts(offset)
        %{"limit" => limit} -> Projects.list_posts(0, limit)
        _ -> Projects.list_posts()
      end

    render(conn, "index.json", posts: posts)
  end

  def create(conn, %{"image_file" => file} = post_params) do
    id = "build-with-elixir/#{Path.rootname(file.filename)}"

    with {:ok, %{"public_id" => public_id}} <-
           @cloudini.upload_image(@cloudini_client, file.path, public_id: id) do
      image_url = Cloudinary.generate_image_url(public_id)

      post_params =
        %{"image_url" => image_url} |> Enum.into(post_params) |> Map.delete("image_file")

      conn
      |> create(post_params)
    end
  end

  def create(conn, post_params) do
    with {:ok, %Post{} = post} <- Projects.create_post(post_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", post_path(conn, :show, post))
      |> render("show.json", post: post)
    end
  end

  def show(conn, %{"id" => id}) do
    post = Projects.get_post!(id)
    render(conn, "show.json", post: post)
  end

  def update(conn, %{"id" => id, "post" => post_params}) do
    post = Projects.get_post!(id)

    with {:ok, %Post{} = post} <- Projects.update_post(post, post_params) do
      render(conn, "show.json", post: post)
    end
  end

  def delete(conn, %{"id" => id}) do
    post = Projects.get_post!(id)

    with {:ok, %Post{}} <- Projects.delete_post(post) do
      send_resp(conn, :no_content, "")
    end
  end
end
