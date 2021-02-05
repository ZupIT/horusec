defmodule BuiltWithElixirWeb.PostControllerTest do
  use BuiltWithElixirWeb.ConnCase

  alias BuiltWithElixir.Projects

  @create_attrs %{
    "author" => "some author",
    "description" => "some description",
    "github_url" => "some github_url",
    "title" => "some title",
    "type" => "some type",
    "website_url" => "some website_url",
    "image_url" => "some image_url"
  }

  @form_create_attrs %{
    "author" => "some author",
    "description" => "some description",
    "github_url" => "some github_url",
    "title" => "some title",
    "type" => "some type",
    "website_url" => "some website_url",
    "image_url" => "some image_url",
    "author_email" => "edgar@me.com"
  }

  @form_create_attrs_with_file %{
    "author" => "some author",
    "description" => "some description",
    "github_url" => "some github_url",
    "title" => "some title",
    "type" => "some type",
    "website_url" => "some website_url",
    "image_file" => %Plug.Upload{
      content_type: "image/png",
      path: "test/assets/no-text.png",
      filename: "no-text.png"
    },
    "author_email" => "edgar@me.com"
  }

  def fixture(:post) do
    {:ok, post} =
      %{"published" => true}
      |> Enum.into(@create_attrs)
      |> Projects.create_post()

    post
  end

  def fixture(:multiple_posts) do
    1..15
    |> Enum.to_list()
    |> Enum.map(fn _ ->
      %{"published" => true}
      |> Enum.into(@create_attrs)
      |> Projects.create_post()
    end)
  end

  setup %{conn: conn} do
    {:ok, conn: put_req_header(conn, "accept", "application/json")}
  end

  describe "index" do
    setup [:create_post]

    test "lists all posts", %{conn: conn} do
      conn = get(conn, post_path(conn, :index))
      response = hd(json_response(conn, 200)["data"])

      assert response ===
               Enum.into(
                 %{"id" => response["id"], "inserted_at" => response["inserted_at"]},
                 @create_attrs
               )
    end
  end

  describe "index with limit and offet" do
    setup [:create_multilple_posts]

    test "list posts with offset", %{conn: conn} do
      conn = get(conn, post_path(conn, :index), offset: 10)
      response = json_response(conn, 200)["data"]

      assert Enum.count(response) == 5
    end

    test "list posts with limit", %{conn: conn} do
      conn = get(conn, post_path(conn, :index), limit: 3)
      response = json_response(conn, 200)["data"]

      assert Enum.count(response) == 3
    end

    test "list posts with offset and limit", %{conn: conn} do
      conn = get(conn, post_path(conn, :index), offset: 1, limit: 20)
      response = json_response(conn, 200)["data"]

      assert Enum.count(response) == 14
    end
  end

  describe "show" do
    setup [:create_post]

    test "single existing post", %{conn: conn, post: post} do
      conn = get(conn, post_path(conn, :show, post.id))
      response = json_response(conn, 200)["data"]

      assert response ===
               Enum.into(
                 %{"id" => response["id"], "inserted_at" => response["inserted_at"]},
                 @create_attrs
               )
    end
  end

  describe "create" do
    test "a single post", %{conn: conn} do
      conn = post(conn, post_path(conn, :create, @form_create_attrs))
      response = json_response(conn, 201)["data"]

      # add the id and inserted_at 
      assert response ===
               %{"id" => response["id"], "inserted_at" => response["inserted_at"]}
               |> Enum.into(@form_create_attrs)
               # remove the author_email since it's not in the response
               |> Map.delete("author_email")
    end

    test "a single post with an image file upload", %{conn: conn} do
      conn = post(conn, post_path(conn, :create), @form_create_attrs_with_file)
      response = json_response(conn, 201)["data"]

      assert response ===
               %{
                 "id" => response["id"],
                 "inserted_at" => response["inserted_at"],
                 "image_url" => response["image_url"]
               }
               |> Enum.into(@form_create_attrs_with_file)
               # remove the author_email since it's not in the response
               |> Map.delete("author_email")
               |> Map.delete("image_file")
    end
  end

  defp create_post(_) do
    post = fixture(:post)
    {:ok, post: post}
  end

  defp create_multilple_posts(_) do
    posts = fixture(:multiple_posts)
    {:ok, posts: posts}
  end
end
