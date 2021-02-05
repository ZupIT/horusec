defmodule BuiltWithElixirWeb.PageController do
  use BuiltWithElixirWeb, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
