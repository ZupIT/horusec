defmodule BuiltWithElixirWeb.Router do
  use BuiltWithElixirWeb, :router

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_flash)
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
  end

  pipeline :api do
    plug(:accepts, ["json"])
  end

  scope "/", BuiltWithElixirWeb do
    # Use the default browser stack
    pipe_through(:browser)

    get("/", PageController, :index)
  end

  scope "/api", BuiltWithElixirWeb do
    pipe_through(:api)

    resources("/projects", PostController, only: [:index, :show, :create])
  end
end
