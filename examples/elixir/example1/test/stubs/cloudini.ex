defmodule CloudiniStub do
  @moduledoc false

  require Logger

  def upload_image(_, path, opts \\ []) do
    public_id = Keyword.get(opts, :public_id, "example_pic")

    Logger.warn("[CLOUDINI-STUB] Uploading file from #{path}")

    {:ok,
     %{
       "secure_url" => "https://res.cloudinary.com/demo/image/upload/lady.jpg",
       "height" => 1000,
       "width" => 667,
       "public_id" => public_id
     }}
  end
end
