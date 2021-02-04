defmodule BuiltWithElixir.Utils.Cloudinary do
  @moduledoc false

  @base Application.get_env(:built_with_elixir, :cloudinary_base_url)

  def generate_image_url(public_id, transformation \\ "t_elixir_project_preview") do
    "#{@base}/image/upload/#{transformation}/#{public_id}"
  end
end
