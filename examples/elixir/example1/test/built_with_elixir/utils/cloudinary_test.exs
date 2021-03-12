defmodule BuiltWithElixir.Utils.CloudinaryTest do
  use ExUnit.Case

  alias BuiltWithElixir.Utils.Cloudinary

  describe "generate_image_url" do
    test "generating a url successfully" do
      base = Application.get_env(:built_with_elixir, :cloudinary_base_url)
      public_id = "cool_image"
      expected_url = "#{base}/image/upload/t_elixir_project_preview/#{public_id}"

      assert Cloudinary.generate_image_url(public_id) == expected_url
    end

    test "generating a url successfully with custom transformation" do
      base = Application.get_env(:built_with_elixir, :cloudinary_base_url)
      transformation = "cool_transformation"
      public_id = "cool_image"
      expected_url = "#{base}/image/upload/#{transformation}/#{public_id}"

      assert Cloudinary.generate_image_url(public_id, transformation) == expected_url
    end
  end
end
