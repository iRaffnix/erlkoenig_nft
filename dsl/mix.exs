defmodule ErlkoenigNft.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_nft_dsl,
      version: "0.4.0",
      elixir: "~> 1.18",
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    []
  end
end
