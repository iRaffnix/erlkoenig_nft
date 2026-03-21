defmodule ErlkoenigNft.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_nft_dsl,
      version: "0.7.0",
      elixir: "~> 1.18",
      deps: deps(),
      escript: escript()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp escript do
    [
      main_module: ErlkoenigNft.CLI,
      name: "erlkoenig",
      embed_elixir: true
    ]
  end

  defp deps do
    []
  end
end
