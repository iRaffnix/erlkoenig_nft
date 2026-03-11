defmodule ErlkoenigNft.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_nft_dsl,
      version: "0.4.0",
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
      name: "erlkoenig"
    ]
  end

  defp deps do
    []
  end
end
