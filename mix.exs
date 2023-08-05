defmodule FF3_1.MixProject do
  use Mix.Project

  def project do
    [
      app: :ff3_1,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: [
          "CHANGELOG.md",
          "LICENSE",
          "README.md"
        ]
      ],
      test_coverage: [
        summary: [
          # FIXME
          threshold: 0
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [
        :crypto
      ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:dialyxir, "~> 1.3", only: :dev, runtime: false},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:recon, "~> 2.3", only: :dev, runtime: false},
      {:styler, "~> 0.8", only: [:dev, :test], runtime: false}
    ]
  end
end
