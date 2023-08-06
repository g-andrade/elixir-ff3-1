defmodule FF3_1.MixProject do
  use Mix.Project

  def project do
    [
      app: :ff3_1,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_options:
        if Mix.env() in [:dev, :test] do
          [{:warnings_as_errors, true}]
        else
          []
        end,
      docs: [
        main: "FF3_1",
        extras: [
          "CHANGELOG.md",
          "LICENSE"
        ]
      ],
      test_coverage: [
        summary: [
          # Threshold adjusted over time as :cover doesn't account for macros
          # (e.g. defstruct)
          threshold: 85.71
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
      {:benchee, "~> 1.0", only: :dev, runtime: false},
      {:dialyxir, "~> 1.3", only: :dev, runtime: false},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:recon, "~> 2.3", only: :dev, runtime: false},
      {:styler, "~> 0.8", only: [:dev, :test], runtime: false}
    ]
  end
end
