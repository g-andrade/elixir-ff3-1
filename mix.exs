defmodule ExFPE.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/g-andrade/ex_fpe"

  def project do
    [
      app: :ex_fpe,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      source_url: @source_url,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      elixirc_options: elixirc_options(Mix.env()),
      docs: [
        main: "readme",
        source_ref: "v#{@version}",
        extras: [
          "README.md": [title: "ExFPE"],
          "CHANGELOG.md": [],
          LICENSE: []
        ]
      ],
      test_coverage: [
        summary: [
          threshold: 93
        ]
      ]
    ]
  end

  defp description do
    "Format-preserving encryption (FF1 and FF3-1)."
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: ["Guilherme Andrade"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE .formatter.exs)
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

  defp deps do
    List.flatten([
      {:benchee, "~> 1.0", only: :dev, runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:recon, "~> 2.5", only: [:dev, :test], runtime: false},
      maybe_credo_dep(),
      maybe_dialyxir_dep(),
      maybe_styler_dep()
    ])
  end

  defp maybe_credo_dep do
    if elixir_vsn_match?("~> 1.12") do
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    else
      []
    end
  end

  defp maybe_dialyxir_dep do
    if elixir_vsn_match?("~> 1.12") do
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    else
      []
    end
  end

  defp maybe_styler_dep do
    if elixir_vsn_match?("~> 1.14") do
      {:styler, "~> 1.1", only: [:dev, :test], runtime: false}
    else
      []
    end
  end

  defp elixirc_paths(env) do
    if env == :test do
      ["lib", "test/helper"]
    else
      ["lib"]
    end
  end

  defp elixirc_options(env) do
    if env in [:dev, :test] do
      [warnings_as_errors: true]
    else
      []
    end
  end

  defp elixir_vsn_match?(requirement), do: Version.match?(System.version(), requirement)
end
