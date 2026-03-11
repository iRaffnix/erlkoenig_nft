defmodule ErlkoenigNft.CLI do
  @moduledoc """
  Command-line interface for erlkoenig_nft DSL.

  Usage:
    erlkoenig show <file.exs>           Show firewall config as nft-style ruleset
    erlkoenig compile <file.exs> [-o path]  Compile DSL to .term file
    erlkoenig validate <file.exs>       Validate DSL config
    erlkoenig inspect <file.exs>        Show raw Erlang term structure
    erlkoenig diff <a.exs> <b.exs>      Compare two firewall configs
    erlkoenig list [dir]                List available examples
  """

  alias ErlkoenigNft.CLI.Formatter

  def main(args) do
    case args do
      ["show" | rest] -> cmd_show(rest)
      ["compile" | rest] -> cmd_compile(rest)
      ["validate" | rest] -> cmd_validate(rest)
      ["inspect" | rest] -> cmd_inspect(rest)
      ["diff", a, b] -> cmd_diff(a, b)
      ["list" | rest] -> cmd_list(rest)
      ["help" | _] -> cmd_help()
      ["--help" | _] -> cmd_help()
      ["-h" | _] -> cmd_help()
      [] -> cmd_help()
      _ -> error("Unknown command: #{Enum.join(args, " ")}\nRun 'erlkoenig help' for usage.")
    end
  end

  # --- Commands ---

  defp cmd_show(args) do
    {file, _opts} = parse_file_args(args)
    modules = load_file!(file)

    for {type, mod} <- modules do
      case type do
        :firewall -> Formatter.render_firewall(mod.config(), mod)
        :guard -> Formatter.render_guard(mod.guard_config(), mod)
        :watch ->
          for watch <- mod.watches() do
            Formatter.render_watch(watch, mod)
          end
      end
    end
  end

  defp cmd_compile(args) do
    {file, opts} = parse_file_args(args)
    modules = load_file!(file)
    out_dir = Keyword.get(opts, :output, Path.rootname(file))

    firewall_mods = for {:firewall, mod} <- modules, do: mod
    guard_mods = for {:guard, mod} <- modules, do: mod
    watch_mods = for {:watch, mod} <- modules, do: mod

    for mod <- firewall_mods do
      config = mod.config()
      default_out = "#{out_dir}.term"
      out_path = Keyword.get(opts, :output, default_out)

      term = build_full_term(config, guard_mods, watch_mods)
      formatted = :io_lib.format(~c"~tp.~n", [term])
      File.write!(out_path, formatted)
      success("Compiled -> #{out_path}")
      info("  chains: #{length(config[:chains] || [])}")
      info("  counters: #{length(config[:counters] || [])}")
      info("  sets: #{length(config[:sets] || [])}")
    end
  end

  defp cmd_validate(args) do
    {file, _opts} = parse_file_args(args)
    modules = load_file!(file)

    errors = List.flatten(for {type, mod} <- modules, do: validate_module(type, mod))

    if errors == [] do
      success("#{Path.basename(file)} — valid")
      info("  Modules: #{length(modules)}")

      for {type, mod} <- modules do
        info("  #{type}: #{inspect(mod)}")
      end
    else
      error("#{Path.basename(file)} — #{length(errors)} error(s):")
      for e <- errors, do: error("  #{e}")
      System.halt(1)
    end
  end

  defp cmd_inspect(args) do
    {file, _opts} = parse_file_args(args)
    modules = load_file!(file)

    for {type, mod} <- modules do
      config =
        case type do
          :firewall -> mod.config()
          :guard -> mod.guard_config()
          :watch -> mod.watches()
        end

      header("#{type} — #{inspect(mod)}")
      IO.puts(inspect(config, pretty: true, width: 80, limit: :infinity))
      IO.puts("")
    end
  end

  defp cmd_diff(file_a, file_b) do
    mods_a = load_file!(file_a)
    mods_b = load_file!(file_b)

    fw_a = for({:firewall, m} <- mods_a, do: m.config()) |> List.first()
    fw_b = for({:firewall, m} <- mods_b, do: m.config()) |> List.first()

    if fw_a == nil or fw_b == nil do
      error("Both files must contain a Firewall module")
      System.halt(1)
    end

    Formatter.render_diff(fw_a, fw_b, Path.basename(file_a), Path.basename(file_b))
  end

  defp cmd_list(args) do
    dir = List.first(args) || find_examples_dir()

    if dir == nil or not File.dir?(dir) do
      error("Examples directory not found. Usage: erlkoenig list [directory]")
      System.halt(1)
    end

    files =
      dir
      |> Path.join("*.exs")
      |> Path.wildcard()
      |> Enum.sort()

    if files == [] do
      info("No .exs files found in #{dir}")
    else
      header("Examples in #{dir}")

      for file <- files do
        name = Path.basename(file)
        desc = extract_description(file)
        IO.puts("  #{color(:cyan, name)}")
        if desc, do: IO.puts("    #{desc}")
      end

      IO.puts("")
      info("Run: erlkoenig show #{Path.join(dir, "<file>")}")
    end
  end

  defp cmd_help do
    IO.puts("""
    #{color(:bold, "erlkoenig")} — nf_tables firewall DSL compiler

    #{color(:bold, "USAGE")}
      erlkoenig <command> [options]

    #{color(:bold, "COMMANDS")}
      #{color(:cyan, "show")} <file.exs>              Render firewall as nft-style ruleset
      #{color(:cyan, "compile")} <file.exs> [-o path]  Compile DSL to .term config file
      #{color(:cyan, "validate")} <file.exs>           Validate DSL config for errors
      #{color(:cyan, "inspect")} <file.exs>            Show raw Erlang term structure
      #{color(:cyan, "diff")} <a.exs> <b.exs>          Compare two firewall configs
      #{color(:cyan, "list")} [dir]                   List available example configs

    #{color(:bold, "EXAMPLES")}
      erlkoenig show examples/01_hardened_webserver.exs
      erlkoenig compile examples/01_hardened_webserver.exs -o /etc/erlkoenig_nft/firewall.term
      erlkoenig validate examples/03_mail_server.exs
      erlkoenig diff examples/01_hardened_webserver.exs examples/10_dev_server.exs
      erlkoenig list examples/

    #{color(:bold, "DOCUMENTATION")}
      https://github.com/iRaffnix/erlkoenig_nft
    """)
  end

  # --- Helpers ---

  defp load_file!(path) do
    unless File.exists?(path) do
      error("File not found: #{path}")
      System.halt(1)
    end

    try do
      results = Code.require_file(path)

      results
      |> Enum.map(fn {mod, _bytecode} -> classify_module(mod) end)
      |> Enum.reject(&is_nil/1)
      |> Enum.sort_by(fn {type, _} ->
        case type do
          :firewall -> 0
          :guard -> 1
          :watch -> 2
        end
      end)
    rescue
      e ->
        error("Failed to compile #{path}:")
        error("  #{Exception.message(e)}")
        System.halt(1)
    end
  end

  defp classify_module(mod) do
    name = Atom.to_string(mod)

    cond do
      String.starts_with?(name, "Elixir.Firewall.") and function_exported?(mod, :config, 0) ->
        {:firewall, mod}

      String.starts_with?(name, "Elixir.Guard.") and function_exported?(mod, :guard_config, 0) ->
        {:guard, mod}

      String.starts_with?(name, "Elixir.Watch.") and function_exported?(mod, :watches, 0) ->
        {:watch, mod}

      true ->
        nil
    end
  end

  defp validate_module(:firewall, mod) do
    config = mod.config()
    errors = []

    errors =
      if not is_list(config[:chains]) or config[:chains] == [],
        do: ["#{inspect(mod)}: must have at least one chain" | errors],
        else: errors

    for chain <- config[:chains] || [], reduce: errors do
      acc ->
        cond do
          not is_binary(chain[:name]) and not is_atom(chain[:name]) ->
            ["#{inspect(mod)}: chain missing name" | acc]

          chain[:hook] not in [:prerouting, :input, :forward, :output, :postrouting] ->
            ["#{inspect(mod)}: chain '#{chain[:name]}' invalid hook: #{inspect(chain[:hook])}" | acc]

          chain[:policy] not in [:accept, :drop] ->
            ["#{inspect(mod)}: chain '#{chain[:name]}' invalid policy: #{inspect(chain[:policy])}" | acc]

          true ->
            acc
        end
    end
  end

  defp validate_module(:guard, mod) do
    config = mod.guard_config()

    cond do
      config == nil -> ["#{inspect(mod)}: guard_config returned nil"]
      not is_integer(config[:ban_duration]) -> ["#{inspect(mod)}: missing ban_duration"]
      not is_list(config[:whitelist]) -> ["#{inspect(mod)}: missing whitelist"]
      true -> []
    end
  end

  defp validate_module(:watch, mod) do
    watches = mod.watches()

    cond do
      not is_list(watches) -> ["#{inspect(mod)}: watches/0 must return a list"]
      watches == [] -> ["#{inspect(mod)}: no watches defined"]
      true ->
        for w <- watches, not is_integer(w[:interval]), do: "#{inspect(mod)}: watch missing interval"
    end
  end

  defp build_full_term(fw_config, guard_mods, watch_mods) do
    term = fw_config

    term =
      case guard_mods do
        [gmod | _] -> Map.put(term, :ct_guard, gmod.guard_config())
        _ -> term
      end

    term =
      case watch_mods do
        [wmod | _] ->
          case wmod.watches() do
            [watch | _] -> Map.put(term, :watch, watch)
            _ -> term
          end

        _ ->
          term
      end

    term
  end

  defp parse_file_args(args) do
    {opts, files} = parse_opts(args, [], [])
    file = List.first(files)

    if file == nil do
      error("Missing file argument. Run 'erlkoenig help' for usage.")
      System.halt(1)
    end

    {file, opts}
  end

  defp parse_opts(["-o", path | rest], opts, files), do: parse_opts(rest, [{:output, path} | opts], files)
  defp parse_opts(["--output", path | rest], opts, files), do: parse_opts(rest, [{:output, path} | opts], files)
  defp parse_opts(["-" <> _ = unknown | rest], opts, files) do
    IO.puts(:stderr, "Warning: unknown option #{unknown}")
    parse_opts(rest, opts, files)
  end
  defp parse_opts([file | rest], opts, files), do: parse_opts(rest, opts, files ++ [file])
  defp parse_opts([], opts, files), do: {opts, files}

  defp find_examples_dir do
    candidates = [
      "examples",
      "../examples",
      Path.join(:code.priv_dir(:erlkoenig_nft_dsl) |> to_string(), "../examples")
    ]

    Enum.find(candidates, &File.dir?/1)
  end

  defp extract_description(file) do
    file
    |> File.stream!()
    |> Enum.take(5)
    |> Enum.find_value(fn line ->
      trimmed = String.trim(line)

      if String.starts_with?(trimmed, "#") and not String.starts_with?(trimmed, "#!") and
           not String.match?(trimmed, ~r/^#\s*\d+\./) do
        trimmed |> String.trim_leading("#") |> String.trim()
      end
    end)
  end

  # --- Output helpers ---

  defp header(text) do
    IO.puts("\n#{color(:bold, "── #{text} ──")}")
  end

  defp success(text), do: IO.puts(color(:green, "✓ #{text}"))
  defp info(text), do: IO.puts(color(:dim, text))
  defp error(text), do: IO.puts(:stderr, color(:red, "✗ #{text}"))

  @colors %{
    red: "\e[31m",
    green: "\e[32m",
    yellow: "\e[33m",
    cyan: "\e[36m",
    bold: "\e[1m",
    dim: "\e[2m",
    reset: "\e[0m"
  }

  def color(name, text) do
    if IO.ANSI.enabled?() do
      "#{@colors[name]}#{text}#{@colors[:reset]}"
    else
      text
    end
  end
end
