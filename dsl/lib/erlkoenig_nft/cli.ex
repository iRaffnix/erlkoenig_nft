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

    erlkoenig status                    Show daemon status
    erlkoenig ban <ip>                  Ban an IP address
    erlkoenig unban <ip>                Unban an IP address
    erlkoenig reload                    Reload config from disk
    erlkoenig apply <file.exs>          Compile and apply to running daemon
    erlkoenig counters                  Show live counter rates
    erlkoenig guard [stats|banned]      Show ct_guard info

    erlkoenig version                   Show version
    erlkoenig completions [bash|zsh|fish]  Print shell completions
  """

  @version Mix.Project.config()[:version]

  alias ErlkoenigNft.CLI.{Formatter, Daemon}

  def main(args) do
    case args do
      # Daemon commands (talk to running daemon via socket)
      ["status" | _] -> cmd_daemon("status")
      ["ban", ip] -> cmd_daemon("ban", %{"ip" => ip})
      ["unban", ip] -> cmd_daemon("unban", %{"ip" => ip})
      ["reload" | _] -> cmd_daemon("reload")
      ["apply" | rest] -> cmd_apply(rest)
      ["counters" | _] -> cmd_daemon("counters")
      ["guard", "stats"] -> cmd_daemon("guard_stats")
      ["guard", "banned"] -> cmd_daemon("guard_banned")
      ["guard" | _] -> error("Usage: erlkoenig guard [stats|banned]")
      # Local commands (no daemon needed)
      ["show" | rest] -> cmd_show(rest)
      ["compile" | rest] -> cmd_compile(rest)
      ["validate" | rest] -> cmd_validate(rest)
      ["inspect" | rest] -> cmd_inspect(rest)
      ["diff", a, b] -> cmd_diff(a, b)
      ["list" | rest] -> cmd_list(rest)
      ["completions", shell] -> cmd_completions(shell)
      ["completions" | _] -> cmd_completions("bash")
      ["version" | _] -> cmd_version()
      ["--version" | _] -> cmd_version()
      ["-v" | _] -> cmd_version()
      ["help" | _] -> cmd_help()
      ["--help" | _] -> cmd_help()
      ["-h" | _] -> cmd_help()
      [] -> cmd_help()
      _ -> error("Unknown command: #{Enum.join(args, " ")}\nRun 'erlkoenig help' for usage.")
    end
  end

  # --- Daemon commands ---

  defp cmd_daemon(cmd, opts \\ %{}) do
    case Daemon.call(cmd, opts) do
      {:ok, %{"ok" => true, "data" => data}} ->
        render_daemon_response(cmd, data)

      {:ok, %{"ok" => true}} ->
        success("#{cmd}: ok")

      {:ok, %{"ok" => false, "error" => err}} ->
        error(err)
        System.halt(1)

      {:error, :not_running} ->
        error("Cannot connect to daemon. Is erlkoenig_nft running?")
        error("  Check: systemctl status erlkoenig_nft")
        System.halt(1)

      {:error, :permission_denied} ->
        error("Permission denied. Add your user to the erlkoenig group:")
        error("  sudo usermod -aG erlkoenig $(whoami)")
        System.halt(1)

      {:error, reason} ->
        error("Connection error: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp cmd_apply(args) do
    {file, _opts} = parse_file_args(args)
    modules = load_file!(file)

    fw_mods = for {:firewall, m} <- modules, do: m
    guard_mods = for {:guard, m} <- modules, do: m
    watch_mods = for {:watch, m} <- modules, do: m

    if fw_mods == [] do
      error("No Firewall module found in #{file}")
      System.halt(1)
    end

    config = hd(fw_mods).config()
    term = build_full_term(config, guard_mods, watch_mods)
    term_string = :io_lib.format(~c"~tp.~n", [term]) |> IO.iodata_to_binary()

    info("Compiled #{Path.basename(file)}")

    case Daemon.call("apply", %{"term" => term_string}) do
      {:ok, %{"ok" => true}} ->
        success("Applied to running daemon")

      {:ok, %{"ok" => false, "error" => err}} ->
        error("Apply failed: #{err}")
        System.halt(1)

      {:error, :not_running} ->
        error("Cannot connect to daemon. Is erlkoenig_nft running?")
        System.halt(1)

      {:error, reason} ->
        error("Connection error: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp render_daemon_response("status", data) do
    header("erlkoenig_nft")
    if t = data["table"], do: IO.puts("  table:    #{t}")

    # status has config embedded — pull chains from config if present
    config = data["config"] || data

    case config["chains"] do
      chains when is_list(chains) ->
        IO.puts("  chains:   #{length(chains)}")

        for c <- chains do
          rules = c["rules"] || []
          IO.puts("    #{color(:cyan, c["name"])} #{c["hook"]} #{c["policy"]} (#{length(rules)} rules)")
        end

      _ ->
        :ok
    end

    case config["sets"] do
      sets when is_list(sets) -> IO.puts("  sets:     #{length(sets)}")
      _ -> :ok
    end

    case data["counters"] do
      n when is_integer(n) -> IO.puts("  counters: #{n}")
      c when is_list(c) -> IO.puts("  counters: #{length(c)}")
      _ -> :ok
    end

    IO.puts("  running:  #{data["running"] || false}")
  end

  defp render_daemon_response("counters", data) do
    header("counters")

    for {name, val} <- data do
      cond do
        is_map(val) ->
          pps = val["pps"] || val["rate"] || 0
          IO.puts("  #{String.pad_trailing(name, 16)} #{pps} pps")

        true ->
          IO.puts("  #{String.pad_trailing(name, 16)} #{inspect(val)}")
      end
    end
  end

  defp render_daemon_response("guard_stats", data) do
    header("ct_guard stats")

    for {key, val} <- data do
      IO.puts("  #{String.pad_trailing(key, 20)} #{inspect(val)}")
    end
  end

  defp render_daemon_response("guard_banned", data) do
    header("banned IPs")

    ips = cond do
      is_list(data) -> data
      is_map(data) and Map.has_key?(data, "ips") -> data["ips"]
      true -> [data]
    end

    if ips == [] do
      info("  (none)")
    else
      for ip <- ips, do: IO.puts("  #{inspect(ip)}")
    end
  end

  defp render_daemon_response(_cmd, data) do
    IO.puts(inspect(data, pretty: true, width: 80))
  end

  # --- Local commands ---

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

  defp cmd_version do
    IO.puts("erlkoenig #{@version}")
  end

  defp cmd_completions(shell) do
    case shell do
      "bash" -> IO.puts(completions_bash())
      "zsh" -> IO.puts(completions_zsh())
      "fish" -> IO.puts(completions_fish())
      _ ->
        error("Unknown shell: #{shell}. Supported: bash, zsh, fish")
        System.halt(1)
    end
  end

  defp cmd_help do
    IO.puts("""
    #{color(:bold, "erlkoenig")} #{@version} — nf_tables firewall DSL compiler & daemon CLI

    #{color(:bold, "USAGE")}
      erlkoenig <command> [options]

    #{color(:bold, "DAEMON COMMANDS")} (talk to running erlkoenig_nft)
      #{color(:cyan, "status")}                       Show daemon status
      #{color(:cyan, "ban")} <ip>                      Ban an IP address
      #{color(:cyan, "unban")} <ip>                    Unban an IP address
      #{color(:cyan, "reload")}                       Reload config from disk
      #{color(:cyan, "apply")} <file.exs>              Compile and apply to running daemon
      #{color(:cyan, "counters")}                     Show live counter rates
      #{color(:cyan, "guard")} stats                   Show detection statistics
      #{color(:cyan, "guard")} banned                  Show banned IPs

    #{color(:bold, "LOCAL COMMANDS")} (no daemon needed)
      #{color(:cyan, "show")} <file.exs>               Render firewall as nft-style ruleset
      #{color(:cyan, "compile")} <file.exs> [-o path]   Compile DSL to .term config file
      #{color(:cyan, "validate")} <file.exs>            Validate DSL config for errors
      #{color(:cyan, "inspect")} <file.exs>             Show raw Erlang term structure
      #{color(:cyan, "diff")} <a.exs> <b.exs>           Compare two firewall configs
      #{color(:cyan, "list")} [dir]                    List available example configs
      #{color(:cyan, "version")}                       Show version
      #{color(:cyan, "completions")} [bash|zsh|fish]    Print shell completions

    #{color(:bold, "EXAMPLES")}
      erlkoenig show examples/hardened_webserver.exs
      erlkoenig compile examples/hardened_webserver.exs -o /etc/erlkoenig_nft/firewall.term
      erlkoenig apply examples/hardened_webserver.exs
      erlkoenig ban 10.0.0.5
      erlkoenig counters
      erlkoenig guard banned

    #{color(:bold, "SHELL COMPLETIONS")}
      erlkoenig completions bash >> ~/.bashrc
      erlkoenig completions zsh  >> ~/.zshrc
      erlkoenig completions fish > ~/.config/fish/completions/erlkoenig.fish

    #{color(:bold, "ENVIRONMENT")}
      ERLKOENIG_SOCKET   Override daemon socket path (default: /var/run/erlkoenig.sock)

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

  # --- Shell completions ---

  @commands ~w(status ban unban reload apply counters guard show compile validate inspect diff list version completions help)
  @guard_subcommands ~w(stats banned)
  @completions_shells ~w(bash zsh fish)

  defp completions_bash do
    """
    _erlkoenig() {
        local cur prev commands
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        commands="#{Enum.join(@commands, " ")}"

        case "$prev" in
            erlkoenig)
                COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
                return 0
                ;;
            guard)
                COMPREPLY=( $(compgen -W "#{Enum.join(@guard_subcommands, " ")}" -- "$cur") )
                return 0
                ;;
            completions)
                COMPREPLY=( $(compgen -W "#{Enum.join(@completions_shells, " ")}" -- "$cur") )
                return 0
                ;;
            show|compile|validate|inspect|apply)
                COMPREPLY=( $(compgen -f -X '!*.exs' -- "$cur") $(compgen -d -- "$cur") )
                return 0
                ;;
            diff)
                COMPREPLY=( $(compgen -f -X '!*.exs' -- "$cur") $(compgen -d -- "$cur") )
                return 0
                ;;
            -o|--output)
                COMPREPLY=( $(compgen -f -- "$cur") $(compgen -d -- "$cur") )
                return 0
                ;;
        esac

        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    }
    complete -F _erlkoenig erlkoenig
    """
  end

  defp completions_zsh do
    """
    #compdef erlkoenig

    _erlkoenig() {
        local -a commands
        commands=(
            'status:Show daemon status'
            'ban:Ban an IP address'
            'unban:Unban an IP address'
            'reload:Reload config from disk'
            'apply:Compile and apply to running daemon'
            'counters:Show live counter rates'
            'guard:Show threat detection info'
            'show:Render firewall as nft-style ruleset'
            'compile:Compile DSL to .term config file'
            'validate:Validate DSL config for errors'
            'inspect:Show raw Erlang term structure'
            'diff:Compare two firewall configs'
            'list:List available example configs'
            'version:Show version'
            'completions:Print shell completions'
            'help:Show usage'
        )

        if (( CURRENT == 2 )); then
            _describe 'command' commands
        else
            case "${words[2]}" in
                guard)
                    local -a guard_sub
                    guard_sub=('stats:Show detection statistics' 'banned:Show banned IPs')
                    _describe 'subcommand' guard_sub
                    ;;
                completions)
                    local -a shells
                    shells=(bash zsh fish)
                    _describe 'shell' shells
                    ;;
                show|compile|validate|inspect|apply)
                    _files -g '*.exs'
                    ;;
                diff)
                    _files -g '*.exs'
                    ;;
            esac
        fi
    }

    _erlkoenig "$@"
    """
  end

  defp completions_fish do
    commands = [
      {"status", "Show daemon status"},
      {"ban", "Ban an IP address"},
      {"unban", "Unban an IP address"},
      {"reload", "Reload config from disk"},
      {"apply", "Compile and apply to running daemon"},
      {"counters", "Show live counter rates"},
      {"guard", "Show threat detection info"},
      {"show", "Render firewall as nft-style ruleset"},
      {"compile", "Compile DSL to .term config file"},
      {"validate", "Validate DSL config for errors"},
      {"inspect", "Show raw Erlang term structure"},
      {"diff", "Compare two firewall configs"},
      {"list", "List available example configs"},
      {"version", "Show version"},
      {"completions", "Print shell completions"},
      {"help", "Show usage"}
    ]

    main =
      for {cmd, desc} <- commands do
        "complete -c erlkoenig -n __fish_use_subcommand -a #{cmd} -d '#{desc}'"
      end

    guard = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from guard' -a 'stats banned'
    """

    completions = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
    """

    file_cmds = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from show compile validate inspect apply diff' -F -r
    """

    Enum.join(main, "\n") <> "\n" <> guard <> completions <> file_cmds
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
