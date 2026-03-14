defmodule ErlkoenigNft.CLI do
  @moduledoc """
  Command-line interface for erlkoenig_nft DSL.

  Usage:
    erlkoenig show <file.exs>           Show firewall config as nft-style ruleset
    erlkoenig compile <file.exs> [-o path]  Compile DSL to .term file
    erlkoenig validate <file.exs>       Validate DSL config
    erlkoenig inspect <file.exs>        Show raw Erlang term structure
    erlkoenig diff <a.exs> <b.exs>      Compare two firewall configs
    erlkoenig examples [dir]            List available examples

    erlkoenig status                    Show daemon status
    erlkoenig ban <ip>                  Ban an IP address
    erlkoenig unban <ip>                Unban an IP address
    erlkoenig reload                    Reload config from disk
    erlkoenig apply <file.exs>          Compile and apply to running daemon
    erlkoenig counters                  Show live counter rates
    erlkoenig guard [stats|banned]      Show ct_guard info

    erlkoenig list ruleset              Show live ruleset
    erlkoenig list chains               List chains
    erlkoenig list sets                 List sets
    erlkoenig list set <name>           Show set elements (live kernel)
    erlkoenig list counters             List counters with sparklines
    erlkoenig add element <set> <val>   Add element to a set
    erlkoenig delete element <set> <val> Delete element from a set
    erlkoenig monitor                   Live-stream counter rates
    erlkoenig diff live                 Compare kernel vs config
    erlkoenig top [n]                   Top source IPs by connections
    erlkoenig log [n]                   Show audit log

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
      ["monitor" | _] -> cmd_monitor()
      ["diff", "live" | _] -> cmd_daemon("diff_live")
      ["top", n] -> cmd_daemon("top", %{"n" => String.to_integer(n)})
      ["top" | _] -> cmd_daemon("top")
      ["log", n] -> cmd_daemon("audit_log", %{"n" => String.to_integer(n)})
      ["log" | _] -> cmd_daemon("audit_log")
      # nft-style list commands (daemon)
      ["list", "ruleset" | _] -> cmd_daemon("list_ruleset")
      ["list", "chains" | _] -> cmd_daemon("list_chains")
      ["list", "sets" | _] -> cmd_daemon("list_sets")
      ["list", "set", name] -> cmd_daemon("list_set", %{"name" => name})
      ["list", "set" | _] -> error("Usage: erlkoenig list set <name>")
      ["list", "counters" | _] -> cmd_daemon("list_counters")
      ["list" | _] -> error("Usage: erlkoenig list [ruleset|chains|sets|set <name>|counters]")
      # nft-style element commands (daemon)
      ["add", "element", set | values] when values != [] -> cmd_add_elements(set, values)
      ["add", "element" | _] -> error("Usage: erlkoenig add element <set> <value> [<value>...]")
      ["delete", "element", set | values] when values != [] -> cmd_delete_elements(set, values)
      ["delete", "element" | _] -> error("Usage: erlkoenig delete element <set> <value> [<value>...]")
      # Local commands (no daemon needed)
      ["show" | rest] -> cmd_show(rest)
      ["compile" | rest] -> cmd_compile(rest)
      ["validate" | rest] -> cmd_validate(rest)
      ["inspect" | rest] -> cmd_inspect(rest)
      ["diff", a, b] -> cmd_diff(a, b)
      ["examples" | rest] -> cmd_examples(rest)
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

  defp render_daemon_response("list_ruleset", data) do
    header("ruleset")
    config = data["config"] || data

    case config["chains"] do
      chains when is_list(chains) ->
        for c <- chains do
          rules = c["rules"] || []
          IO.puts("  chain #{color(:cyan, c["name"])} {")
          IO.puts("    type #{c["type"] || "filter"} hook #{c["hook"]} priority #{c["priority"] || 0}; policy #{c["policy"] || "accept"};")
          IO.puts("    # #{length(rules)} rules")
          IO.puts("  }")
        end
      _ -> :ok
    end

    case config["sets"] do
      sets when is_list(sets) ->
        for s <- sets do
          IO.puts("  set #{color(:cyan, s["name"] || List.first(s))} { type #{s["type"] || Enum.at(s, 1)} }")
        end
      _ -> :ok
    end
  end

  defp render_daemon_response("list_chains", data) do
    header("chains")

    for c <- data do
      IO.puts("  #{color(:cyan, c["name"])} #{c["hook"]} priority #{c["priority"]} policy #{c["policy"]} (#{c["rules"]} rules)")
    end
  end

  defp render_daemon_response("list_sets", data) do
    header("sets")

    for s <- data do
      flags = if s["flags"], do: " [#{inspect(s["flags"])}]", else: ""
      IO.puts("  #{color(:cyan, s["name"])} type #{s["type"]}#{flags}")
    end
  end

  defp render_daemon_response("list_set", data) do
    header("set #{data["name"]}")
    IO.puts("  type: #{data["type"]}")

    elements = data["elements"] || []
    config_elements = data["config_elements"] || []

    if elements == [] and config_elements == [] do
      info("  (empty)")
    else
      if elements != [] do
        IO.puts("  elements (live kernel): #{length(elements)}")
        for e <- elements, do: IO.puts("    #{e}")
      end

      if config_elements != [] do
        IO.puts("  elements (config): #{length(config_elements)}")
        for e <- config_elements, do: IO.puts("    #{inspect(e)}")
      end
    end
  end

  defp render_daemon_response("list_counters", data) do
    header("counters")

    for c <- data do
      pps = c["pps"] || 0
      total_pkts = c["total_packets"] || c["packets"] || 0
      total_bytes = c["total_bytes"] || c["bytes"] || 0
      history = c["history"] || []
      spark = sparkline(history)

      pps_str = format_rate(pps)
      IO.puts("  #{String.pad_trailing(c["name"], 16)} #{String.pad_leading(pps_str, 8)} pps  #{spark}  #{total_pkts} pkts  #{format_bytes(total_bytes)}")
    end
  end

  defp render_daemon_response("top", data) do
    sources = data["sources"] || []
    total = data["total"] || 0
    mode = data["mode"] || "unknown"

    header("top sources (#{total} connections, #{mode} mode)")

    if sources == [] do
      info("  (no connections)")
    else
      max_count = sources |> Enum.map(fn s -> Enum.at(s, 1, 0) end) |> Enum.max(fn -> 1 end)

      for s <- sources do
        [ip, count] = s
        bar_len = if max_count > 0, do: trunc(count / max_count * 30), else: 0
        bar = String.duplicate("█", bar_len)
        IO.puts("  #{String.pad_trailing(to_string(ip), 40)} #{String.pad_leading(to_string(count), 6)}  #{color(:cyan, bar)}")
      end
    end
  end

  defp render_daemon_response("audit_log", data) do
    if data == [] or data == nil do
      info("  (no audit entries)")
    else
      header("audit log")
      for entry <- data do
        time = entry["time"] || "?"
        action = entry["action"] || "?"
        details = entry["details"] || %{}

        detail_str = details
          |> Enum.map(fn {k, v} -> "#{k}=#{v}" end)
          |> Enum.join(" ")

        action_color = case action do
          a when a in ["ban", "del_element"] -> :red
          a when a in ["unban", "add_element"] -> :green
          "reload" -> :yellow
          _ -> :cyan
        end

        IO.puts("  #{color(:dim, time)}  #{color(action_color, String.pad_trailing(action, 14))} #{detail_str}")
      end
    end
  end

  defp render_daemon_response("diff_live", data) do
    if data == [] or data == nil do
      success("Config and kernel are in sync")
    else
      header("config drift")
      for d <- data do
        case d["type"] do
          "missing_chain" ->
            IO.puts("  #{color(:red, "-")} chain #{color(:cyan, d["chain"])} #{d["detail"]}")
          "extra_chain" ->
            IO.puts("  #{color(:green, "+")} chain #{color(:cyan, d["chain"])} #{d["detail"]}")
          "missing_set" ->
            IO.puts("  #{color(:red, "!")} set #{color(:cyan, d["set"])} #{d["detail"]}")
          "set_elements" ->
            IO.puts("  #{color(:yellow, "~")} set #{color(:cyan, d["set"])} config=#{d["config_count"]} kernel=#{d["kernel_count"]}")
          _ ->
            IO.puts("  #{inspect(d)}")
        end
      end
    end
  end

  defp render_daemon_response(_cmd, data) do
    IO.puts(inspect(data, pretty: true, width: 80))
  end

  defp cmd_add_elements(set, values) do
    for value <- values do
      cmd_daemon("add_element", %{"set" => set, "value" => value})
    end
  end

  defp cmd_delete_elements(set, values) do
    for value <- values do
      cmd_daemon("del_element", %{"set" => set, "value" => value})
    end
  end

  defp cmd_monitor do
    IO.puts(color(:dim, "Streaming counter rates (Ctrl-C to stop)...\n"))

    case Daemon.stream("monitor", %{}, fn resp ->
      case resp do
        %{"ok" => true, "data" => data} ->
          render_monitor_frame(data)
        _ ->
          :ok
      end
    end) do
      {:error, :not_running} ->
        error("Cannot connect to daemon. Is erlkoenig_nft running?")
        System.halt(1)
      {:error, :permission_denied} ->
        error("Permission denied.")
        System.halt(1)
      {:error, reason} ->
        error("Connection error: #{inspect(reason)}")
        System.halt(1)
      _ ->
        :ok
    end
  end

  defp render_monitor_frame(data) do
    counters = data["counters"] || []
    # Clear screen and move cursor to top
    IO.write("\e[2J\e[H")
    IO.puts(color(:bold, "── erlkoenig monitor ──") <> "  " <> color(:dim, NaiveDateTime.to_string(NaiveDateTime.local_now())))
    IO.puts("")

    for c <- counters do
      pps = c["pps"] || 0
      bps = c["bps"] || 0
      total_pkts = c["total_packets"] || 0
      total_bytes = c["total_bytes"] || 0
      history = c["history"] || []
      spark = sparkline(history)

      pps_str = format_rate(pps)
      bps_str = format_bytes(bps) <> "/s"
      IO.puts("  #{color(:cyan, String.pad_trailing(c["name"], 16))} #{String.pad_leading(pps_str, 8)} pps  #{String.pad_leading(bps_str, 12)}  #{spark}  #{total_pkts} pkts  #{format_bytes(total_bytes)}")
    end

    IO.puts("")
    IO.puts(color(:dim, "  Ctrl-C to stop"))
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

  defp cmd_examples(args) do
    dir = List.first(args) || find_examples_dir()

    if dir == nil or not File.dir?(dir) do
      error("Examples directory not found. Usage: erlkoenig examples [directory]")
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
      #{color(:cyan, "monitor")}                      Live-stream counter rates
      #{color(:cyan, "diff live")}                     Compare running kernel vs config
      #{color(:cyan, "top")} [n]                         Top source IPs by connection count
      #{color(:cyan, "log")} [n]                         Show audit log (last n entries)

    #{color(:bold, "NFT-STYLE COMMANDS")} (query/modify running firewall)
      #{color(:cyan, "list ruleset")}                  Show live ruleset (chains + sets)
      #{color(:cyan, "list chains")}                   List chains with hook/policy/rule count
      #{color(:cyan, "list sets")}                     List set names and types
      #{color(:cyan, "list set")} <name>                Show elements of a named set
      #{color(:cyan, "list counters")}                 List counter names and current values
      #{color(:cyan, "add element")} <set> <val>...     Add element(s) to a named set
      #{color(:cyan, "delete element")} <set> <val>...  Delete element(s) from a named set

    #{color(:bold, "LOCAL COMMANDS")} (no daemon needed)
      #{color(:cyan, "show")} <file.exs>               Render firewall as nft-style ruleset
      #{color(:cyan, "compile")} <file.exs> [-o path]   Compile DSL to .term config file
      #{color(:cyan, "validate")} <file.exs>            Validate DSL config for errors
      #{color(:cyan, "inspect")} <file.exs>             Show raw Erlang term structure
      #{color(:cyan, "diff")} <a.exs> <b.exs>           Compare two firewall configs
      #{color(:cyan, "examples")} [dir]                List available example configs
      #{color(:cyan, "version")}                       Show version
      #{color(:cyan, "completions")} [bash|zsh|fish]    Print shell completions

    #{color(:bold, "EXAMPLES")}
      erlkoenig show examples/hardened_webserver.exs
      erlkoenig compile examples/hardened_webserver.exs -o /etc/erlkoenig_nft/firewall.term
      erlkoenig apply examples/hardened_webserver.exs
      erlkoenig ban 10.0.0.5
      erlkoenig list sets
      erlkoenig add element blocklist4 10.0.0.5
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

  @commands ~w(status ban unban reload apply counters guard monitor top log list add delete show compile validate inspect diff examples version completions help)
  @guard_subcommands ~w(stats banned)
  @list_subcommands ~w(ruleset chains sets set counters)
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
            list)
                COMPREPLY=( $(compgen -W "#{Enum.join(@list_subcommands, " ")}" -- "$cur") )
                return 0
                ;;
            add|delete)
                COMPREPLY=( $(compgen -W "element" -- "$cur") )
                return 0
                ;;
            diff)
                COMPREPLY=( $(compgen -W "live" -- "$cur") $(compgen -f -X '!*.exs' -- "$cur") $(compgen -d -- "$cur") )
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
            'monitor:Live-stream counter rates'
            'top:Top source IPs by connection count'
            'log:Show audit log'
            'diff:Compare firewall configs or live drift'
            'list:List firewall objects (ruleset, chains, sets, counters)'
            'add:Add element to a set'
            'delete:Delete element from a set'
            'show:Render firewall as nft-style ruleset'
            'compile:Compile DSL to .term config file'
            'validate:Validate DSL config for errors'
            'inspect:Show raw Erlang term structure'
            'diff:Compare two firewall configs'
            'examples:List available example configs'
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
                list)
                    local -a list_sub
                    list_sub=('ruleset:Show live ruleset' 'chains:List chains' 'sets:List sets' 'set:Show set elements' 'counters:List counters')
                    _describe 'subcommand' list_sub
                    ;;
                add|delete)
                    local -a elem_sub
                    elem_sub=('element:Set element')
                    _describe 'subcommand' elem_sub
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
                    local -a diff_sub
                    diff_sub=('live:Compare kernel vs config')
                    _describe 'subcommand' diff_sub
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
      {"monitor", "Live-stream counter rates"},
      {"top", "Top source IPs by connection count"},
      {"log", "Show audit log"},
      {"list", "List firewall objects"},
      {"add", "Add element to a set"},
      {"delete", "Delete element from a set"},
      {"show", "Render firewall as nft-style ruleset"},
      {"compile", "Compile DSL to .term config file"},
      {"validate", "Validate DSL config for errors"},
      {"inspect", "Show raw Erlang term structure"},
      {"diff", "Compare two firewall configs"},
      {"examples", "List available example configs"},
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

    list_sub = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from list' -a 'ruleset chains sets set counters'
    """

    add_del = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from add delete' -a 'element'
    """

    completions = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
    """

    file_cmds = """
    complete -c erlkoenig -n '__fish_seen_subcommand_from show compile validate inspect apply diff' -F -r
    """

    Enum.join(main, "\n") <> "\n" <> guard <> list_sub <> add_del <> completions <> file_cmds
  end

  # --- Formatting helpers ---

  @sparkline_chars ~w(▁ ▂ ▃ ▄ ▅ ▆ ▇ █)

  defp sparkline([]), do: String.duplicate("░", 20)
  defp sparkline(values) do
    max_val = Enum.max(values)
    if max_val == 0 do
      String.duplicate("▁", length(values))
    else
      values
      |> Enum.map(fn v ->
        idx = trunc(v / max_val * 7)
        idx = min(idx, 7)
        Enum.at(@sparkline_chars, idx)
      end)
      |> Enum.join()
    end
  end

  defp format_rate(rate) when is_float(rate) do
    cond do
      rate >= 1_000_000 -> "#{Float.round(rate / 1_000_000, 1)}M"
      rate >= 1_000 -> "#{Float.round(rate / 1_000, 1)}K"
      rate >= 1 -> "#{Float.round(rate, 1)}"
      true -> "0"
    end
  end
  defp format_rate(rate) when is_integer(rate), do: format_rate(rate / 1)

  defp format_bytes(bytes) when is_number(bytes) do
    cond do
      bytes >= 1_073_741_824 -> "#{Float.round(bytes / 1_073_741_824, 1)} GiB"
      bytes >= 1_048_576 -> "#{Float.round(bytes / 1_048_576, 1)} MiB"
      bytes >= 1024 -> "#{Float.round(bytes / 1024, 1)} KiB"
      true -> "#{trunc(bytes)} B"
    end
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
