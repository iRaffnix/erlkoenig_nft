defmodule ErlkoenigNft.CLI.Daemon do
  @moduledoc """
  Unix domain socket client for the erlkoenig_nft daemon.

  Connects to the daemon's JSON API socket and sends commands.
  """

  @default_socket "/var/run/erlkoenig.sock"
  @max_response_size 1_048_576

  @doc "Send a command to the daemon and return the parsed response."
  def call(cmd, opts \\ %{}) do
    path = socket_path()

    with {:ok, sock} <- connect(path),
         :ok <- send_request(sock, Map.put(opts, "cmd", cmd)),
         {:ok, resp} <- read_response(sock) do
      :socket.close(sock)
      {:ok, resp}
    else
      {:error, :econnrefused} -> {:error, :not_running}
      {:error, :enoent} -> {:error, :not_running}
      {:error, :eacces} -> {:error, :permission_denied}
      other -> other
    end
  end

  defp socket_path do
    System.get_env("ERLKOENIG_SOCKET") || @default_socket
  end

  defp connect(path) do
    with {:ok, sock} <- :socket.open(:local, :stream, :default),
         :ok <- :socket.connect(sock, %{family: :local, path: path}) do
      {:ok, sock}
    else
      {:error, _} = err ->
        err
    end
  end

  defp send_request(sock, cmd_map) do
    payload = :json.encode(cmd_map)
    :socket.send(sock, [payload, "\n"])
  end

  defp read_response(sock, buf \\ <<>>) do
    case :binary.match(buf, "\n") do
      {pos, 1} ->
        line = :binary.part(buf, 0, pos)
        {:ok, :json.decode(line)}

      :nomatch when byte_size(buf) > @max_response_size ->
        {:error, :response_too_large}

      :nomatch ->
        case :socket.recv(sock, 0, 10_000) do
          {:ok, data} -> read_response(sock, <<buf::binary, data::binary>>)
          {:error, _} = err -> err
        end
    end
  end
end
