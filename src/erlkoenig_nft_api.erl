%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_nft_api).
-moduledoc """
JSON API server over a Unix domain socket.

Exposes the erlkoenig_nft public API as a line-delimited JSON protocol,
similar to the Docker daemon socket.

    Client:  {"cmd":"status"}\n
    Server:  {"ok":true,"data":{...}}\n

    Client:  {"cmd":"ban","ip":"10.0.0.5"}\n
    Server:  {"ok":true}\n

Socket path (in order of precedence):
  1. ERLKOENIG_SOCKET environment variable
  2. application:get_env(erlkoenig_nft, api_socket)
  3. /var/run/erlkoenig.sock

Commands: status, ban, unban, reload, apply, counters, guard_stats, guard_banned
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2]).

-define(DEFAULT_SOCKET, "/var/run/erlkoenig.sock").

%% --- Public API ---

-doc "Start the API socket server.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% --- gen_server callbacks ---

init([]) ->
    Path = socket_path(),
    %% Remove stale socket file
    _ = file:delete(Path),
    case listen(Path) of
        {ok, LSock} ->
            %% Set socket file permissions: owner+group rw
            _ = file:change_mode(Path, 8#0660),
            Group = os:getenv("ERLKOENIG_GROUP", "erlkoenig"),
            _ = os:cmd("chgrp " ++ Group ++ " " ++ Path ++ " 2>/dev/null"),
            logger:info("API socket listening on ~s", [Path]),
            %% Start async accept loop
            {select, _} = socket:accept(LSock, nowait),
            {ok, #{listen => LSock, path => Path, handlers => #{}}};
        {error, Reason} ->
            logger:warning("API socket failed to start: ~p", [Reason]),
            {ok, #{listen => undefined, path => Path, handlers => #{}}}
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, not_supported}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Async accept completed — a client is ready
handle_info({'$socket', LSock, select, _Ref}, #{listen := LSock} = State) ->
    case socket:accept(LSock) of
        {ok, ClientSock} ->
            Pid = proc_lib:spawn_link(fun() -> handle_client(ClientSock) end),
            _ = socket:setopt(ClientSock, {otp, controlling_process}, Pid),
            Mon = monitor(process, Pid),
            Handlers = maps:put(Pid, Mon, maps:get(handlers, State)),
            %% Accept next connection
            {select, _} = socket:accept(LSock, nowait),
            {noreply, State#{handlers := Handlers}};
        {error, Reason} ->
            logger:warning("API accept error: ~p", [Reason]),
            {select, _} = socket:accept(LSock, nowait),
            {noreply, State}
    end;

%% Handler process exited
handle_info({'DOWN', _Mon, process, Pid, _Reason}, State) ->
    Handlers = maps:remove(Pid, maps:get(handlers, State)),
    {noreply, State#{handlers := Handlers}};

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #{listen := LSock, path := Path}) ->
    case LSock of
        undefined -> ok;
        _ -> socket:close(LSock)
    end,
    _ = file:delete(Path),
    ok;
terminate(_Reason, _State) ->
    ok.

%% --- Internal: Socket setup ---

listen(Path) ->
    case socket:open(local, stream, default) of
        {ok, Sock} ->
            case socket:bind(Sock, #{family => local, path => Path}) of
                ok ->
                    case socket:listen(Sock) of
                        ok -> {ok, Sock};
                        Err ->
                            socket:close(Sock),
                            Err
                    end;
                Err ->
                    socket:close(Sock),
                    Err
            end;
        Err ->
            Err
    end.

socket_path() ->
    case os:getenv("ERLKOENIG_SOCKET") of
        false ->
            case application:get_env(erlkoenig_nft, api_socket) of
                {ok, Path} -> Path;
                undefined -> ?DEFAULT_SOCKET
            end;
        Path ->
            Path
    end.

%% --- Internal: Per-connection handler ---

handle_client(Sock) ->
    client_loop(Sock, <<>>).

client_loop(Sock, Buf) ->
    case binary:match(Buf, <<"\n">>) of
        {Pos, 1} ->
            Line = binary:part(Buf, 0, Pos),
            Rest = binary:part(Buf, Pos + 1, byte_size(Buf) - Pos - 1),
            Response = process_request(Line),
            RespBin = [json:encode(Response), <<"\n">>],
            case socket:send(Sock, RespBin) of
                ok -> client_loop(Sock, Rest);
                {error, _} -> socket:close(Sock)
            end;
        nomatch ->
            case socket:recv(Sock, 0, 30000) of
                {ok, Data} ->
                    client_loop(Sock, <<Buf/binary, Data/binary>>);
                {error, _} ->
                    socket:close(Sock)
            end
    end.

process_request(Line) ->
    try
        Cmd = json:decode(Line),
        dispatch(Cmd)
    catch
        _:Reason ->
            #{<<"ok">> => false, <<"error">> => iolist_to_binary(
                io_lib:format("~p", [Reason]))}
    end.

%% --- Internal: Command dispatch ---

dispatch(#{<<"cmd">> := <<"status">>}) ->
    try
        Data = erlkoenig_nft:status(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"ban">>, <<"ip">> := IP}) ->
    try
        ok = erlkoenig_nft:ban(binary_to_list(IP)),
        #{<<"ok">> => true, <<"data">> => #{<<"banned">> => IP}}
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"unban">>, <<"ip">> := IP}) ->
    try
        case erlkoenig_nft:unban(binary_to_list(IP)) of
            ok -> #{<<"ok">> => true, <<"data">> => #{<<"unbanned">> => IP}};
            {error, R} -> #{<<"ok">> => false, <<"error">> => format_err(R)}
        end
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"reload">>}) ->
    try
        case erlkoenig_nft:reload() of
            ok -> #{<<"ok">> => true};
            {error, R} -> #{<<"ok">> => false, <<"error">> => format_err(R)}
        end
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"apply">>, <<"term">> := TermStr}) ->
    try
        Path = erlkoenig_nft_config:config_path(),
        ConfigPath = case Path of
            {ok, P} -> P;
            {error, _} -> "/etc/erlkoenig_nft/firewall.term"
        end,
        TmpPath = ConfigPath ++ ".tmp",
        ok = file:write_file(TmpPath, TermStr),
        ok = file:rename(TmpPath, ConfigPath),
        case erlkoenig_nft:reload() of
            ok -> #{<<"ok">> => true};
            {error, R} ->
                #{<<"ok">> => false, <<"error">> => format_err(R)}
        end
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"counters">>}) ->
    try
        Rates = erlkoenig_nft:rates(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Rates)}
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"guard_stats">>}) ->
    try
        Stats = erlkoenig_nft:guard_stats(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Stats)}
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := <<"guard_banned">>}) ->
    try
        Banned = erlkoenig_nft:guard_banned(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Banned)}
    catch _:E ->
        #{<<"ok">> => false, <<"error">> => format_err(E)}
    end;

dispatch(#{<<"cmd">> := Cmd}) ->
    #{<<"ok">> => false, <<"error">> => <<"unknown command: ", Cmd/binary>>};

dispatch(_) ->
    #{<<"ok">> => false, <<"error">> => <<"missing cmd field">>}.

%% --- Internal: Term → JSON-safe conversion ---

term_to_json(T) when is_map(T) ->
    maps:fold(fun(K, V, Acc) ->
        maps:put(term_to_json_key(K), term_to_json(V), Acc)
    end, #{}, T);
term_to_json(T) when is_list(T) ->
    [term_to_json(E) || E <- T];
term_to_json(T) when is_tuple(T) ->
    [term_to_json(E) || E <- tuple_to_list(T)];
term_to_json(T) when is_atom(T) ->
    atom_to_binary(T);
term_to_json(T) when is_binary(T) ->
    T;
term_to_json(T) when is_integer(T) ->
    T;
term_to_json(T) when is_float(T) ->
    T;
term_to_json(T) when is_pid(T) ->
    list_to_binary(pid_to_list(T));
term_to_json(T) when is_reference(T) ->
    list_to_binary(ref_to_list(T));
term_to_json(T) ->
    iolist_to_binary(io_lib:format("~p", [T])).

term_to_json_key(K) when is_atom(K) -> atom_to_binary(K);
term_to_json_key(K) when is_binary(K) -> K;
term_to_json_key(K) -> iolist_to_binary(io_lib:format("~p", [K])).

format_err(E) ->
    iolist_to_binary(io_lib:format("~p", [E])).
