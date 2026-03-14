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

Commands: status, ban, unban, reload, apply, counters, guard_stats, guard_banned,
          list_ruleset, list_chains, list_sets, list_set, list_counters,
          add_element, del_element
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2]).

-define(DEFAULT_SOCKET, "/var/run/erlkoenig.sock").
-define(MAX_BUF_SIZE, 1048576). %% 1 MB max request size

%% --- Public API ---

-doc "Start the API socket server.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% --- gen_server callbacks ---

init([]) ->
    Path = socket_path(),
    _ = file:delete(Path),
    case listen(Path) of
        {ok, LSock} ->
            _ = file:change_mode(Path, 8#0660),
            set_socket_group(Path),
            logger:info("API socket listening on ~s", [Path]),
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
    _ = case LSock of
        undefined -> ok;
        _ -> socket:close(LSock)
    end,
    _ = file:delete(Path),
    ok;
terminate(_Reason, _State) ->
    ok.

%% --- Internal: Socket setup ---

set_socket_group(Path) ->
    Group = os:getenv("ERLKOENIG_GROUP", "erlkoenig"),
    case valid_group_name(Group) of
        true ->
            case group_gid(Group) of
                {ok, Gid} ->
                    _ = file:change_group(Path, Gid),
                    ok;
                error ->
                    logger:warning("Group '~s' not found, socket accessible to owner only", [Group])
            end;
        false ->
            logger:warning("Invalid group name '~s', ignoring", [Group])
    end.

valid_group_name(Name) ->
    lists:all(fun(C) ->
        (C >= $a andalso C =< $z) orelse
        (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9) orelse
        C =:= $_ orelse C =:= $-
    end, Name) andalso length(Name) > 0 andalso length(Name) =< 32.

group_gid(Name) ->
    %% Read /etc/group to resolve group name → gid
    case file:read_file("/etc/group") of
        {ok, Bin} ->
            Lines = binary:split(Bin, <<"\n">>, [global]),
            NameBin = list_to_binary(Name),
            find_gid(NameBin, Lines);
        {error, _} ->
            error
    end.

find_gid(_Name, []) -> error;
find_gid(Name, [Line | Rest]) ->
    case binary:split(Line, <<":">>, [global]) of
        [Name, _, GidBin | _] ->
            try {ok, binary_to_integer(GidBin)}
            catch _:_ -> error end;
        _ ->
            find_gid(Name, Rest)
    end.

listen(Path) ->
    case socket:open(local, stream, default) of
        {ok, Sock} ->
            case socket:bind(Sock, #{family => local, path => Path}) of
                ok ->
                    case socket:listen(Sock) of
                        ok -> {ok, Sock};
                        Err ->
                            _ = socket:close(Sock),
                            Err
                    end;
                Err ->
                    _ = socket:close(Sock),
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

client_loop(Sock, Buf) when byte_size(Buf) > ?MAX_BUF_SIZE ->
    logger:warning("API client exceeded max buffer size, disconnecting"),
    _ = socket:close(Sock),
    ok;
client_loop(Sock, Buf) ->
    case binary:match(Buf, <<"\n">>) of
        {Pos, 1} ->
            Line = binary:part(Buf, 0, Pos),
            Rest = binary:part(Buf, Pos + 1, byte_size(Buf) - Pos - 1),
            case process_request(Line) of
                {stream, monitor, Interval} ->
                    stream_monitor(Sock, Interval),
                    _ = socket:close(Sock),
                    ok;
                Response ->
                    RespBin = [json:encode(Response), <<"\n">>],
                    case socket:send(Sock, RespBin) of
                        ok -> client_loop(Sock, Rest);
                        {error, _} -> _ = socket:close(Sock), ok
                    end
            end;
        nomatch ->
            case socket:recv(Sock, 0, 30000) of
                {ok, Data} ->
                    client_loop(Sock, <<Buf/binary, Data/binary>>);
                {error, _} ->
                    _ = socket:close(Sock),
                    ok
            end
    end.

process_request(Line) ->
    try
        Cmd = json:decode(Line),
        dispatch(Cmd)
    catch
        _:_ ->
            #{<<"ok">> => false, <<"error">> => <<"invalid request">>}
    end.

%% --- Internal: Streaming handler ---

stream_monitor(Sock, Interval) ->
    Rates = erlkoenig_nft:rates(),
    Counters = erlkoenig_nft:list_counters(),
    Data = #{<<"counters">> => term_to_json(Counters),
             <<"rates">> => term_to_json(Rates)},
    Msg = [json:encode(#{<<"ok">> => true, <<"data">> => Data}), <<"\n">>],
    case socket:send(Sock, Msg) of
        ok ->
            timer:sleep(Interval),
            stream_monitor(Sock, Interval);
        {error, _} ->
            ok
    end.

%% --- Internal: Command dispatch ---

dispatch(#{<<"cmd">> := <<"status">>}) ->
    try
        Data = erlkoenig_nft:status(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API status error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"ban">>, <<"ip">> := IP}) ->
    try
        ok = erlkoenig_nft:ban(binary_to_list(IP)),
        #{<<"ok">> => true, <<"data">> => #{<<"banned">> => IP}}
    catch _:E ->
        logger:warning("API ban error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"ban failed">>}
    end;

dispatch(#{<<"cmd">> := <<"unban">>, <<"ip">> := IP}) ->
    try
        case erlkoenig_nft:unban(binary_to_list(IP)) of
            ok -> #{<<"ok">> => true, <<"data">> => #{<<"unbanned">> => IP}};
            {error, _R} -> #{<<"ok">> => false, <<"error">> => <<"unban failed">>}
        end
    catch _:E ->
        logger:warning("API unban error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"unban failed">>}
    end;

dispatch(#{<<"cmd">> := <<"reload">>}) ->
    try
        case erlkoenig_nft:reload() of
            ok -> #{<<"ok">> => true};
            {error, _R} -> #{<<"ok">> => false, <<"error">> => <<"reload failed">>}
        end
    catch _:E ->
        logger:warning("API reload error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"reload failed">>}
    end;

dispatch(#{<<"cmd">> := <<"apply">>, <<"term">> := TermStr}) ->
    try
        %% Validate the term parses before writing
        case validate_config_term(TermStr) of
            ok ->
                ConfigPath = resolve_config_path(),
                TmpPath = ConfigPath ++ ".tmp",
                case file:write_file(TmpPath, TermStr) of
                    ok ->
                        case file:rename(TmpPath, ConfigPath) of
                            ok ->
                                case erlkoenig_nft:reload() of
                                    ok -> #{<<"ok">> => true};
                                    {error, _R} ->
                                        #{<<"ok">> => false, <<"error">> => <<"reload failed after apply">>}
                                end;
                            {error, RenameErr} ->
                                _ = file:delete(TmpPath),
                                logger:warning("API apply rename error: ~p", [RenameErr]),
                                #{<<"ok">> => false, <<"error">> => <<"failed to write config">>}
                        end;
                    {error, WriteErr} ->
                        logger:warning("API apply write error: ~p", [WriteErr]),
                        #{<<"ok">> => false, <<"error">> => <<"failed to write config">>}
                end;
            {error, Reason} ->
                #{<<"ok">> => false, <<"error">> => Reason}
        end
    catch _:E ->
        logger:warning("API apply error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"apply failed">>}
    end;

dispatch(#{<<"cmd">> := <<"counters">>}) ->
    try
        Rates = erlkoenig_nft:rates(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Rates)}
    catch _:E ->
        logger:warning("API counters error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"guard_stats">>}) ->
    try
        Stats = erlkoenig_nft:guard_stats(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Stats)}
    catch _:E ->
        logger:warning("API guard_stats error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"guard_banned">>}) ->
    try
        Banned = erlkoenig_nft:guard_banned(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Banned)}
    catch _:E ->
        logger:warning("API guard_banned error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"monitor">>, <<"interval">> := Interval})
  when is_integer(Interval), Interval >= 500 ->
    %% Handled specially — returns a stream marker
    {stream, monitor, Interval};
dispatch(#{<<"cmd">> := <<"monitor">>}) ->
    {stream, monitor, 2000};

dispatch(#{<<"cmd">> := <<"list_ruleset">>}) ->
    try
        Status = erlkoenig_nft:status(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Status)}
    catch _:E ->
        logger:warning("API list_ruleset error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"list_chains">>}) ->
    try
        Data = erlkoenig_nft:list_chains(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API list_chains error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"list_sets">>}) ->
    try
        Data = erlkoenig_nft:list_sets(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API list_sets error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"list_set">>, <<"name">> := Name}) ->
    try
        case erlkoenig_nft:list_set(Name) of
            {ok, Data} ->
                #{<<"ok">> => true, <<"data">> => term_to_json(Data)};
            {error, Reason} ->
                #{<<"ok">> => false, <<"error">> => iolist_to_binary(
                    io_lib:format("~p", [Reason]))}
        end
    catch _:E ->
        logger:warning("API list_set error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"list_counters">>}) ->
    try
        Data = erlkoenig_nft:list_counters(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API list_counters error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"add_element">>, <<"set">> := Set, <<"value">> := Value}) ->
    try
        case erlkoenig_nft:add_element(Set, Value) of
            ok -> #{<<"ok">> => true};
            {error, Reason} ->
                #{<<"ok">> => false, <<"error">> => iolist_to_binary(
                    io_lib:format("~p", [Reason]))}
        end
    catch _:E ->
        logger:warning("API add_element error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"add element failed">>}
    end;

dispatch(#{<<"cmd">> := <<"top">>, <<"n">> := N}) when is_integer(N), N > 0 ->
    try
        Sources = erlkoenig_nft:ct_top(N),
        TotalConns = erlkoenig_nft:ct_count(),
        Mode = erlkoenig_nft:ct_mode(),
        Data = #{<<"sources">> => term_to_json(Sources),
                 <<"total">> => TotalConns,
                 <<"mode">> => atom_to_binary(Mode)},
        #{<<"ok">> => true, <<"data">> => Data}
    catch _:E ->
        logger:warning("API top error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;
dispatch(#{<<"cmd">> := <<"top">>}) ->
    try
        Sources = erlkoenig_nft:ct_top(10),
        TotalConns = erlkoenig_nft:ct_count(),
        Mode = erlkoenig_nft:ct_mode(),
        Data = #{<<"sources">> => term_to_json(Sources),
                 <<"total">> => TotalConns,
                 <<"mode">> => atom_to_binary(Mode)},
        #{<<"ok">> => true, <<"data">> => Data}
    catch _:E ->
        logger:warning("API top error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"audit_log">>, <<"n">> := N}) when is_integer(N), N > 0 ->
    try
        Data = erlkoenig_nft:audit_log(N),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API audit_log error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;
dispatch(#{<<"cmd">> := <<"audit_log">>}) ->
    try
        Data = erlkoenig_nft:audit_log(100),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API audit_log error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"diff_live">>}) ->
    try
        Data = erlkoenig_nft:diff_live(),
        #{<<"ok">> => true, <<"data">> => term_to_json(Data)}
    catch _:E ->
        logger:warning("API diff_live error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"internal error">>}
    end;

dispatch(#{<<"cmd">> := <<"del_element">>, <<"set">> := Set, <<"value">> := Value}) ->
    try
        case erlkoenig_nft:del_element(Set, Value) of
            ok -> #{<<"ok">> => true};
            {error, Reason} ->
                #{<<"ok">> => false, <<"error">> => iolist_to_binary(
                    io_lib:format("~p", [Reason]))}
        end
    catch _:E ->
        logger:warning("API del_element error: ~p", [E]),
        #{<<"ok">> => false, <<"error">> => <<"delete element failed">>}
    end;

dispatch(#{<<"cmd">> := _}) ->
    #{<<"ok">> => false, <<"error">> => <<"unknown command">>};

dispatch(_) ->
    #{<<"ok">> => false, <<"error">> => <<"missing cmd field">>}.

%% --- Internal: Config validation ---

resolve_config_path() ->
    case erlkoenig_nft_config:config_path() of
        {ok, P} ->
            P;
        {error, _} ->
            %% Fallback: write to etc/ relative to CWD (release layout)
            case os:getenv("ERLKOENIG_CONFIG_DIR") of
                false -> "etc/firewall.term";
                Dir -> filename:join(Dir, "firewall.term")
            end
    end.

validate_config_term(TermStr) ->
    %% Parse the term and check it has the required structure
    case safe_consult_string(TermStr) of
        {ok, [Config]} when is_map(Config) ->
            case maps:is_key(table, Config) andalso maps:is_key(chains, Config) of
                true -> ok;
                false -> {error, <<"config must contain 'table' and 'chains' keys">>}
            end;
        {ok, _} ->
            {error, <<"config must be a single map term">>};
        {error, _} ->
            {error, <<"config term failed to parse">>}
    end.

safe_consult_string(Bin) when is_binary(Bin) ->
    safe_consult_string(binary_to_list(Bin));
safe_consult_string(Str) ->
    case erl_scan:string(Str) of
        {ok, Tokens, _} ->
            parse_terms(Tokens, []);
        {error, _, _} ->
            {error, scan_failed}
    end.

parse_terms([], Acc) ->
    {ok, lists:reverse(Acc)};
parse_terms(Tokens, Acc) ->
    case erl_parse:parse_term(Tokens) of
        {ok, Term} ->
            %% Find remaining tokens after the dot
            Rest = drop_until_dot(Tokens),
            parse_terms(Rest, [Term | Acc]);
        {error, _} ->
            {error, parse_failed}
    end.

drop_until_dot([]) -> [];
drop_until_dot([{dot, _} | Rest]) -> Rest;
drop_until_dot([_ | Rest]) -> drop_until_dot(Rest).

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
