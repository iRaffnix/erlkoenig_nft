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

-module(erlkoenig_nft_otel).
-moduledoc """
OpenTelemetry instrumentation for erlkoenig_nft.

Subscribes to internal event streams (pg groups) and translates them
into OTel metrics, traces, and structured logs. Pushes via OTLP.

Returns `ignore` when the OpenTelemetry SDK is not loaded, so this
module is safe to include in the supervision tree unconditionally.

Depends only on `opentelemetry_api` — the SDK and exporter are
release-level dependencies (see ADR-0005).

## Metrics

Subscribes to `counter_events`, `ct_events`, `nflog_events` pg groups.
Polls `guard_stats/0` every 10 seconds.

## Traces

Provides `span/3` for wrapping operations in spans. Used by the
public API module (`erlkoenig_nft.erl`) for ban/unban/reload.

## Logs

Emits structured log records for audit events (ban, unban, reload,
threat alerts). Correlated with active span context.
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([span/3]).
-export([log_event/2, log_event/3]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2]).

-include_lib("opentelemetry_api/include/otel_tracer.hrl").

-define(GUARD_POLL_INTERVAL, 10000).

%% --- Public API ---

-doc "Start the OTel instrumentation server.".
-spec start_link() -> {ok, pid()} | {error, term()} | ignore.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Wrap a function in an OTel span.

    erlkoenig_nft_otel:span(<<"nft.ban">>, #{<<"ip">> => IP}, fun() ->
        do_ban(IP)
    end)

If the SDK is not loaded, the function is called directly with no overhead.
""".
-spec span(binary(), map(), fun(() -> Result)) -> Result when Result :: term().
span(Name, Attributes, Fun) ->
    ?with_span(Name, #{attributes => Attributes}, fun(_SpanCtx) ->
        try
            Result = Fun(),
            ?set_attribute(<<"result">>, <<"ok">>),
            Result
        catch
            Class:Reason:Stack ->
                ?set_attribute(<<"result">>, <<"error">>),
                ?set_attribute(<<"error.type">>, atom_to_binary(Class)),
                ?set_attribute(
                    <<"error.message">>,
                    iolist_to_binary(io_lib:format("~p", [Reason]))
                ),
                erlang:raise(Class, Reason, Stack)
        end
    end).

-doc "Emit a structured OTel log record at info severity.".
-spec log_event(binary(), map()) -> ok.
log_event(EventName, Body) ->
    log_event(EventName, info, Body).

-doc "Emit a structured OTel log record at the given severity.".
-spec log_event(binary(), atom(), map()) -> ok.
log_event(EventName, Severity, Body) ->
    SevText = severity_text(Severity),
    logger:log(Severity, Body#{
        <<"otel.event.name">> => EventName,
        <<"otel.severity">> => SevText
    }),
    ok.

%% --- gen_server callbacks ---

init([]) ->
    proc_lib:set_label(erlkoenig_nft_otel),
    case otel_sdk_loaded() of
        true ->
            %% Subscribe to event streams
            ok = pg:join(erlkoenig_nft, counter_events, self()),
            ok = pg:join(erlkoenig_nft, ct_events, self()),
            ok = pg:join(erlkoenig_nft, nflog_events, self()),
            %% Start guard stats polling
            erlang:send_after(?GUARD_POLL_INTERVAL, self(), poll_guard),
            logger:info("OTel instrumentation active"),
            {ok, #{
                guard_prev => #{},
                ct_new_count => 0,
                ct_destroy_count => 0,
                nflog_count => 0
            }};
        false ->
            ignore
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, not_supported}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Counter events from erlkoenig_nft_counter
handle_info({counter_event, Name, Data}, State) ->
    Attrs = [{<<"name">>, Name}],
    TotalPkts = maps:get(total_packets, Data, 0),
    TotalBytes = maps:get(total_bytes, Data, 0),
    Pps = maps:get(pps, Data, 0.0),
    Bps = maps:get(bps, Data, 0.0),
    record_metric('erlkoenig.nft.counter.packets', TotalPkts, Attrs),
    record_metric('erlkoenig.nft.counter.bytes', TotalBytes, Attrs),
    record_metric('erlkoenig.nft.counter.pps', Pps, Attrs),
    record_metric('erlkoenig.nft.counter.bps', Bps, Attrs),
    {noreply, State};
%% Conntrack events
handle_info({ct_new, _Details}, #{ct_new_count := N} = State) ->
    NewN = N + 1,
    record_metric('erlkoenig.nft.ct.new', NewN, []),
    %% Update active connections gauge
    try
        Active = erlkoenig_nft:ct_count(),
        record_metric('erlkoenig.nft.ct.active', Active, [])
    catch
        _:_ -> ok
    end,
    {noreply, State#{ct_new_count := NewN}};
handle_info({ct_destroy, _Details}, #{ct_destroy_count := N} = State) ->
    NewN = N + 1,
    record_metric('erlkoenig.nft.ct.destroy', NewN, []),
    try
        Active = erlkoenig_nft:ct_count(),
        record_metric('erlkoenig.nft.ct.active', Active, [])
    catch
        _:_ -> ok
    end,
    {noreply, State#{ct_destroy_count := NewN}};
handle_info({ct_alert, Alert}, State) ->
    log_event(<<"nft.ct.alert">>, warning, #{
        <<"alert">> => iolist_to_binary(io_lib:format("~p", [Alert]))
    }),
    {noreply, State};
%% NFLOG events
handle_info({nflog_event, Details}, #{nflog_count := N} = State) ->
    NewN = N + 1,
    record_metric('erlkoenig.nft.nflog.packets', NewN, []),
    Src = maps:get(src, Details, <<>>),
    Dst = maps:get(dst, Details, <<>>),
    Proto = maps:get(proto, Details, <<>>),
    log_event(<<"nft.nflog.drop">>, warning, #{
        <<"src">> => Src, <<"dst">> => Dst, <<"proto">> => Proto
    }),
    {noreply, State#{nflog_count := NewN}};
%% Periodic guard stats polling
handle_info(poll_guard, #{guard_prev := Prev} = State) ->
    NewPrev =
        try
            Stats = erlkoenig_nft:guard_stats(),
            Floods = maps:get(floods_detected, Stats, 0),
            Scans = maps:get(scans_detected, Stats, 0),
            ActiveBans = maps:get(active_bans, Stats, 0),
            BansIssued = maps:get(bans_issued, Stats, 0),
            record_metric('erlkoenig.nft.guard.floods', Floods, []),
            record_metric('erlkoenig.nft.guard.scans', Scans, []),
            record_metric('erlkoenig.nft.guard.active_bans', ActiveBans, []),
            record_metric('erlkoenig.nft.guard.bans_issued', BansIssued, []),
            %% Log new floods/scans as events
            PrevFloods = maps:get(floods_detected, Prev, 0),
            PrevScans = maps:get(scans_detected, Prev, 0),
            if
                Floods > PrevFloods ->
                    log_event(<<"nft.guard.flood_detected">>, warning, #{
                        <<"total">> => Floods
                    });
                true ->
                    ok
            end,
            if
                Scans > PrevScans ->
                    log_event(<<"nft.guard.scan_detected">>, warning, #{
                        <<"total">> => Scans
                    });
                true ->
                    ok
            end,
            Stats
        catch
            _:_ -> Prev
        end,
    erlang:send_after(?GUARD_POLL_INTERVAL, self(), poll_guard),
    {noreply, State#{guard_prev := NewPrev}};
handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%% --- Internal ---

-spec otel_sdk_loaded() -> boolean().
otel_sdk_loaded() ->
    %% The opentelemetry_api package also has an `opentelemetry` module,
    %% so we check for a module that only exists in the SDK.
    case code:ensure_loaded(otel_batch_processor) of
        {module, otel_batch_processor} -> true;
        _ -> false
    end.

-spec record_metric(atom(), number(), [{binary(), term()}]) -> ok.
record_metric(Name, Value, Attributes) ->
    %% The OTel metrics API lives in opentelemetry_experimental, which is
    %% a release-level dep (not in our app deps). Use fully dynamic module
    %% references to avoid xref warnings. Falls back to no-op if SDK not loaded.
    MeterMod = otel_meter_mod(),
    CounterMod = otel_counter_mod(),
    try
        case MeterMod:lookup_instrument(otel_meter_default, Name) of
            undefined ->
                ok;
            Instrument ->
                CounterMod:add(Instrument, Value, maps:from_list(Attributes))
        end
    catch
        error:undef ->
            ok;
        _:_ ->
            ok
    end.

otel_meter_mod() -> otel_meter.
otel_counter_mod() -> otel_counter.

severity_text(debug) -> <<"DEBUG">>;
severity_text(info) -> <<"INFO">>;
severity_text(notice) -> <<"INFO">>;
severity_text(warning) -> <<"WARN">>;
severity_text(error) -> <<"ERROR">>;
severity_text(critical) -> <<"ERROR">>;
severity_text(alert) -> <<"ERROR">>;
severity_text(emergency) -> <<"ERROR">>;
severity_text(_) -> <<"INFO">>.
