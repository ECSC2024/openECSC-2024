-module(node).
-export([start/0]).

nth([H|_], 0) -> H;
nth([_|T], I) -> nth(T, I-1);
nth([], _) -> nil.

idx(L, E) -> idx(L, E, 0).
idx([H|_], H, I) -> I;
idx([_|T], E, I) -> idx(T, E, I+1);
idx([], _, _) -> nil.

srt([P|R]) ->
	srt([X || X <- R, X < P]) ++ [P] ++ srt([X || X <- R, X >= P]);
srt([]) -> [].

shf(L) ->
	[Y||{_,Y} <- srt([{rand:uniform(), X} || X <- L])].

len([_|T]) -> 1 + len(T);
len([]) -> 0.
	
seq(N) -> seq(0, N).
seq(S, N) when S < N ->
	[S|seq(S+1, N)];
seq(N, N) -> [].

sub(L,[P0|P]) ->
	[nth(L, P0)|sub(L,P)];
sub(_, []) -> [].

inv(P) -> inv(P, seq(len(P))).
inv(P, [H|R]) ->
	[idx(P, H)|inv(P, R)];
inv(_, []) -> [].

xorL([M0|M], [K0|K]) ->
	[M0 bxor K0|xorL(M, K)];
xorL([], _) -> [].

enc(M, P, K) -> xorL(sub(M, P), K).
dec(C, P, K) -> sub(xorL(C, K), inv(P)).
	
%% 
listen(Other, Msg, Key, Stop) ->
	receive
		{enc, _, {P, C}} ->
			case dec(C, P, Key) of
				Msg ->
					Other ! {ok, self()},
					case Stop of
						true -> ok;
						_ -> 
							[Ph|Pl] = P,
							speak(Other, Msg, Key, Pl ++ [Ph], true)
					end;
				_ ->
					Other ! {ko, self()},
					err
			end;
		_ ->
			err
	end.

speak(Other, Msg, Key, P, Stop) ->
	Other ! {enc, self(), {P, enc(Msg, P, Key)}},
	receive
		{ok, _} ->
			case Stop of
				true -> ok;
				_ -> listen(Other, Msg, Key, true)
			end;
		_ -> 
			err
	end.

start() ->
	Other = list_to_atom(os:getenv("OTHER")),
	Init = os:getenv("INIT"),
	Msg = os:getenv("MESSAGE"),
	Key = os:getenv("KEY"),

	register(app, self()),

	% give some time for the other node to start
	timer:sleep(1000),
	true = net_kernel:connect_node(Other),

	P = shf(seq(len(Msg))),
	ok = case Init of
		false -> listen({app, Other}, Msg, Key, false);
		_ -> speak({app, Other}, Msg, Key, P, false)
	end.