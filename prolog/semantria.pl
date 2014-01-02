:- module(semantria, [ request/3
                     ]).

:- use_module(library(base64), [base64/2]).
:- use_module(library(func)).
:- use_module(library(http/http_open), [http_open/3]).
:- use_module(library(http/http_ssl_plugin)).
:- use_module(library(http/json), [json_read/2]).
:- use_module(library(interpolate)).
:- use_module(library(random), [random_between/3]).
:- use_module(library(readutil), [read_stream_to_codes/2]).
:- use_module(library(sha), [hmac_sha/4]).
:- use_module(library(uri), [uri_encoded/3]).
:- use_module(library(uri_qq)).

%% consumer_key(Key:text)
%
%  Add a clause to this predicate to specify your Semantria
%  API "consumer key".
:- multifile consumer_key/1.
:- dynamic consumer_key/1.

%% secret_key_md5(MD5:text)
%
%  Add a clause to this predicate to specify the MD5 hash of your
%  Semantria API "secret key". The hash should use lower case
%  hexadecimal encoding.
%
%  This hack is necessary because SWI Prolog doesn't seem to have a good
%  MD5 implementation. Run `md5sum $secret_key` at a command prompt to
%  get the value you need.
:- multifile secret_key_md5/1.
:- dynamic secret_key_md5/1.


% the base URL for all API requests to Semantria
api_base('https://api35.semantria.com/').


%% request(+Method, +Path, Response:dict)
%
%  Makes a Method request to Semantria at Path.  For example,
%
%      ?- request(get, status, R).
%      R = semantria{api_version:"3.5", ...} .
request(Method, Path, Response) :-
    sign_request('$Path.json', _{}, Url, Auth),
    http_open( Url
             , Stream
             , [ method(Method)
               , request_header(authorization=Auth)
               ]
             ),
    json_read(Stream, json(PairsEq)),
    maplist(eq_dash, PairsEq, Pairs),
    dict_pairs(Response, Path, Pairs).

eq_dash(K=V,K-V).


% generate the URL and Authorization header that's needed for making
% requests to Semantria. documentation for this process is available
% at https://semantria.com/developer The written docs are somewhat poor,
% so it's best to consult the various SDKs and their source code to
% resolve questions.
sign_request(Path, Params0, Url, Authorization) :-
    % preliminaries
    api_base(Base),
    nonce(Nonce),
    now(Now),

    % build "Signature Base String"
    Extra = [ oauth_consumer_key=consumer_key(~)
            , oauth_nonce=Nonce
            , oauth_signature_method="HMAC-SHA1"
            , oauth_timestamp=Now
            , oauth_version=1.0
            ],
    put_dict(Extra, Params0, Params),
    Url = {|uri(Base)||$Path?$Params|},

    % build HMAC-SHA1 signature
    secret_key_md5(Key),
    hmac_sha(Key, uri_encode $ Url, SignatureBytes, [algorithm(sha1)]),
    base64(atom_codes(~,SignatureBytes), Signature64),
    uri_encode(Signature64, Signature),

    % build Authorization header
    authorization_header([ oauth_signature=Signature
                         | Extra
                         ]
                        , Authorization
                        ).


% comma-separated Authorization header
authorization_header(Values, Header) :-
    maplist(quote_headerval, Values, Parts),
    atomic_list_concat(Parts, ', ', PartialHeader),
    Header = 'OAuth, ~s' $ PartialHeader.

quote_headerval(Key=Value,Auth) :-
    Auth = '~s="~w"' $ [Key,Value].


% generate a large random integer
nonce(Nonce) :-
    random_between(1,18_446_744_073_709_551_616,Nonce).


% current time in integer seconds since the epoch
now(T) :-
    get_time(Tfloat),
    T is round(Tfloat).


% encode URI values as Semantria expects.
% uri_encoded/3 doesn't encode :, / or ? characters.
uri_encode(Value, Encoded) :-
    uri_encoded(query_value, Value, E0),
    atom_codes(E0, E1),
    once(phrase(enc, E1, E2)),
    atom_codes(Encoded, E2).

enc, "%3A" --> ":", enc.
enc, "%2F" --> "/", enc.
enc, "%3F" --> "?", enc.
enc, [C] --> [C], enc.
enc --> { true }.
