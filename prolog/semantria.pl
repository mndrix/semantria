:- module(semantria, [ queue_document/2
                     , request_document/2
                     , request/3
                     ]).

:- use_module(library(base64), [base64/2]).
:- use_module(library(error), [must_be/2]).
:- use_module(library(func)).
:- use_module(library(http/http_header)).  % needed for POST requests
:- use_module(library(http/http_open), [http_open/3]).
:- use_module(library(http/http_ssl_plugin)).
:- use_module(library(http/json), [atom_json_term/3, json_read/2]).
:- use_module(library(random), [random_between/3]).
:- use_module(library(readutil), [read_stream_to_codes/2]).
:- use_module(library(sha), [hash_atom/2, hmac_sha/4, sha_hash/3]).
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


%% queue_document(+Document:string, ?Id:string) is det.
%
%  Add Document to Semantria's queue for processing. If Id is ground,
%  use that as the document's Id; otherwise, bind Id to a hash of
%  Document.
queue_document(Document, Id) :-
    % prepare arguments
    must_be(string, Document),
    document_id(Document, Id),

    % submit document to Semantria
    Details = _{ id: Id, text: Document },
    request(post(Details), document, _).

document_id(_, Id) :-
    ground(Id),
    !.
document_id(Document, Id) :-
    sha_hash(Document,HashBytes,[]),
    hash_atom(HashBytes, IdLong),
    sub_atom(IdLong, 0, 32, _, IdShort),  % 32 char max per API docs
    atom_string(IdShort, Id).




%% request_document(+Id:string, -Response:dict)
%
%  Request a Semantria document.
request_document(Id, Response) :-
    request(get, document/Id, Response).


%% request(+Method, +Path, Response:dict)
%
%  Makes a Method request to Semantria at Path.  For example,
%
%      ?- request(get, status, R).
%      R = semantria{api_version:"3.5", ...} .
%
%  For a POST request, make `Method=post(Dict)`. The Dict is converted
%  into a JSON object and included as the request body.
request(Method, Path, Response) :-
    sign_request('~w.json' $ Path, _{}, Url, Auth),
    debug(semantria, "request URL: ~s~n", [Url]),
    request_open(Method, Url, Auth, Stream),
    json_read(Stream, Json),
    json_to_dict(Json, Response).

request_open(get, Url, Auth, Stream) :-
    http_open( Url
             , Stream
             , [ method(get)
               , request_header(authorization=Auth)
               ]
             ).
request_open(post(Dict), Url, Auth, Stream) :-
    % convert Dict to JSON
    dict_pairs(Dict, json, Pairs0),
    maplist(eq_dash, Pairs, Pairs0),
    atom_json_term(Json, json(Pairs), [as(atom)]),
    debug(semantria, "request JSON body: ~s~n", [Json]),

    % POST JSON to Semantria
    http_open( Url
             , Stream
             , [ post(atom(application/json, Json))
               , request_header(authorization=Auth)
               , status_code(_)
               ]
             ).


eq_dash(K=V,K-V).


json_to_dict(json(EqPairs), Dict) :-
    !,
    maplist(json_pair, EqPairs, DashPairs),
    dict_pairs(Dict, _, DashPairs).
json_to_dict(Term, Term).

json_pair(Key=Value0, Key-Value) :-
    ( atom(Value0) ->
        atom_string(Value0, Value)
    ; Value0=json(_) ->
        json_to_dict(Value0, Value)
    ; is_list(Value0) ->
        maplist(json_to_dict, Value0, Value)
    ; true ->
        Value = Value0
    ).


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
