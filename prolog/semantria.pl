:- module(semantria, [ process_document/2
                     , queue_document/2
                     , request_document/2
                     , request/3
                     ]).

:- use_module(library(base64), [base64/2]).
:- use_module(library(condition)).
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


%% process_document(+Document:string, -Response:dict)
%
%  Queue Document for processing and block until a Response is
%  available. This predicate is a synchronous convenience on
%  top of Semantria's asynchronous API.
%  A document ID is generated based on the
%  document's content. Calling process_document/2 on a document that
%  has already been processed returns immediately (using results cached
%  on Semantria's server).
process_document(Document, Response) :-
    document_id(Document, Id),
    process_document_(Document, Id, 10, Response).

process_document_(_, Id, Tries, Response) :-
    handle( request_document(Id, Response0)
          , error(_,context(_,status(404,_)))
          , fail
          ),
    !,
    Status = Response0.status,
    ( Status == "PROCESSED" ->
        Response = Response0
    ; Status == "QUEUED" ->
        poll_document(Id, Tries, Response)
    ; Status == "FAILED" ->
        throw("Semantria document processing failed")
    ; % otherwise ->
        must_be(one_of(["PROCESSED","QUEUED","FAILED"]), Status)
    ).
process_document_(Document, Id, Tries, Response) :-
    queue_document(Document, Id),
    process_document_(Document, Id, Tries, Response).

poll_document(Id, Tries0, Response) :-
    sleep(1),  % give Semantria a chance to finish its work
    Tries is Tries0 - 1,
    ( Tries =< 0 -> throw("Too many retries") ; true ),
    process_document_(_, Id, Tries, Response).

%% queue_document(+Document:string, ?Id:string) is det.
%
%  Add Document to Semantria's queue for processing. If Id is ground,
%  use that as the document's Id; otherwise, bind Id to a unique
%  identifier for Document. Generated identifiers are guaranteed to be
%  stable across invocations.
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
%  Request details about an already-queued document with Id. This
%  predicate is usually called after calling queue_document/2.
request_document(Id, Response) :-
    request(get, document/Id, Response).


%% request(+Method, +Path, Response:dict)
%
%  Low-level predicate for making authenticated API calls. Method
%  specifies the HTTP method. Path indicates the path. It can be an
%  atom or a term (like `document/some_document_id`). For example,
%
%      ?- request(get, status, R).
%      R = _{api_version:"3.5", ...} .
%
%  For a POST request, make `Method=post(Dict)`. The Dict is converted
%  into a JSON object and included as the request body.
request(Method, Path, Response) :-
    sign_request('~w.json' $ Path, _{}, Url, Auth),
    debug(semantria, "request URL: ~s~n", [Url]),
    catch( request_open(Method, Url, Auth, Stream)
         , E
         , failable_exception(E)
         ),
    json_read(Stream, Json),
    json_to_dict(Json, Response).

request_open(get, Url, Auth, Stream) :-
    http_open( Url
             , Stream
             , [ method(get)
               , request_header(authorization=Auth)
               , cert_verify_hook(ssl_verify)
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
               , status_code(202)
               , cert_verify_hook(ssl_verify)
               ]
             ).


eq_dash(K=V,K-V).


% accept all SSL certificates
ssl_verify( _SSL
          , _ProblemCertificate
          , _AllCertificates
          , _FirstCertificate
          , _Error
          ).


% convert an exception into a signal which can either fail or rethrow.
% this is convenient for converting predicates that throw exceptions
% into predicates that raise signals.
% maybe it'd be convenient to have call_signal/2 which is like call/1
% but automatically uses this predicate to convert exceptions into
% signals.
failable_exception(E) :-
    ( signal(E, Restart) ->
        ( Restart == fail ->
            fail
        ; % unexpected restart ->
            must_be(one_of([fail]), Restart)
        )
    ; % signal not handled ->
        throw(E)
    ).



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
