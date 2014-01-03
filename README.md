# Synopsis

    :- use_module(library(semantria)).

    % provide Semantria API credentials
    :- multifile semantria:consumer_key/1,
                 semantria:secret_key_md5/1.
    semantria:consumer_key("...").
    semantria:secret_key_md5("...").

    main :-
        process_document("When in the course ...", R),
        format("Sentiment: ~s~n", [R.sentiment_polarity]).

# Description

A thin wrapper around the [Semantria API](https://semantria.com/) for natural language processing.

# Changes in this Version

  * First public release

# Installation

Using SWI-Prolog 7.1 or later:

    ?- pack_install(semantria).

This module uses [semantic versioning](http://semver.org/).

Source code available and pull requests accepted at
http://github.com/mndrix/semantria

@author Michael Hendricks <michael@ndrix.org>
@license BSD
