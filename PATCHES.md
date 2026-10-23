# Boundless patches

The `main` branch mirrors upstream, which is https://codeberg.org/dequbed/rsasl;
the GitHub repository dequbed/rsasl is archived and no longer updated.
Boundless's required changes live on `boundless`, based on upstream rsasl
2.3.1 (`ee7065d92976ceb1fc1b0c27545f8a816e3de166`).

## Short SCRAM server attributes return parse errors

A peer's empty or one-byte server-final attribute panics when its prefix is
sliced. Server-first guards its nonce attribute but slices a short salt or
iteration attribute before checking the nonce. Boundless's client runs these
parsers for every supported SCRAM mechanism through its shared SASL exchange.

The private `next_server_attribute` reader returns a fixed two-byte prefix and
its value, or `ParseError::MissingAttributes`. Both server-message parsers use
it for every attribute they inspect. Attribute order, mandatory-extension
handling, optional extensions and valid verifier/error messages keep their
existing behavior. No Boundless-side parser or panic recovery is added.
This follows the guarded attribute reading in PostgreSQL's
[`read_attr_value`](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/interfaces/libpq/fe-auth-scram.c).

Regression tests in `src/mechanisms/scram/parser.rs`:

- `short_server_first_attributes_are_parse_errors`: empty and one-byte nonce,
  salt and iteration attributes, including `r=x,,i=4096` and `,x=long`.
- `short_server_final_attributes_are_parse_errors`: empty and one-byte
  server-final attributes, including a leading empty attribute before `x=long`.

The tests reproduce parser panics on the unchanged upstream implementation.
Boundless additionally tests all five supported SCRAM mechanisms through
`protocols::sasl::tests::scram_short_server_attributes_are_peer_parse_failures`:
these inputs return `protocol_response_invalid` and the public authentication
outcome through the ordinary shared failure conversion.
