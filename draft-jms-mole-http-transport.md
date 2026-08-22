---
title: "MoLE HTTP Transport"
abbrev: "MoLE HTTP Transport"
category: info

docname: draft-jms-mole-http-transport-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - moderation
 - endorsement
 - unlinkability
 - privacy
venue:
#  group: "Anti-Fraud Community Group"
#  type: "Community Group"
#  mail: "public-antifraud@w3.org"
#  arch: "https://lists.w3.org/Archives/Public/public-antifraud/"
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-http-transport.html"

author:
 -
    fullname: Samuel Schlesinger
    organization: Google LLC
    email: sgschlesinger@gmail.com
 -
    fullname: Dennis Jackson
    organization: Mozilla
    email: ietf@dennis-jackson.uk
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: ot-ietf@thibault.uk

normative:
  BASE64: RFC4648
  CACHING: RFC9111
  HTTP: RFC9110
  ORIGIN: RFC6454
  PROTOCOLS: #I-D.draft-jms-mole-protocols
    title: MoLE Protocols
    target: https://datatracker.ietf.org/doc/draft-jms-mole-protocols/00/
  QUIC: RFC9000
  SHA2: RFC6234
  STRUCTURED-FIELDS: RFC9651
  TLS13: RFC8446

informative:
  BCP56: RFC9205

...

--- abstract

MoLE targets browser deployments, so Clients, Anchors, and Moderators need
an HTTP transport for the protocol flows defined by the architecture.

This document defines the `Mole` HTTP authentication scheme, which carries
challenges and presentations for the endorsement and credential flows, and
the headers used to return credential material. The grant exchanges with
the Anchor are defined per protocol in {{PROTOCOLS}}.


--- middle

# Introduction

MoLE separates the decision to grant an Endorsement from authorization at a
Moderator.  A Client obtains the grant before accessing a protected resource.
When challenged by a Moderator, the Client either redeems that Endorsement and
requests a Credential, or presents an existing Credential.  In both cases, the
proof in `Authorization` authorizes the request that carries it.  The response
can return newly issued or updated credential material.

This document follows the HTTP authentication framework and the guidance for
building protocols with HTTP in {{BCP56}}.  It does not define browser APIs.

# Terminology

{::boilerplate bcp14-tagged}

# Presentation Language

This document uses the TLS presentation language {{TLS13}} to describe the
structure of protocol messages.  In addition to the base syntax, it uses
variable-size vector length headers.

## Variable-Size Vector Length Headers

In the TLS presentation language, vectors are encoded as a sequence of encoded
elements prefixed with a length.  The length field has a fixed size set by
specifying the minimum and maximum lengths of the encoded sequence of elements.

In this document, there are several vectors whose sizes vary over significant
ranges.  So instead of using a fixed-size length field, it uses a variable-size
length using a variable-length integer encoding based on the one described in
{{Section 16 of QUIC}}. They differ only in that the one here requires a
minimum-size encoding. Instead of presenting min and max values, the vector
description simply includes a `V`. For example:

~~~ tls-presentation
struct {
    uint32 fixed<0..255>;
    opaque variable<V>;
} StructWithVectors;
~~~

# HTTP Authentication Scheme {#http-authentication-scheme}

The `Mole` authentication scheme follows the HTTP authentication framework in
{{Section 11 of HTTP}}.  It carries Moderator challenges and either Endorsement
redemptions or Credential presentations.  Grant exchanges with an Anchor are
outside this authentication scheme and are defined by the endorsement protocol
in {{PROTOCOLS}}.

~~~ aasvg
+--------+                                +-----------+
| Client |                                | Moderator |
+---+----+                                +-----+-----+
    |                                           |
    |<--- WWW-Authenticate: Mole challenge= -----+
    |                                           |
 (select a prefetched Endorsement or Credential)|
    |                                           |
    +--- Authorization: Mole ... ---------------->|
    |                                           |
    |<----------------------- Mole-Credential --+
    |                                           |
~~~

A Moderator challenge describes exactly one flow.  A `redeem` challenge names
one Endorsement type and one Credential type.  A `present` challenge names one
Credential type.  To offer alternatives, a Moderator sends multiple `Mole`
challenges.  A Client selects one challenge for which it has the required
prefetched Endorsement or Credential and supports all named types.  Challenge
order does not express preference.  A Client MUST ignore an unusable challenge
and MUST NOT combine parameters from different challenges.

All base64url values in this document are encoded without padding
({{BASE64}}).

## Authentication Parameter Parsing

The syntax of a `Mole` challenge and credentials is the `auth-param` syntax in
{{HTTP}}.  Parameter names are case-insensitive.  The values of `flow`,
`challenge`, `credential-request`, `presentation`, and `realm` MUST use the
quoted-string form.  After quoted-string processing, proof and challenge values
MUST be valid unpadded base64url and MUST decode to the structure required by
the selected flow.

A challenge MUST contain exactly one `flow` parameter and exactly one
`challenge` parameter.  The `flow` value is either `redeem` or `present`.  It
MAY contain one `realm` parameter.  A Client MUST ignore unknown challenge
parameters so that the scheme can evolve.  It MUST treat a challenge as
unusable if parsing fails, any parameter name is duplicated, required
parameters are missing, the `flow` value is unknown, or a known value is
malformed.

An `Authorization` value using `Mole` MUST contain exactly one `challenge`
parameter, copied byte-for-byte from the selected challenge, and exactly one of
`credential-request` or `presentation`, matching its flow.  It MUST NOT contain
`flow` or `realm`.  A Moderator MUST reject Mole credentials containing an
unknown or duplicate parameter, both proof parameters, no proof parameter, a
missing or changed challenge, an invalid encoding, or a structure that does not
consume the complete decoded value.  These conditions make the credentials
malformed; they are not alternate interpretations of the request.  Receiving
more than one `Authorization` field containing Mole credentials is also
malformed.

The `realm` parameter is present only for compatibility with the HTTP
authentication framework.  Its value has no MoLE security, policy, routing, or
cache-partitioning semantics.  Clients MUST NOT use it for challenge selection
or Credential reuse.

# Configuration

Anchors and Moderators publish configuration used by Clients before
running the HTTP authentication flows. Configuration includes endpoint URLs,
supported protocol types, public key material, and the Anchor set associated
with each Moderator policy. Its contents and format are defined in the Key
Rotation and Discovery section of {{PROTOCOLS}}.

Each endpoint configuration MUST also advertise
`max_mole_field_value_size`, a positive integer giving the largest encoded
field value, in octets, that the endpoint will send or accept for this binding.
Moderator configuration MUST advertise `max_request_retry_interval`, the
number of seconds for which an exact request retry can recover an authentication
result after first processing.
The limit is measured before field parsing, base64 decoding, allocation based
on decoded lengths, or cryptographic processing.  A sender MUST NOT generate a
Mole field value larger than the peer's advertised limit.  A Client that cannot
produce a proof within the limit MUST decline the challenge.  A recipient MUST
reject an oversized field before decoding or cryptographic processing; a
Moderator SHOULD use 431 (Request Header Fields Too Large) for an oversized
request.  A protocol instance whose encoded messages exceed the advertised
limit cannot use this HTTP binding.

The limit applies to the uncompressed field value.  Implementations MUST NOT
rely on HTTP/2 or HTTP/3 field compression, trailers, or fragmentation to meet
it.

> **EDITOR'S NOTE:** The configuration format is still defined as an open
> item in {{PROTOCOLS}}.  The exact interoperable minimum or maximum for
> `max_mole_field_value_size`, and carriage for large proofs (including browser
> WebAPI carriage), remain unresolved and are out of scope for this version.
> This document intentionally does not define a POST upload,
> reference, trailer, or fragmented alternative.

# Protected Request Flow

The flow begins when a Client makes a request without Mole credentials and the
Moderator returns a `Mole` challenge.  A 401 (Unauthorized) response means that
authentication is required before the request can be served.  A successful
response MAY advertise a challenge when Mole is optional, but that challenge
authorizes only a repeat of the request identified in its binding. A successful
response MUST NOT carry a Mole challenge for an unsafe method unless the
application provides idempotency for the repeated request.

After selecting a challenge, the Client retries the request with one
`Authorization: Mole` field.  For `redeem`, the field carries a
`CredentialRequest`; for `present`, it carries a `CredentialPresentation`.
Successful verification authorizes that same request under the policy in the
challenge.  It does not authorize a session, a redirected request, or another
request. When authentication is required, the Moderator processes the protected
operation only after successful verification. An optional challenge on a
successful response instead applies only to a later repeat.

The Endorsement grant used by `redeem` MUST have been obtained before the
Moderator's challenge.  The Client MUST NOT send the challenge, or any value
derived from it, to an Anchor.  Thus, the flow requires no Anchor availability
or challenge-dependent Anchor activity on the protected-request path.

The response to an authorized `redeem` request MAY contain the corresponding
`CredentialResponse`.  The response to an authorized `present` request MAY
contain an update.  Both use `Mole-Credential` as defined in
{{mole-credential}}.  Authorization of the request and issuance of credential
material are distinct results: an otherwise successful response without
`Mole-Credential` authorizes the operation but supplies no new Credential.

> **EDITOR'S NOTE:** HTTP authentication requires repeating the challenged
> request.  Repeating a non-idempotent request can duplicate application
> effects when the outcome is lost or intermediaries retry it.  This document
> does not yet define a general mechanism that makes destructive methods safe.
> Applications need to restrict Mole challenge/retry to methods they can safely
> repeat, or supply their own idempotency mechanism.  Resolving this method and
> retry tension remains open.

## Challenge Binding

Every Moderator challenge contains a `RequestBinding`:

~~~tls-presentation
struct {
  opaque moderator_origin<V>;
  opaque request_method<V>;
  opaque target_uri<V>;
  opaque content_digest[32];
  opaque content_type<V>;
  opaque content_encoding<V>;
  opaque policy_context<V>;
  uint64 issued_at;
  uint64 expires_at;
  opaque nonce[32];
} RequestBinding;
~~~

`moderator_origin` is the ASCII serialization of the Moderator's origin as
defined by {{ORIGIN}}.  `request_method` is the case-sensitive method token and
`target_uri` is the absolute target URI reconstructed by the Moderator under
{{HTTP}}. `content_digest` is SHA-256 over the request content octets, including
the zero-length sequence when the request has no content. `content_type` and
`content_encoding` are the field values after HTTP field parsing, or empty when
the corresponding field is absent. A request with multiple values is outside
this binding. `policy_context` identifies the exact policy and key-configuration
version. `issued_at` and
`expires_at` are seconds since the Unix epoch; `expires_at` MUST be later than
`issued_at`.  `nonce` MUST be unpredictable and unique for challenges issued by
the same Moderator. Header fields other than `Authorization` are not covered;
a Moderator MUST NOT make its Mole authorization decision or protected
operation depend on an unbound request field unless the application binds that
field separately.

A Moderator MUST establish, by exact lookup keyed by `nonce` or by an
authenticated stateless encoding, that it issued the byte-identical complete
challenge. It MUST verify all binding fields before cryptographic processing
and MUST reject a new operation if the challenge is expired, is not yet valid
under the Moderator's allowed clock skew, or does not match the request's
origin, method, target URI, content, policy, types, and current key
configuration. Exact-retry lookup is performed before freshness rejection as
specified in {{replay}}. The complete encoded challenge, including the binding,
MUST be covered by the type-specific challenge digest or proof when the profile
defines one. A bearer profile that cannot provide that coverage MUST document
the weaker property and its replay protection in {{PROTOCOLS}}.

A Client MUST use a challenge only for the request it identifies and MUST NOT
send Mole credentials preemptively based on an earlier challenge, an HTTP
authentication cache, `realm`, or success at another resource.  A cached
Credential can be selected only after receiving a fresh applicable challenge.
The exact lost-response retry in {{replay}} is the sole exception: it repeats
the same credentials and byte-identical challenge rather than starting a new
operation.

For `redeem`, the challenge value encodes:

~~~tls-presentation
struct {
  uint16 endorsement_type;
  uint16 credential_type;
  RequestBinding binding;
  opaque challenge<V>;
} ModeratorChallenge;
~~~

The `challenge` field carries the `Challenge` structure of the named
endorsement type, defined in {{PROTOCOLS}}.

~~~
WWW-Authenticate: Mole flow="redeem", challenge="<moderator-challenge>", realm="example"
~~~

The Client answers with a `CredentialRequest` ({{PROTOCOLS}}) in the
`Authorization` field.  It carries the Endorsement redemption bound to this
challenge and the Credential issuance request.

~~~
Authorization: Mole challenge="<moderator-challenge>", credential-request="<credential-request>"
~~~

For `present`, the challenge value encodes:

~~~tls-presentation
struct {
  uint16 credential_type;
  RequestBinding binding;
  opaque challenge<V>;
} CredentialChallenge;
~~~

The `challenge` field carries the `Challenge` structure of the named
credential type, defined in {{PROTOCOLS}}.

~~~
WWW-Authenticate: Mole flow="present", challenge="<credential-challenge>", realm="example"
~~~

~~~tls-presentation
struct {
  uint16 credential_type;
  opaque credential_presentation<V>;
} CredentialPresentation;
~~~

The `credential_presentation` field carries the type-specific
`CredentialPresentation` value defined by {{PROTOCOLS}}.

~~~
Authorization: Mole challenge="<credential-challenge>", presentation="<credential-presentation>"
~~~

A complete instantiation example is given in the appendix of
{{PROTOCOLS}}.

Each credential type MUST define the challenge fields that partition cached
Credentials, or state that Credentials of that type are not cacheable.

## Credential Response Field {#mole-credential}

`Mole-Credential` is an RFC 9651 Dictionary Structured Header Field. It MUST
NOT be carried in a trailer section. It has two defined members:

* `response` is a Byte Sequence containing a complete `CredentialResponse`
  from {{PROTOCOLS}}; and
* `update` is a Byte Sequence containing a complete `CredentialResponse` for
  the selected Credential type.

Exactly one of `response` and `update` MUST be present.  `response` is valid
only after `credential-request`, and `update` is valid only after
`presentation`.  Unknown Dictionary members MUST be ignored.  A recipient MUST
discard the entire field as malformed if Structured Field parsing fails, a
known member has parameters, a known member is not a Byte Sequence, both known
members are present, or no known member is present.

~~~
Mole-Credential: response=:AAECAw==:
~~~

or, in a different response:

~~~
Mole-Credential: update=:BAUGBw==:
~~~

Absence of `Mole-Credential` after a presentation means that no replacement
Credential was issued.  The Client MUST consider the presented Credential
spent unless the selected Credential protocol explicitly specifies otherwise.
An empty Byte Sequence is an actual zero-length protocol value; it does not
mean absence.  Absence after redemption means that no Credential was issued.

## Replay, Lost Responses, and Distribution {#replay}

A Moderator MUST accept each challenge nonce at most once for a new operation.
Challenge consumption, Endorsement nullifier or Credential-spend recording,
the authentication decision, and creation of any `Mole-Credential` value MUST
be one atomic authentication operation. The Moderator MUST retain an
idempotency record through at least `max_request_retry_interval` after first
processing.

An exact retry containing the same challenge-bound `Authorization` value MUST
return the recorded authentication result and the same `Mole-Credential` value,
if any, without repeating redemption, spend, issuance, or update. This binding
does not provide exactly-once execution of the protected operation; its retry
follows normal HTTP and application semantics. A different proof using an
already consumed challenge MUST be rejected. A Client that loses a response MAY
make an exact retry only when repeating the HTTP request is safe under HTTP
semantics or the application provides idempotency. Otherwise, it MUST treat the
result as indeterminate and MUST NOT reuse the proof with another request.

All instances representing the same Moderator MUST use an atomic shared replay
and idempotency store, including instances in different regions or failure
domains.  The identity of a Moderator is established by its configured origin,
policy namespace, and cryptographic key material, not by a particular process.
Different Moderators do not coordinate replay state; origin and policy binding
prevent a proof accepted by one from being used at another.

# HTTP Processing

## Status Codes and Errors

A Moderator uses HTTP status codes according to their generic semantics.  It
MUST NOT treat an unrecognized status code as a MoLE protocol signal.  Clients
MUST handle unrecognized status codes according to their status class, as
specified by {{HTTP}}.

A syntactically malformed Mole `Authorization` field is a malformed request,
for which 400 (Bad Request) is appropriate.  Invalid, expired, replayed, or
otherwise unacceptable credentials normally result in 401 (Unauthorized) with
a fresh applicable challenge.  When valid credentials were understood but are
insufficient under policy, 403 (Forbidden) is appropriate.  Oversized request
fields are handled as specified in {{configuration}}.  Server failures use an
applicable 5xx status code.  These mappings do not redefine those status codes
or prevent use of other applicable status codes.  More detailed errors, when
safe to disclose, belong in response content rather than new status semantics.

## Redirects

A Client MUST NOT copy or reuse a Mole `Authorization` field while following a
redirect, even when the redirect target has the same origin.  The target URI is
different and therefore the proof is not valid for it.  The Client follows the
redirect according to {{HTTP}}, without Mole credentials, and obtains a fresh
challenge from the target resource.  It MUST NOT send Mole credentials to a
different origin.  A 301 or 302 redirect can change POST to GET, and 307 or 308
can repeat a request; applications need to account for those method semantics
and the retry limitation in {{protected-request-flow}}.

## Caching

A response containing `Mole-Credential`, or a challenge containing a
client-specific or request-specific binding, MUST contain `Cache-Control:
no-store`.  `no-cache` is not a substitute.  Other responses to requests with
Mole credentials are governed by {{CACHING}}, including its rules for responses
to requests containing `Authorization`; applications SHOULD use `no-store`
when the representation or authorization result is client-specific.

# Complete Examples

The values below are complete HTTP exchanges with structurally valid transport
wrappers, not valid ACT or Privacy Pass profile inputs and not type-specific
cryptographic test vectors. They use an issue time
of 2026-08-22 00:00:00 UTC, a 60-second lifetime, and illustrative opaque
type-specific values.  The line beginning with `...` represents the protected
response content.

## Redeem and Issue

~~~http-message
GET /p HTTP/1.1
Host: m.example

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Mole flow="redeem", challenge="AAEAARFodHRwczovL20uZXhhbXBsZQNHRVQTaHR0cHM6Ly9tLmV4YW1wbGUvcOOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVAAABcAAAAABqiOaAAAAAAGqI5rwAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwA", realm="example"
Cache-Control: no-store
Content-Length: 0

GET /p HTTP/1.1
Host: m.example
Authorization: Mole challenge="AAEAARFodHRwczovL20uZXhhbXBsZQNHRVQTaHR0cHM6Ly9tLmV4YW1wbGUvcOOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVAAABcAAAAABqiOaAAAAAAGqI5rwAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwA", credential-request="AAEAAAEA"

HTTP/1.1 200 OK
Cache-Control: no-store
Mole-Credential: response=:AAEA:
Content-Type: text/plain
Content-Length: 3

...
~~~

## Present and Update

~~~http-message
PUT /o HTTP/1.1
Host: m.example
Content-Type: application/octet-stream
Content-Length: 2

hi

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Mole flow="present", challenge="AAIRaHR0cHM6Ly9tLmV4YW1wbGUDUFVUE2h0dHBzOi8vbS5leGFtcGxlL2-PQ0NGZI9rlt-J3akBxRdrEKbYOWHdPBrIi1my3DJ6pBhhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0AAW8AAAAAaojmgAAAAABqiOa8AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A", realm="example"
Cache-Control: no-store
Content-Length: 0

PUT /o HTTP/1.1
Host: m.example
Authorization: Mole challenge="AAIRaHR0cHM6Ly9tLmV4YW1wbGUDUFVUE2h0dHBzOi8vbS5leGFtcGxlL2-PQ0NGZI9rlt-J3akBxRdrEKbYOWHdPBrIi1my3DJ6pBhhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0AAW8AAAAAaojmgAAAAABqiOa8AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A", presentation="AAIA"
Content-Type: application/octet-stream
Content-Length: 2

hi

HTTP/1.1 204 No Content
Cache-Control: no-store
Mole-Credential: update=:AAIA:
~~~

# Security Considerations

All exchanges defined in this document MUST use `https` URIs.  Clients MUST
authenticate the server by validating its TLS certificate according to
{{Section 4.3.4 of HTTP}}.  Disabling certificate or hostname validation is not
permitted.

Mole credentials and credential responses are bearer-like, client-specific
security material at the HTTP layer.  TLS protects them only between TLS
endpoints.  Reverse proxies, gateways, debuggers, and server components that
terminate TLS can observe them.  Deployments MUST limit access to this material
and MUST NOT record it in logs, traces, analytics, error reports, or URLs.
Clients MUST store Endorsements, Credentials, and updates with protection
appropriate to their value and MUST scope them to the configured Moderator
origin, policy, types, and key material.

Request, origin, policy, and freshness binding limits replay but does not
replace atomic spend and nullifier tracking.  The shared-state requirements in
{{replay}} apply whenever a Moderator is
distributed.  Separate Moderators intentionally have no shared replay store.

Redirect handling prevents disclosure to another resource or origin.  The
field-size limit reduces memory-exhaustion and cryptographic denial-of-service
risk only if enforced before decoding, allocation, and cryptographic work.


# IANA Considerations

## Authentication Scheme

This document registers the `Mole` authentication scheme, as defined in
{{http-authentication-scheme}}, in the "HTTP Authentication Schemes"
registry.

* Authentication Scheme Name: Mole
* Reference: This document
* Notes: Carries challenge-bound MoLE Endorsement redemptions and Credential
  presentations.

## HTTP Field Names

This document registers the `Mole-Credential` field name in the
"Hypertext Transfer Protocol (HTTP) Field Name Registry".

* Field Name: Mole-Credential
* Status: permanent
* Structured Type: Dictionary
* Reference: This document
* Comments: Response field carrying MoLE Credential issuance or update
  material.

Endorsement and credential type values are registered in {{PROTOCOLS}}, not
in this document.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
