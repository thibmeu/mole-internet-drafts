---
title: "Issuer Hiding for Publicly Verifiable Privacy Pass Tokens"
abbrev: "Privacy Pass Issuer Hiding"
category: info

docname: draft-meunier-privacypass-issuer-hiding-latest
submissiontype: IETF
number:
date:
consensus: false
v: 3
keyword:
 - privacy pass
 - issuer hiding
 - unlinkability
venue:
  github: "Moderation-of-unLinkable-Endorsements/internet-drafts"
  latest: "https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-meunier-privacypass-issuer-hiding.html"

author:
 -
    fullname: Thibault Meunier
    organization: Cloudflare
    email: ot-ietf@thibault.uk

normative:
  RFC9576:
  RFC9577:
  RFC9578:

informative:
  MOLE-ARCHITECTURE: I-D.draft-jms-mole-architecture
  MOLE-PROTOCOLS: I-D.draft-jms-mole-protocols

...

--- abstract

Some applications need publicly verifiable, Privacy Pass-shaped tokens while
allowing a verifier to trust more than one issuer.  Revealing which issuer
produced a token can disclose the relationship or policy under which the
client qualified.  In these applications, issuer hiding is a mandatory
property rather than an optional optimization.

This document describes that use case and a methodology for identifying such
token types.  It does not define a cryptographic scheme, wire format, or IANA
registration.

--- middle

# Introduction

Privacy Pass separates attestation, issuance, and redemption so that an
Origin does not learn the Client's attestation context {{RFC9576}}.  Publicly
verifiable tokens allow an Origin to verify a token using an Issuer Public
Key, without sharing an Issuer secret {{RFC9578}}.

An Origin can accept several Issuers.  With existing publicly verifiable
tokens, however, the verifying key identifies the Issuer.  The Origin can
therefore learn which relationship or policy caused the Client to receive a
token.  Merely permitting an issuer-hiding mode is insufficient when Origins
or intermediaries can request a non-hiding presentation instead.

This document describes applications in which the token protocol needs to
make issuer hiding mandatory.  The verifier selects an acceptable issuer set,
and learns only that the token was issued under one key in that set.  The
document deliberately stops before selecting a construction or defining how
the set is represented.

# Use Case

Consider a service that accepts evidence from several independent providers.
One provider might have an account relationship with a Client, another might
have observed a scarce action, and another might enforce a different abuse
policy.  The service chooses which providers it trusts, but does not need to
know which provider vouched for a particular Client.

Using a single shared Issuer can hide this distinction, but requires the
providers and service to coordinate issuance policy and key operation.  It
also creates centralization pressure of the kind discussed in
{{Section 5.2 of RFC9576}}.  Giving every provider a distinct publicly
verifiable key avoids that coordination, but ordinary verification reveals
the provider and can partition Clients into smaller anonymity sets.

The required result is therefore a publicly verifiable token for which:

* the verifier chooses an acceptable set of Issuer Public Keys;
* successful verification proves issuance under one key in that set;
* verification does not reveal which key was used; and
* the protocol does not offer a verifier-selectable non-hiding presentation
  for the same use case.

The accepted set is policy, not an assertion that all Issuers are equivalent.
The verifier remains responsible for selecting Issuers whose issuance
policies are acceptable for the resource being protected.

This requirement is similar to Anchor hiding in the MoLE architecture
{{MOLE-ARCHITECTURE}}.  A Privacy Pass-shaped token satisfying it could be
used as a MoLE Endorsement.  That observation does not make every MoLE
Endorsement a Privacy Pass token.

# Applicability Requirements

Issuer hiding is applicable when issuer identity carries information that the
verifier does not need for its authorization decision.  A specification for
such a token type needs to state:

1. how the verifier determines the acceptable issuer set;
2. the issuer-hiding property provided within that set;
3. whether issuance, redemption, or auxiliary messages expose the issuer;
4. how set changes and key rotation affect anonymity sets; and
5. which parties and collusions are covered by the privacy claim.

Issuer hiding does not make a poorly chosen set private.  A singleton set
reveals the Issuer, and a set tailored to one Client can act as an identifier.
Clients therefore need a way to detect unacceptable sets and inconsistent
views.  These are deployment requirements in addition to the cryptographic
property.

# Registry Methodology

The Privacy Pass Token Types registry established by {{RFC9578}} describes
token constructions, including whether each token type is publicly
verifiable.  A future publicly verifiable construction with mandatory issuer
hiding might be identified there, in the MoLE Endorsement Types registry
outlined by {{MOLE-PROTOCOLS}}, or in both registries.

Evaluation should begin with the use case and properties above, not with a
codepoint.  A registration proposal should provide a stable specification of
the construction and its privacy model.  If two registries are involved,
their entries should cross-reference the exact specifications and distinguish
the Privacy Pass token type from its use as a MoLE Endorsement.  Registration
in either registry does not, by itself, establish the issuer-hiding property.

This document does not classify existing token or endorsement schemes.  It
also does not request changes to either registry.

> **Editor's Note:** Decide whether issuer hiding belongs as a property or
> registration in the Privacy Pass Token Types registry, as a MoLE
> Endorsement Type, or as linked registrations in both.  If both are used,
> define which registration is authoritative and the cross-registration
> requirements.

# Protocol Structure

{{RFC9577}} defines the Privacy Pass `TokenChallenge` and `Token` structures,
and {{RFC9578}} defines issuance messages for its registered token types.  An
issuer-hiding construction needs to determine whether those common
structures can represent an issuer set without exposing a selected Issuer.
This document does not make that choice and defines no replacement structure.

> **Editor's Note:** Determine whether issuer hiding can reuse the existing
> `Token` and `TokenChallenge` structures, how a verifier-selected issuer set
> is bound into the challenge, and whether issuance requests need a distinct
> structure.  Resolve these questions before specifying a token type.

# Out of Scope

This document does not define a complete scheme, proof system, transport,
directory format, wire structure, codepoint, or registration template.  It
does not map every Privacy Pass or MoLE construction to the requirements in
this document.

Client-generated proofs over credentials obtained out of band, including
Longfellow-like proofs, are a distinct design point and are out of scope.
Longfellow is not described here as a Privacy Pass token.

# Security Considerations

Public verifiability allows anyone with the public configuration to verify a
presentation.  Issuer hiding needs to hold against a verifier that chooses the
issuer set and challenge, not only against an honest verifier using a default
configuration.

The effective anonymity set is the Clients that can present under the same
accepted issuer set and observable configuration.  Set contents, ordering,
key rotation, errors, message sizes, and timing can reduce that set even when
the cryptographic proof hides the selected key.  Issuer hiding also does not
hide information revealed independently by the application request or the
network path.  The general Privacy Pass security and privacy considerations
in {{RFC9576}}, {{RFC9577}}, and {{RFC9578}} continue to apply.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
