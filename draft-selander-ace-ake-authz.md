---
title: Lightweight Authorization for Authenticated Key Exchange.
abbrev: Lightweight Authorization for AKE.
docname: draft-selander-ace-ake-authz-latest

ipr: trust200902
cat: info

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Mattsson
        org: Ericsson AB
        email: john.mattsson@ericsson.com
      -
        ins: M. Vucinic
        name: Malisa Vucinic
        org: INRIA
        email: malisa.vucinic@inria.fr
      -
        ins: M. Richardson
        name: Michael Richardson
        org: Sandelman Software Works
        email: mcr+ietf@sandelman.ca




normative:


informative:

  RFC2119:
  RFC3748:
  RFC7228:
  RFC8152:
  RFC8174:
  I-D.ietf-lake-reqs:
  I-D.ietf-ace-oauth-authz:
  I-D.raza-ace-cbor-certificates:
  I-D.irtf-cfrg-hpke:
  I-D.ietf-ace-coap-est:
  I-D.ietf-6tisch-minimal-security:

--- abstract

This document describes a procedure for augmenting an authenticated Diffie-Hellman key exchange with third party assisted authorization targeting constrained IoT deployments (RFC 7228).

--- middle

# Introduction  {#intro}


For constrained IoT deployments {{RFC7228}} the overhead contributed by security protocols may be significant which motivates the specification of lightweight protocols that are optimizing, in particular, message overhead (see {{I-D.ietf-lake-reqs}}).
This document describes a lightweight procedure for augmenting an authenticated Diffie-Hellman key exchange with third party assisted authorization.

The procedure involves a device, a domain authenticator and an authorization server.
The device and authenticator performs mutual authentication and authorization, assisted by the authorization server which provides relevant authorization information to the device (a "voucher") and the authenticator.

The protocol specified in this document optimizes the message count by performing authorization and enrolment in parallel with authentication, instead of in sequence which is common for network access.
It further reuses protocol elements from the authentication protocol leading to reduced message sizes on constrained links.

The specification assumes a lightweight AKE protocol {{I-D.ietf-lake-reqs}} between device and authenticator, and defines the integration of a lightweight authorization procedure.
This enables a secure target interaction in few message exchanges.
In this document we consider the target interaction to be "enrolment", for example certificate enrolment (such as {{I-D.ietf-ace-coap-est}}) or joining a network for the first time (e.g. {{I-D.ietf-6tisch-minimal-security}}), but it can be applied to authorize other target interactions.

This protocol is applicable in a wide variety of settings, and can be mapped to different authorization architectures.
This document specifies a profile of the ACE framework {{I-D.ietf-ace-oauth-authz}}.
Other settings such as EAP {{RFC3748}} are out of scope.

## Terminology   {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Problem Description {#prob-desc}

The (potentially constrained) device wants to enrol into a domain over a constrained link.
The device authenticates and enforces authorization of the (non-constrained) domain authenticator with the help of a voucher, and makes the enrolment request.
The domain authenticator authenticates the device and authorizes its enrolment.
Authentication between device and domain authenticator is made with a lightweight authenticated Diffie-Hellman key exchange protocol (LAKE, {{I-D.ietf-lake-reqs}}).
The procedure is assisted by a (non-constrained) authorization server located in a non-constrained network behind the domain authenticator providing information to the device and to the domain authenticator.

The objective of this document is to specify such a protocol which is lightweight over the constrained link and reuses elements of the LAKE. See illustration in {{fig-overview}}.


~~~~~~~~~~~
                   Voucher
              LAKE  Info
+----------+  |    |   +---------------+  Voucher  +---------------+
|          |  |    |   |               |  Request  |               |
|  Device  |--|----o-->|    Domain     |---------->| Authorization |
|          |<-|---o----| Authenticator |<----------|     Server    |
|    (U)   |--|---|--->|      (V)      |  Voucher  |       (W)     |
|          |      |    |               |  Response |               |
+----------+      |    +---------------+           +---------------+
                  Voucher


~~~~~~~~~~~
{: #fig-overview title="Overview and example of message content. Voucher Info and Voucher are sent together with LAKE messages." artwork-align="center"}


# Assumptions

## Device

The device is pre-provisioned with an identity ID and asymmetric key credentials: a private key, a public key (PK_U), and optionally a public key certificate Cert(PK_U), issued by a trusted third party such as e.g. the device manufacturer, used to authenticate to the domain authenticator. The ID may be a reference or pointer to the certificate.

The device is also provisioned with information about its authorization server:

* At least one static public DH key of the authorization server (G_W) used to ensure secure communication with the device (see {{U-W}}).
* Location information about the authorization server (LOC_W), e.g. its domain name. This information may be available in the device certificate Cert(PK_U).



## Domain Authenticator

The domain authenticator has a private key and corresponding public key PK_V used to authenticate to the device.

The domain authenticator needs to be able to locate the authorization server of the device for which the LOC_W is expected to be sufficient. The communication between domain authenticator and authorization server is mutually authenticated and protected. Authentication credentials used with the authorization server are out of scope. How this communication is established and secured (typically TLS) is out of scope.

TODO: Need for channel binding?


## Authorization Server

The authorization server has a private DH key corresponding to G_W, which is used to secure the communication with the device (see {{U-W}}). Authentication credentials and communication security used with the domain authenticator is out of scope.

The authorization server provides the authorization decision for enrolment to the device in the form of a CBOR encoded voucher. The authorization server provides information to the domain authenticator about the device, such as the the device's certificate Cert(PK_U).

The authorization server needs to be available during the execution of the protocol.


## Lightweight AKE

We assume a Diffie-Hellman key exchange protocol complying with the LAKE requirements {{I-D.ietf-lake-reqs}}. Specifically we assume for the LAKE:

* Three messages
* CBOR encoding
* The ephemeral public Diffie-Hellman key of the device, G_X, is sent in message 1. G_X is also used as ephemeral key and nonce in the ECIES scheme between device and authorization server.

* The static public key of the domain authenticator, PK_V, sent in message 2
* Support for Auxilliary Data AD1-3 in messages 1-3 as specified in section 2.5 of {{I-D.ietf-lake-reqs}}.
* Cipher suite negotiation where the device can propose ECDH curves restricted by its available public keys of the authorization server.



# The Protocol

Three security sessions are going on in parallel (see figure {{fig-protocol}}):

* Between device and (domain) authenticator,
* between authenticator and authorization server, and
* between device and authorization server mediated by the authenticator.

We study each in turn, starting with the last.

~~~~~~~~~~~
   U                                 V                     W
   |                                 |                     |
   |--- Message 1 incl. G_X, AD1 --->|--- Voucher Req. --->|
   |                                 |                     |
   |<-- Message 2 incl. PK_V, AD2 ---|<-- Voucher Resp. ---|
   |                                 |
   |--- Message 3 incl. AD3 -------->|

~~~~~~~~~~~
{: #fig-protocol title="The Protocol" artwork-align="center"}


## Device <-> Authorization Server {#U-W}

The communication between device and authorization server is carried out via the authenticator protected between the endpoints using an ECIES hybrid encryption scheme (see {{I-D.irtf-cfrg-hpke}}): The device uses the private key of its ephemeral DH key G_X generated for LAKE message 1 (see {{U-V}}) together with the static public DH key of the authorization server G_W to generate a shared secret G_XW. The shared secret is used to derive AEAD encryption keys to protect data between device and authorization server. The data is carried in AD1 and AD2 (between device and authenticator) and in voucher request/response (between authenticator and authorization server).

TODO: Reference relevant ECIES scheme in {{I-D.irtf-cfrg-hpke}}.

TODO: Define derivation of encryption keys (k_rq, k_rs) and nonces (n_rq, n_rs) for both directions


AD1 SHALL be the following CBOR sequence containing voucher information:

~~~~~~~~~~~
AD1 = (
    LOC_W:           tstr,
    CC:              bstr,
    CIPHERTEXT_RQ:   bstr
)
~~~~~~~~~~~

where

* LOC_W is location information about the authorization server
* CC is a crypto context identifier for the security context between the device and the authorization server
* 'CIPHERTEXT_RQ' is the authenticated encrypted identity of the device with CC as Additional Data, more specifically:

'CIPHERTEXT_RQ' is 'ciphertext' of COSE_Encrypt0 (Section 5.2-5.3 of {{RFC8152}}) computed from the following:

* the secret key k_rq
* the nonce n_rq
* 'protected' is a byte string of size 0
* 'plaintext and 'external_aad' as below:

~~~~~~~~~~~
plaintext = (
    ID:              bstr
 )
~~~~~~~~~~~
~~~~~~~~~~~
external_aad = (
    CC:              bstr
 )
~~~~~~~~~~~

where

* ID is the identity of the device, for example a reference or pointer to the device certificate
* CC is defined above.



AD2 SHALL be a CBOR sequence of one item, the Voucher, defined in the next section.

~~~~~~~~~~~
AD2 = (
    Voucher:        bstr
)
~~~~~~~~~~~


### Voucher {#voucher}


The Voucher is essentially a Message Authentication Code binding the identity of the authenticator to the first message sent from the device in the LAKE protocol.

More specifically 'Voucher' is the 'ciphertext' of COSE_Encrypt0 (Section 5.2 of {{RFC8152}}) computed from the the following:

* the secret key k_rs
* the nonce n_rs
* 'protected' is a byte string of size 0
* 'plaintext' is empty (plaintext =  nil)
* 'external_aad' as below:

~~~~~~~~~~~
external_aad = bstr .cbor external_aad_arr
~~~~~~~~~~~
~~~~~~~~~~~
external_aad_arr = [
    voucher_type:  int,
    PK_V:          bstr,
    G_X:           bstr,
    CC:            bstr,
    ID:            bstr
]
~~~~~~~~~~~

where

* 'voucher-type' indicates the kind of voucher used
* PK_V is a COSE_Key containing the public authentication key of the authenticator. The public key must be an Elliptic Curve Diffie-Hellman key, COSE key type 'kty' = 'EC2' or 'OKP'.
   * COSE_Keys of type OKP SHALL only include the parameters 1 (kty), -1 (crv), and -2 (x-coordinate). COSE_Keys of type EC2 SHALL only include the parameters 1 (kty), -1 (crv), -2 (x-coordinate), and -3 (y-coordinate). The parameters SHALL be encoded in decreasing order.
* G_X is the ephemeral key of the device sent in the first LAKE message
* CC and ID are defined in {{U-W}}


All parameters, except 'voucher-type', are as received in the voucher request (see {{V-W}}).

TODO: Consider making the voucher a CBOR Map to indicate type of voucher, to indicate the feature (cf. {{V-W}})


## Device <-> Authenticator {#U-V}

The device and authenticator run the LAKE protocol authenticated with public keys (PK_U and PK_V) of the device and the authenticator. The normal processing of the LAKE is omitted here.


### Message 1

#### Device processing

The device selects a cipher suite with an ECDH curve satisfying the static public DH key G_W of the authorization server. As part of the normal LAKE processing, the device generates the ephemeral public key G_X to be sent in LAKE message 1. A new G_X MUST be generated for each execution of the protocol. The same ephemeral key is used in the ECIES scheme, see {{U-W}}.

The device sends LAKE message 1 with AD1 as specified in {{U-W}}.


#### Authenticator processing

The authenticator receives LAKE message 1 from the device, which triggers the exchange of voucher related data with the authorization server as described in {{V-W}}.


### Message 2

#### Authenticator processing

The authenticator sends LAKE message 2 to the device with the voucher (see {{U-W}}) in AD2. The public key PK_V is encoded in the way public keys are encoded in the LAKE protocol.



#### Device processing

The device MUST verify the Voucher using its ephemeral key G_X sent in message 1 and PK_V received in message 2. If the Voucher does not verify, the device MUST discontinue the protocol.


### Message 3

#### Device processing


The device sends message 3. AD3 depends on the kind of enrolment the device is requesting. It may e.g. be a CBOR encoded Certificate Signing Request, see {{I-D.raza-ace-cbor-certificates}}.

#### Authenticator processing

The authenticator receives message 3.


## Authenticator <-> Authorization Server {#V-W}

The authenticator and authorization server are assumed to have secure communication, for example based on TLS authenticated with certificates.


### Voucher Request


The authenticator sends the voucher request to the authorization server.
The Voucher_Request SHALL be a CBOR array as defined below:

~~~~~~~~~~~
Voucher_Request = [
    PK_V:            bstr,
    G_X:             bstr,
    CC:              bstr,
    CIPHERTEXT_RQ:   bstr
]
~~~~~~~~~~~

where the parameters are defined in {{U-W}}.


### Voucher Response

The authorization server decrypts the identity of the device and looks up its certificate, Cert(PK_U). The authorization server sends the voucher response to the authenticator. The Voucher_Response SHALL be a CBOR array as defined below:

~~~~~~~~~~~
Voucher_Response = [
    CERT_PK_U:      bstr,
    Voucher:        bstr
]
~~~~~~~~~~~

where

* CERT_PK_U is the device certificate of the public key PK_U, issued by a trusted third party, intended to be verified by the authenticator. The format of this certificate is out of scope.
* Voucher is defined in {{U-W}}

TODO: The voucher response may contain a "Voucher-info" field as an alternative to make the Voucher a CBOR Map (see {{U-W}})

# ACE Profile

This section defines the profile of the ACE framework (see Appendix C of {{I-D.ietf-ace-oauth-authz}}).


# Security Considerations  {#sec-cons}

TODO: Identity protection of device

TODO: How can the authorization server attest the received PK_V?

TODO: Use of G_X as ephemeral key between device and authenticator, and between device and authorization server

TODO: Remote attestation

# IANA Considerations  {#iana}

TODO: CC registry

TODO: Voucher type registry

--- back



