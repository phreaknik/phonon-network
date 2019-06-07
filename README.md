# Phonon Network Specification

The Phonon Network is a layer 2 scaling solution for public blockchain networks. It is designed to function on the Ethereum network, leveraging its account-based model.

Phonon uses **hardware enforced security** against double spend attacks, specifically via smart cards that leverage physical fingerprints for entropy, which cannot be extracted.

At initialization time, each card uses the internal, physical entropy to produce a key pair, the public key of which functions as an identity. Each card also has the ability to verify that it holds the private key corresponding to that public key via a challenge/response mechanism. A card's public key (identity) is signed by a certificate authority, specifically one which is comprised of several issuers. All signatures are combined using [**muSig**](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/) (which uses **Schnorr signatures**) to produce a single aggregated ECDSA signature. Per Schnorr, the public key corresponding to this aggregated signature may be verified using all of the individual signers' public keys.

## Initialization and Card Identity

## Authentication Using a Multi-Party CA

## The Settlement Contract

### Deposits

### Withdrawals

## Accounting on the Card

### Sending

### Receiving

### Adding or Removing CA PubKeys

The card should have an updated list of CA keys should the member set ever change

### Managing Settlement Contracts And Assets

The card should only receive or send payments for known assets on known settlement contracts
