# Phonon Network Specification

The Phonon Network is a layer 2 scaling solution for public blockchain networks. It is designed to function on the Ethereum network, leveraging its account-based model.

Phonon uses **hardware enforced security** against double spend attacks, specifically via smart cards that leverage physical fingerprints for entropy, which cannot be extracted.

At initialization time, each card uses the internal, physical entropy to produce a key pair, the public key of which functions as an identity. Each card also has the ability to verify that it holds the private key corresponding to that public key via a challenge/response mechanism. A card's public key (identity) is signed by a certificate authority, specifically one which is comprised of several issuers. All signatures are combined using [**muSig**](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/) (which uses **Schnorr signatures**) to produce a single aggregated ECDSA signature. Per Schnorr, the public key corresponding to this aggregated signature may be verified using all of the individual signers' public keys.

Although the Phonon Network is theoretically card-agnostic, it is designed to be used with Safe Cards, which have a specific Java card applet (see [here](https://github.com/GridPlus/safe-card)).

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

The card should only receive or send payments for known assets on known settlement contracts. This data is stored in the following way:

```
private Address[] settlementContractAddresses;
private Address[][] assets;
private long[][] balances;
```

Where `Address` is a 20-byte piece of data.

> Note that the card will have a fixed number of slots for `settlementContractAddresses` and for each slot, it will have another (possibly different) fixed number of `assets` and `balances`.

Each `settlementContractAddress` maps to a set of `assets` and corresponding `balances`, which are associated based on index.

The card owner may add or remove `settlementContractAddresses` or `assets` using the following criteria:

**Adding** requires an empty slot for either `settlementContractAddresses` or `assets` (depending on which is trying to be added.

**Removing** requires that *all* balances are zero. Removing a settlement contract address requires *all* of its assets have a zero balance. Removing an asset (from within a specified settlement contract address) requires that asset's balance be zero.

> If a balance is non-zero, the card may create a **withdrawal event** to zero the balance. In the case of small balances (i.e. dust), the user may not wish to broadcast this withdrawal. Recall that creating a withdrawal event does not affect global blockchain state until it is sent to the chain.

The user may utilize the following API:

#### addContract(Address addr)

Adds an address to the list of `settlementContractAddress` (at the first unused index). Fails if there is no unused index.

#### addAsset(short settlementIndex, Address assetAddr)

Adds an asset address to a specified index of `settlementContractAddresses`. Fails if the index has no unused `asset` index or if the asset is already present in the list.

#### removeContract(short settlementIndex)

Clears all `assets` from the specified `settlementContractAddresses` index. Fails if any corresponding `balance` is non-zero.

#### removeAsset(short settlementIndex, short assetIndex)

Clears `asset` at specified indices (`settlementContractAddresses` and `assets`). Fails if corresponding `balance` is non-zero.
