# Phonon Network Specification

The Phonon Network is a layer 2 scaling solution for public blockchain networks. It is designed to function on the Ethereum network, leveraging its account-based model.

Phonon uses **hardware enforced security** against double spend attacks, specifically via smart cards that leverage physical fingerprints for entropy, which cannot be extracted.

At initialization time, each card uses the internal, physical entropy to produce a key pair, the public key of which functions as an identity. Each card also has the ability to verify that it holds the private key corresponding to that public key via a challenge/response mechanism. A card's public key (identity) is signed by a certificate authority, specifically one which is comprised of several issuers. All signatures are combined using [**muSig**](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/) (which uses **Schnorr signatures**) to produce a single aggregated ECDSA signature. Per Schnorr, the public key corresponding to this aggregated signature may be verified using all of the individual signers' public keys.

Although the Phonon Network is theoretically card-agnostic, it is designed to be used with Safe Cards, which have a specific Java card applet (see [here](https://github.com/GridPlus/safe-card)).

## Initialization and Card Identity

To initialize a Java card, you first need a card reader (e.g. HID - link needed). While many variants exist, the Phonon Network is designed to *prefer* a secure interface, which exists in the GridPlus Lattice1. 

The card applet source code (e.g. the SafeCard applet) is compiled and flashed onto the card using the reader. This is called **installation**.

After installing the applet, the issuer calls the `init()` function, which looks something like this:

```
public KeycardApplet(byte[] bArray, short bOffset, byte bLength) {
    // Setup
    crypto = new Crypto();
    secp256k1 = new SECP256k1(crypto);
    secureChannel = new SecureChannel(PAIRING_MAX_CLIENT_COUNT, crypto, secp256k1);
    
    // Allocate space for certs
    certs = new byte[CERTS_LEN];
    certsLoaded = 0;
    
    // Create and configure authentication keypair
    certsAuthPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    certsAuthPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
    secp256k1.setCurveParameters(certsAuthPublic);
    secp256k1.setCurveParameters(certsAuthPrivate);

    // Load the authentication keypair with data
    byte[] privBuf = new byte[Crypto.KEY_SECRET_SIZE];
    crypto.random.generateData(privBuf, (short) 0, Crypto.KEY_SECRET_SIZE);
    certsAuthPrivate.setS(privBuf, (short) 0, Crypto.KEY_SECRET_SIZE);
    byte[] pubBuf = new byte[Crypto.KEY_PUB_SIZE];
    secp256k1.derivePublicKey(privBuf, (short) 0, pubBuf, (short) 0);
    certsAuthPublic.setW(pubBuf, (short) 0, Crypto.KEY_PUB_SIZE);

    ...other stuff...
  }
```

Here we generate an "authentication" key pair, which is used to identify the card. `crypto.random.generateData` uses the card's physical fingerprint (entropy) to create a random private key, which fills in the key pair objects.

At this point, the card is **initialized**. While there are other key pairs (related to holding crypto assets), the only one needed for Phonon is the authentication key.

### Proving Identity

The card's identity is captured in `certsAuthPublic` above. Any user with a card reader may request this public key at any time after the card is initialized.

The card may "prove" its identity to any requester with a card reader using a challenge/response mechanism:

```
private void authenticate(APDU apdu) {
    ...
    
    // Copy the input hash into a buffer
    byte[] msgHash = new byte[Crypto.KEY_SECRET_SIZE];
    Util.arrayCopyNonAtomic(apduBuffer, (short) ISO7816.OFFSET_CDATA, msgHash, (short) 0, Crypto.KEY_SECRET_SIZE);

    ...
    
    // Add signature of msg hash
    Signature tmpSig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    tmpSig.init(certsAuthPrivate, Signature.MODE_SIGN);
    tmpSig.signPreComputedHash(msgHash, (short) 0, MessageDigest.LENGTH_SHA_256, apduBuffer, sigOff);
   
    ...
  }
```

Here the card receives a hash and signs it using its authentication key (`certsAuthPrivate`), returning that signature as a response. Thus, the requester can verify that the public key yeilded from the card earlier corresponds to the private key which made this signature.

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
