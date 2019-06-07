# Phonon Network Specification

The Phonon Network is a layer 2 scaling solution for public blockchain networks. It is designed to function on the Ethereum network, but will likely be extended to the Bitcoin network in future versions. Phonon can be thought of as a L2 scaling technique where transactions are completely validated only between participants of a direct transaction. Nothing is shared with users on the Phonon network outside of the participant set for a given transaction.

To achieve this design topology, Phonon uses **hardware enforced security** to prevent against double spend attacks, specifically via smart cards that leverage physical fingerprints for entropy, which cannot be extracted. Although the Phonon Network is theoretically card-agnostic, it is designed to be used with Safe Cards, which have a specific Java card applet (see [here](https://github.com/GridPlus/safe-card)).

Physical fingerprints for entropy come in the form of Physically Uncloneable Functions, or PUFs. A PUF is a physical entity embodied in a physical structure. They are based on variations that occur during semiconductor manufacturing and essentially act as entropy stamped into a physical circuit. This entropy cannot be removed from the PUF, hence the uncloneable descriptor from its name.

"Phonons" are discrete packets of value which may be transmitted across the Phonon network. They are created by on-chain deposits, which are associated with a particular public key (a derivative of the recipient card's identity public key - more on this later). Each deposit may contain one or more non-fungible phonons, which are similar to the concept of a "bill" (i.e. has a specific denomination and cannot be divided).

# Initialization and Card Identity

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
    
    // Create and configure identity keypair
    certsAuthPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    certsAuthPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
    secp256k1.setCurveParameters(certsAuthPublic);
    secp256k1.setCurveParameters(certsAuthPrivate);

    // Load the identity keypair with data
    byte[] privBuf = new byte[Crypto.KEY_SECRET_SIZE];
    crypto.random.generateData(privBuf, (short) 0, Crypto.KEY_SECRET_SIZE);
    certsAuthPrivate.setS(privBuf, (short) 0, Crypto.KEY_SECRET_SIZE);
    byte[] pubBuf = new byte[Crypto.KEY_PUB_SIZE];
    secp256k1.derivePublicKey(privBuf, (short) 0, pubBuf, (short) 0);
    certsAuthPublic.setW(pubBuf, (short) 0, Crypto.KEY_PUB_SIZE);

    ...other stuff...
  }
```

Here we generate an "identity" key pair, which is used to identify the card. `crypto.random.generateData` uses the card's PUF (entropy) to create a random private key, which fills in the key pair objects.

At this point, the card is **initialized**. While there are other key pairs (related to holding crypto assets), the only one needed for Phonon is the identity key.

## Proving Identity

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

Here the card receives a hash and signs it using its identity key (`certsAuthPrivate`), returning that signature as a response. Thus, the requester can verify that the public key yeilded from the card earlier corresponds to the private key which made this signature.

## Certifying a Card

Each SafeCard is loaded with a certificate from the GridPlus certificate authority. This is nothing more than a signature on the public key of the card (which the card has proven to have) by an ECDSA key pair controlled by GridPlus at the time of card issuance. Once loaded, the cert cannot be modified or removed.

The cert can be inspected at any time by any user with a card reader. It proves that GridPlus issued the card in question and is a prerequisite for most SafeCard-based interactions on the Lattice1.

> In the Phonon Network, it is **strongly** recommended that all transfers and withdrawals check the certificate of the card sending the message

# Structure of a Phonon

Each phonon represents a non-fungible "packet" of tokens. It contains the following data:

1. **Receiving private key:** at deposit time, each phonon must be sent to a different address. The deposit address corresponds to a private key, which is passed between participants in the network as the phonon is spent. So long as private keys aren't reused, any counterparty risk (which should be obviated by hardware-enforced rules, but ya know... crypto people) is constrained to the individual phonon
2. **Network ID:** an identifier (`uint8`) for the network from which this phonon derives. A recipient of a phonon should be careful to ensure this id corresponds to the network on which he expects the tokens to exist. This id maps to a 32-byte descriptor on the card, which may later be upgraded. In the case of Ethereum, this network id maps to a settlement smart contract address (20 bytes)
3. **Asset ID:** an identifier (`uint16`) for the asset describing this phonon. A list of accepted asset ids is stored on-chain. In the case of Bitcoin, there is only one asset id (`0`). In Ethereum, it corresponds to a token address or id.
4. **Amount:** the number of tokens (in atomic units). Because of ether's units, this must be a `uint256`.

# Accounting on the Card

Data is stored both on the public blockchain (see: *On-Chain Settlements*) and on the card. This section covers data types, deposits, and withdrawals on Phonon-compatable cards.

## Getting a Deposit Address

Phonons are not deposited to the card's identity address, but rather to an address derived from the identity key:

```
byte[] getDepositKey(long startingNonce, short n) {
    byte[] toReturn = new byte[n * PRIVATE_KEY_LEN];
    // Derive n private keys
    for (short i = 0; i < n; i++) {
      // Copy this key to the return buffer
      Util.arrayCopyNonAtomic(toReturn, i*n, sha256(authPrivKey, startingNonce+n), PRIVATE_KEY_LEN);
    }
    return toReturn;
}
```

Here we can generate `n` private keys, whose public keys (actually addresses) are needed for deposits on-chain.

## Storing Phonons

Phonon storage is described on the card as:

```
class Phonon {
  public byte[32] owner;    // Private key that can spend or withdraw the phonon
  public short assetId;     // Combination of the asset type (e.g. a type of ERC20) and an optional id (for NFTs)
  public byte[32] amount;   // Atomic units of token being deposited
  public short networkId;   // Index (on-card) on which to determine which network these tokens exist on
}

private Phonon[] phonons;
```

> `networkId` maps to an identifier on the card. In the case of Ethereum, this is the settlement contract address. For Bitcoin, it is `null`.

## Storing Network References

The card must keep a number of network "references", which are 20-byte descriptors indexed on a network ID:

```
private byte[] networks;
```

Here, each network descriptor is a 32-byte slice of `networks`, which is a 1D array of size `numNetworks * 20`. For example, if we want the identifier for network 3, we would slice `networks[96:128]`.

> Descriptors are 20 bytes because currently the Phonon Network only supports Ethereum-based withdrawals, with Bitcoin withdrawal support coming in a future update. Network descriptors are only used for Ethereum-based chains and represent the address of the settlement contract. In the future, it may be useful to expand network ids to a more generalizable 32 bytes. Because space is limited on the card, we expect only a small number of networks to be supported at any time.

The card owner may, at any time, update his card's network list using the following API:

**getNetworkReference(short id)**

This returns a 32-byte network descriptor for the given slot. If it is empty, this is 32 zero bytes.

**setNetworkReference(short id, byte[] reference)**

This sets a 32-byte slice of `networks` using the provided `reference` at the provided index (`32 * id`).

## Deposits

A phonon can be added to the card with the following API call:

**deposit(long recipientIndex, short assetId, byte[] amount)**

This will re-derive the recipient private key using the index. Recall that this was previously derived so that the user could generate a deposit *address*. We now use the corresponding *private key* as the identifier.

The included data is packed into a `Phonon` and is stored at the first unused index.

> Note that there is a maximum number of phonons which may be stored on a given card. If the card runs out of space, this API call will fail, but the user can store the phonon somewhere else and send it to the card at any time - of course this means the user must also persist the `recipientIndex`, which is not part of the phonon deposit metadata!

## Withdrawals

The card may withdraw a phonon at any time by passing the phonon index and calling the "withdraw" functions. Because the data being signed is different depending on the type of network, we have multiple withdraw functions.

**withdraw(short phononIndex, byte[] data)**

Look up the phonon based on an index. If no phonon exists at that index, this call will fail.

### Ethereum-based Withdrawals

If the provided phonon corresponds to a non-null network descriptor (indicating it is an Ethereum-based network), this function will do the following:

1. Assert that `data` is 20 bytes (it corresponds to the recipient address).
2. Sign a message (`msg`) with the phonon's private key: `sha256(owner, networkDescriptor, assetId, amount)`.
3. Sign the same message with the card's identity private key.
4. Remove the phonon at the provided index.

The following serialized payload is expected from a withdrawal:

```
serWithdrawal = [ 
  TLV_NETWORK_DESCRIPTOR,
  NETWORK_DESCRIPTOR_LEN,   // 20
  networkDescriptor,
  TLV_MSG_HASH, 
  MSG_HASH_LEN,             // 32
  msg,
  TLV_SIGNATURE,
  SIGNATURE_LEN,            // 65 - we need v for ecrecover (in addition to r and s)
  ownerSig,                 // signature from `owner` private key on `msg`
  TLV_SIGNATURE,
  SIGNATURE_LEN,
  idSig,                    // signature from this card's identity key on `msg`
  TLV_CERT,
  SIGNATURE_LEN,
  cert                      // Authentication certificate of the card's identity key
]
```

**TODO: It would be preferable if we could avoid having to use `v`, as all other signatures in our system are 64 bytes. I believe `v` is simply required for `ecrecover`. Unfortunately I'm not sure there is an alternative verification in solidity.**


### Bitcoin Withdrawals

If the provided phonon corresponds to a null network descriptor, we need to create a Bitcoin transaction to withdraw, as there is no smart contract to manage balances on-chain and this balance is simply encumbered by a type of pay to script hash corresponding to the key held in the phonon.

**TODO: Describe the data needed to be passed in and signed**


# On-Chain Settlements

Phonons may be deposited and withdrawn using a settlement smart contract on Ethereum. Network and asset IDs are also stored in a registry on a smart contract, which should function as a source of truth. (The network id should be fixed for a given network).

## Ethereum-based networks

Ethereum (and Ethereum-derived networks) use smart contracts to manage deposits and withdrawals. Each deposit is mapped to a recipient, asset, and amount. Withdrawing requires a signature on key data, which can be used to prove validity of the withdrawal.

### Data Structures

Data is stored in the following way on the settlement smart contract:

```
struct Asset {
  address contract;
  uint256 id;         // Identifier for ERC721s
}

struct Phonon {
  uint256 assetId;
  uint256 amount;
}

mapping(address => Phonon) public phonons;
mapping(uint256 => Asset) public assets;
```

Here `assets` are indexed on `assetId`, which maps to both a contract containing the asset code and an optional identifier for a non-fungible asset within that contract. `Phonons` are indexed on a recipient address and contain an `Asset` and an amount.

> Assets are generally created and stored on a registry, which can be the same settlement contract. These can be added either by users or administrators or set once at deployment time.

### Settlement API

Each settlement smart contract should have the following API.

#### Deposits

Once a user generates one or more deposit addresses from his card, he may send a number of tokens to the contract for deposit. Once the deposit occurs, the user may send a message to his card specifying the parameters used to make the deposit.

**deposit(address recipient, uint256 assetId, uint256 amount)**

Deposit one or more tokens to `recipient`. The following logic is performed:

1. Look up the asset using `assetId`. If this maps to an empty asset, the transaction will fail.
2. Look up the balance of the recipient using: `phonons[recipient]`. If this balance is >0, the transaction will fail.
3. Move asset from the sender's account. Depending on the asset type (ERC20 or ERC721), this will call a different method of the underlying contract.

This produces a transaction on the Ethereum network, which may be sent to the user's card for deposit.

> Note that in the Phonon Network, the onus of verification and proof falls on the recipient of the phonon. The depositor may submit the deposit data immediately after submitting the on-chain transaction. Because no proof is passed, it is assumed that the depositor may act maliciously - recipient cards should check the amount of work behind the deposit before accepting it as payment!

#### Withdrawals

The following data is necessary to withdraw a phonon on an Ethereum-based network:

1. `networkDescriptor` - tells the user which network and which contract to withdraw from
2. Message hash (`sha256(owner, networkDescriptor, assetId, amount)`)
3. Signature of message hash by `owner`
4. Signature of message hash by identity key
5. Cert authorizing the identity public key

With all of this data, the contract can do the following:

1. Use `ecrecover` and *(1)* to get the identity public key from *(4)*
2. Verify that the cert *(5)* is a signature by a known CA (stored in the contract) on the recovered identity public key
3. Use `ecrecover` and *(2)* to get the `owner` public key (and address) from *(3)*
4. Find the `Phonon` object associated to the `owner` address recovered above and construct the following hash: `sha256(owner, address(this), assetId, amount)`. This value should match *(2)*.


# Transacting on the Phonon Network

## Sending

To send a phonon, a card must first serialize its data:

```
serPhonon = [ 
  TLV_NETWORK_DESCRIPTOR,
  NETWORK_DESCRIPTOR_LEN,  // 20
  networkDescriptor,
  TLV_PRIVATE_KEY, 
  PRIVATE_KEY_LEN,         // 32
  owner,
  TLV_ASSET_ID,
  ASSET_ID_LEN,            // 2
  assetId,
  TLV_PHONON_AMOUNT,
  PHONON_AMOUNT_LEN,       // 32 - we need to allow for large integers
  amount
]
```

In this serialization scheme, each parameters is prefixed by:

1. An data type identifier (1-byte TLV)
2. A 1-byte length prefix indicating the number of bytes to follow for that parameter

Once serialized, the phonon is deleted from its index in the global `phonons` variable. The serialized payload is returned to the requester.

## Receiving

A card receiving a phonon has more strict requirements to validate the phonon's origin as well as the authenticity of the sending card.

**TODO: All of the stuff about verification: cert of sending card, transaction on desired network, etc**



