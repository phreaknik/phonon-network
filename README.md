# Phonon Network Specification

The Phonon Network is a layer 2 scaling solution for public blockchain networks. It is designed to function on the Ethereum network, but will likely be extended to the Bitcoin network in future versions. Phonon can be thought of as a L2 scaling technique where transactions are completely validated only between participants of a direct transaction. Nothing is shared with users on the Phonon network outside of the participant set for a given transaction.

To achieve this design topology, Phonon uses **hardware enforced security** to prevent against double spend attacks, specifically via smart cards that leverage physical fingerprints for entropy, which cannot be extracted. Although the Phonon Network is theoretically card-agnostic, it is designed to be used with SafeCards, which have a specific Java card applet (see [here](https://github.com/GridPlus/safe-card)).

Physical fingerprints for entropy come in the form of Physically Uncloneable Functions, or PUFs. A PUF is a physical entity embodied in a physical structure. They are based on variations that occur during semiconductor manufacturing and essentially act as entropy stamped into a physical circuit. This entropy cannot be removed from the PUF, hence the uncloneable descriptor from its name.

### What is a Phonon?

"Phonons" are discrete packets of value which may be transmitted across the Phonon network. They are **created by on-chain deposits**, which are associated with a particular public key (a derivative of the recipient card's identity public key - more on this later). Each deposit may contain one or more non-fungible phonons, which are similar to the concept of a "bill" (i.e. has a specific denomination and cannot be divided). 

### How are Phonons Transferred?

Each phonon contains an amount, an asset type, a private key, and some other metadata. Because private keys are being passed, all phonon transmission happens over secure (encrypted) channels between counterparty cards. The data is encrypted/decrypted using a shared AES secret which is the ECDH shared secret of the cards' identity key pairs.

### How do Withdrawals Work?

When a user wishes to withdraw a phonon onto the blockchain network from which it originated, they call a function on the card, which generates the relevant payload and makes a signature needed to satisfy the withdrawal conditions (these vary depending on the network and/or withdrawal implementation). *The signature originates from the **private key contained in the phonon itself** - once the withdrawal occurs, the phonon (including this key) is deleted from the card.* At this point, it is up to the user to package this signature into a transaction and make the withdrawal on-chain.

### Where is the Trust?

Although not strictly part of the Phonon Network, it is important for participants to trust the issuance of their counterparty (i.e. that the counterparty's card is indeed running Phonon and will not double spend). This is generally accomplished with a **certificate authority** (usually the card issuer), who signs the identity public key of the card in the manufacturing provisioning process. Every user of the phonon network may configure which CAs they trust and may add or revoke trust of any given CA at any time.

# Structure of a Phonon

Each phonon represents a non-fungible "packet" of tokens. It contains the following minimum set of data, which may be stored in various ways (covered in later sections):

1. **Receiving private key:** at deposit time, each phonon must be sent to a different address. The deposit address corresponds to a private key, which is passed between participants in the network as the phonon is spent. So long as private keys aren't reused, any counterparty risk (which should be obviated by hardware-enforced rules, but ya know... crypto people) is constrained to the individual phonon
2. **Network ID:** an identifier for the network from which this phonon derives. A recipient of a phonon should be careful to ensure this id corresponds to the network on which he expects the tokens to exist. In the case of Ethereum, this network id maps to a settlement smart contract address (20 bytes)
3. **Asset ID:** an identifier for the asset describing this phonon. For Ethereum, a list of accepted asset ids is stored on-chain; these correspond to a token address and, for NFTs, a token id. For Bitcoin, there is only one asset id (`0`).
4. **Tx Data:** usually a transaction hash and, in the case of Bitcoin, a UTXO index in that transaction.
4. **Amount:** the number of tokens (in atomic units).

# Provisioning a Card

Phonon is designed to work with [Java cards](https://www.oracle.com/technetwork/java/embedded/javacard/overview/index.html). To initialize a Java card, you first need a card reader (e.g. [HID OMNIKEY](https://www.hidglobal.com/products/readers/omnikey) series). While many variants exist, the Phonon Network is designed to *prefer* a secure interface, which exists in the GridPlus [Lattice1](https://gridplus.io/lattice). 

## Installing and Initializing the Applet

Part of the manufacturing/issuing process involves installation and initialization of the Java card applet. Each step occurs only once - if someone attempts to reinstall an applet, the card will lose its identity keystore. 

First, the card applet source code (e.g. the SafeCard applet) is compiled and flashed onto the card using the reader. This is called **installation**.

After installing the applet, the issuer calls the `init()` function, which looks something like this:

```
public KeycardApplet(byte[] bArray, short bOffset, byte bLength) {
    ...setup...
    
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

At this point, the card is **initialized**. While other key pairs (related to holding crypto assets) may be added later, the only one needed for Phonon is the identity key, which cannot be changed once it is initialized.

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

Each SafeCard is loaded with a certificate from the GridPlus certificate authority. This is nothing more than a signature on the card's identity public key (which the card has proven to have) by an ECDSA key pair controlled by GridPlus at the time of card issuance. Once loaded, the cert cannot be modified or removed.

The cert can be inspected at any time by any user with a card reader. It proves that GridPlus issued the card in question and is a prerequisite for most SafeCard-based interactions on the Lattice1.

> GridPlus certificates are not *required* in the Phonon Network, but they *are* utilized in the data transport layer used by Lattice1 devices, which must first check the certification of a counterparty before creating a secure channel and accepting payment.

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

### Nonce Tracking

Each deposit key is the hash of a **nonce** with the identity key. A global nonce is kept on each card; every time a phonon is deposited, the global nonce is incremented. More on this later.

## Storing Phonons

Phonon storage is described on the card as:

```
class Phonon {
  public byte[32] owner;    // Private key that can spend or withdraw the phonon
  public int assetId;       // ETH only: uint32 representing a type of ERC20 or NFT id
  public long amount;       // uint64 representing the asset value
  public short decimals;    // ETH only: (amount * 10^decimals) represents the value in atomic units
  public byte[32] txId;     // Transaction hash (or, more generically, "id")
  public byte idx;          // BTC only: Index of the UTXO in the transaction represented by `txId`
  public short networkId;   // Index (on-card) on which to determine which network these tokens exist on
}

private Phonon[] phonons;
```

#### `owner`

The private key associated with the deposit address of this phonon. This key is needed to withdraw (or spend) the phonon.

#### `assetId` (ETH ONLY)

An index for the type of asset on the smart contract. This is specific to the on-chain smart contract in question (see: *On-Chain Settlements* section). An asset index must be unique on a combination of the address of the contract and an index of a specific token on that contract. It is assumed that a uint32 is large enough to capture all asset ids in a given contract.

#### `amount`

The amount to transact. For Bitcoin, this uint64 represents the total number of satoshis (the atomic unit). For Ethereum, this may not be enough to describe the atomic units and must be combined with `decimals`.

#### `decmials` (ETH ONLY)

If the coin has >8 decimals, it must utilize this field in the following way:

```
atomicUnits = amount * (10 ** decimals)
```

It is up to the depositor to encode these two parameters. So long as the recipient can verify the full amount on-chain, any equivalent multiplicative combination is allowed. For example, the following are equivalent to represent 6.12 ether (which has 18 decimals):

1. `amount = 612`, `decimals = 16`
2. `amount = 6,120,000`, `decimals = 12`

#### `txId`

The id (usually a hash) of the on-chain transaction in which this phonon was created. This is not strictly necessary for Ethereum, but is good practice to include.

#### `idx` (BTC ONLY)

Index of the Phonon UTXO (in Bitcoin, each Phonon is a UTXO) within the transaction specified in `txId`.

#### `networkId`

An index that maps to a network descriptor on the card. In the case of Ethereum, this is the settlement contract address. For Bitcoin, it is usually 0 or null.

It is important to note that the actual descriptor on the card is used for verification by the recipient of a Phonon Network transction. The sender and recipient must agree on the mappings between network ids and network descriptors in order to agree on the value of the phonon being transferred.

## Storing Network References

The card must keep a number of network "references", which are 32-byte descriptors indexed on a network ID:

```
private byte[] networks;
```

Here, each network descriptor is a 32-byte slice of `networks`, which is a 1D array of size `numNetworks * 32`. For example, if we want the identifier for network 3, we would slice `networks[96:128]`.

> For the near future, descriptors will likely be either 20 bytes (Ethereum contract addresses - left padded with zeros) or 0 bytes (Bitcoin). However, the slot is kept at 32 bytes for upgradability.

The card owner may, at any time, update his card's network list using the following API pseudocode:

* Get a 32-byte network descriptor for the given slot. If it is empty, this is 32 zero bytes:
```
byte[] getNetworkReference(short id) {
  short i = 32*id;
  return networks[i:32+i];
}
```

* Set a 32-byte slice of `networks` using the provided `reference` at the provided index (`32*id`):
```
void setNetworkReference(short id, byte[] reference) {
  short i = 32*id;
  networks[i:32+i] = reference;
}
```

## Deposits

A phonon can be added to the card with the following pseudocode:

```
deposit(long recipientIndex, short assetId, byte[] amount, short networkId) {

  // Check nonce
  validateDeposit(receiptIndex);

  // Derive the private key associated with the deposit address
  // using the same nonce index
  byte[] priv = deriveIdPriv(recipientIndex);
  
  // Instantiate the phonon and put it in the next available storage slot
  Phonon p = new Phonon(priv, assetId, amount, networkId);
  phonons[nextAvailableIndex] = p;
  
}
```

This will re-derive the recipient private key using the index. Recall that this was previously derived so that the user could generate a deposit *address*. We now use the corresponding *private key* as the identifier.

The included data is packed into a `Phonon` and is stored at the first unused index.

> Note that there is a maximum number of phonons which may be stored on a given card. If the card runs out of space, this API call will fail, but the user can store the phonon somewhere else and send it to the card at any time - of course this means the user must also persist the `recipientIndex`, which is not part of the phonon deposit metadata!

### Nonce Tracking

Recall the presence of `globalNonce` to track the last deposit address index that was used. Any deposit **must** be based on a nonce **greater than or equal to** the global nonce at that time:

```
validateDeposit(long n) {
  if (n <= globalNonce) {
    throw new Error();
  } else {
    globalNonce = n;
  }
}
```

This mechanism prevents against replay attacks, whereby a user could deposit the same phonon multiple times - including after sending it. However, the user's software should be careful to issue deposits **in order** of the corresponding deposit address index.

### Network Specificity and Verification

On Ethereum, deposits will correspond to calls to a smart contract, which is responsible for managing balances, deposits, and withdrawals. On Bitcoin, deposits are simply transfers to the deposit address (i.e. they look like any other transaction on the network).

You may have notices that no proofs are needed for deposits. This is because on the Phonon Network, it is the responsibility of the **recipient** to validate the following when receiving a phonon:

1. The asset and network are the same as the recipient is expecting.
2. The value of the phonon is correct.
3. The deposit has a sufficient amount of work (or, more generally, finality) behind it.
4. (Technically optional, but important) The counterparty has a card that the recipient trusts.

If these conditions are satisfied, the recipient can send an "ack" message to the sender (covered later) indicating that he is satisfied with the payment.

## Withdrawals

The card may withdraw a phonon at any time by passing the phonon index and calling the "withdraw" function:

```
byte[] withdraw(short phononIndex, byte[] data) {
  Phonon p = phonons[phononIndex];  
  if (p == null) {
    throw new Error();
  } else {
    return doWithdrawal(p, data);  // Depends on type of network
  }
}
```

This looks up the phonon based on a storage index, which simply indicates where in the card's memory this data is being stored. If no phonon exists at that index, this call will fail.

`data` contains withdrawal parameters, which is the receiving address for Ethereum and is empty for Bitcoin (because the address is specified by the withdrawing party's transaction building software - not the card).

### Ethereum-based Withdrawals

If the provided phonon corresponds to a non-null network descriptor (indicating it is an Ethereum-based network), this function will do the following:

1. Assert that `data` is 20 bytes (it corresponds to the recipient address).
2. Sign a message (`msg`) with the phonon's private key: `sha256(owner, networkDescriptor, assetId, amount, recipient)`. **Note that `amount` here is actually `amount * (10 ** decimals)`!**
3. Sign the same message with the card's identity private key.
4. Remove the phonon at the provided index.

The following serialized payload is expected from a withdrawal:

```
serWithdrawal = [ 
  TLV_NETWORK_DESCRIPTOR,
  NETWORK_DESCRIPTOR_LEN,   // 20
  networkDescriptor,
  TLV_ETH_ADDR,
  ETH_ADDR_LEN,             // 20
  recipient,                // The address to which the withdrawn coins will transfer
  TLV_MSG_HASH, 
  MSG_HASH_LEN,             // 32
  msg,
  TLV_SIGNATURE,
  SIGNATURE_LEN,            // 64
  ownerSig                  // signature (r,s) from `owner` private key on `msg`
]
```

This is all the data needed to withdraw a phonon via a smart contract, which can do the following to verify the withdrawal (see: Ethereum-based Networks section for more details).

#### Signature Recovery Parameter

Ethereum smart contracts do not have the ability to *verify* a signature relative to a public key, but they are able to *recover* a signer based on a signature and message. They do this using a [recovery parameter](https://ethereum.stackexchange.com/questions/57478/generate-v-parameter-in-ethereum-transaction). This is a single bit (value 0 or 1), represented by `v`, which is usually thrown away when a signature is serialized (e.g. using DER format).

Smart cards return a 64-byte signature containing `r` and `s` params, which are 32 bytes each. It does **not** return a `v` value. Therefore, we need to recreate `v`. Although it isn't very well documented, there *is* a way to calculate `v`: see [here](https://ethereum.stackexchange.com/a/53182). 

However, because it is a single bit, we can avoid on-card complexity and just brute force the value on another layer using a mechanism such as the following:

```
let v = 27;
if (pubKey == eth.ecrecover(msg, 27, sig.r, sig.s).toString('hex')) {
  console.log('v is 27');
} else if (pubKey == eth.ecrecover(msg, 28, sig.r, sig.s).toString('hex')) {
  console.log('v is 28');
} else {
  console.log('Signature is invalid');
}
```

The above uses [`ethereumjs-util`](https://www.npmjs.com/package/ethereumjs-util) to perform `ecrecover` on a signature. Although it expects either 27 or 28 for `v`, you can see that its range is still binary. Don't worry too much about the actual values - just find which ones your library is expecting.

Once requesting a withdrawal signature, the interface must do a check such as the above to determine `v` before passing the withdrawal data to the on-chain smart contract.


### Bitcoin Withdrawals

If the provided phonon corresponds to a null network descriptor, we need to create a Bitcoin transaction to withdraw, as there is no smart contract to manage balances on-chain and this balance is simply encumbered by a type of pay to script hash corresponding to the key held in the phonon.

Bitcoin withdrawals must unencumber the coins by signing the transaction input, which is fully described by `txId` and `idx` in the phonon. The following data is then serialized and returned from the card. This data can be packaged into a transaction by the interface. It is therefore up to the interface to determine the network fee and the recipient!

> **IMPORTANT NOTE:** *Unlike Ethereum, Bitcoin withdrawal data does **not** include the recipient! The recipient must be specified in the transaction output by the interface, making a secure interface like the [Lattice](https://gridplus.io/lattice) more important than it is for Ethereum.*

```
serWithdrawal = [
  TLV_TX_ID,
  TX_ID_LEN,           // 32
  txId,
  TLV_UTXO_IDX,
  UTXO_IDX_LEN,        // 1
  idx,
  TLV_SIGNATURE,
  SIGNATURE_LEN,
  signedInput
]
```

**TODO: determine the ramifications of spending via segwit or not. [This document](https://bitcoincore.org/en/2016/01/26/segwit-benefits/) describes segwit spends as not needing to have knowledge of the full transactions. If legacy spends do require knowledge of the full transaction, we should probably only support segwit.**

# On-Chain Settlements

Phonons may be deposited and withdrawn using a settlement smart contract on Ethereum. Network and asset IDs are also stored in a registry on a smart contract, which should function as a source of truth. (The network id should be fixed for a given network).

## Ethereum-based Networks

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

> Assets are generally created and stored on a registry, which can be the same settlement contract. Depending on the design, the contract deployer may wish to restrict access to registry management or open it up to users so that they can add their own tokens (especially useful for NFTs).

### Deposits

Once a user generates one or more deposit addresses from his card, he may send a number of tokens to the contract for deposit. Once the deposit occurs, the user may send a message to his card specifying the parameters used to make the deposit.

In order to deposit one or more tokens to `recipient`, the following logic is performed:

1. Look up the asset using `assetId`. If this maps to an empty asset, the transaction will fail.
2. Look up the balance of the recipient using: `phonons[recipient]`. If this balance is >0, the transaction will fail.
3. Move asset from the sender's account. Depending on the asset type (ERC20 or ERC721), this will call a different method of the underlying contract.

This produces a transaction on the Ethereum network, the contents of which may be sent to the user's card for deposit.

### Withdrawals

The following data is necessary to withdraw a phonon on an Ethereum-based network:

1. `networkDescriptor` - tells the user which network and which contract to withdraw from
2. `recipient` - the receiving address for this withdrawal
3. Message hash (`sha256(owner, networkDescriptor, assetId, amount, recipient)`)
4. Signature of message hash by `owner`

With this data, the contract can do the following:

1. Use `ecrecover` and *(2)* to get the `owner` public key (and address) from *(3)*
2. Find the `Phonon` object associated to the `owner` address recovered above.
3. Use `recipient` and data from steps 1 and 2 to construct the following hash: `sha256(owner, address(this), assetId, amount, recipient)`. This value should match *(3)*.
4. Delete phonon from contract storage and transfer coins to `recipient`.

> Note that the `networkDescriptor` is the settlement contract address, which is validated in step 2 above because smart contracts can identify themselves via `address(this)`.

## Bitcoin Network

As covered in previous sections, no Phonon-based logic happens on the Bitcoin network. Deposits and withdrawals function as normal Bitcoin transactions.

# Transacting on the Phonon Network

Phonons are sent across the Phonon Network using encrypted communication channels that connect any two cards. Because transfers are validated between only two participants, there is no concept of blocks or block times and "consensus" is a single "ack" message.

## Connections

In order for cards on the Phonon Network to communicate, they must form encrypted communication channels using their identity keypairs. Shared secrets are derived via ECDH and are used for symmetric AES encryption.

## Sending

To send a phonon, a card must first serialize its data:

```
serPhonon = [ 
  TLV_NETWORK_DESCRIPTOR,
  NETWORK_DESCRIPTOR_LEN,  // 32 bytes
  networkDescriptor,
  TLV_PRIVATE_KEY, 
  PRIVATE_KEY_LEN,         // 32
  owner,
  TLV_ASSET_ID,
  ASSET_ID_LEN,            // 2
  assetId,
  TLV_TX_ID,
  TX_ID_LEN,               // 32
  txId,
  TLV_UTXO_IDX,
  UTXO_IDX_LEN,            // 1
  idx,
  TLV_PHONON_AMOUNT,
  PHONON_AMOUNT_LEN,       // 4
  amount,
  TLV_PHONON_DECIMALS,
  PHONON_DECIMALS_LEN,     // 2
  decimals
]
```

In this serialization scheme, each parameters is prefixed by:

1. A data type identifier (1-byte TLV)
2. A 1-byte length prefix indicating the number of bytes to follow for that parameter

> The [TLV encoding](https://docs.oracle.com/javacard/3.0.5/api/javacardx/framework/tlv/BERTLV.html) pattern is used mostly because it is an artifact of Java card libraries.

Once serialized, the phonon is deleted from its index in the global `phonons` variable. The serialized payload is encrypted via AES using the shared ECDH secret between the sender and receiver. Once the encrypted payload is returned by the card, the sender's communication interface sends this payload to the recipient's interface along with the sender's card's identity public key.

### Viewing Phonon Data

Because the phonon is *deleted* when the transfer is initiated, the sender could find himself in a situation where the recipient doesn't agree to the value of the phonon and the sender would lose that phonon forever!

To avoid this situation, the card may also serialize the above data **without the private key** (and with the *public key* instead):

```
bytes[] sendPhonon(short phononIdx, bool withPriv) {
  if (withPriv == false) {
    return serialize(phononIdx, false);  // Get data with public key
  } else {
    bytes[] retData = serialize(phononIdx, true);  // Get data with private key
    phonons[phononIdx] = null;    // Delete the phonon
    return resData;
}
```

Using this option, the user may send phonon data for verification without sending the phonon itself.

## Receiving Payment

After receiving the encrypted payload (and sender's identity public key), the recipient's connectivity interface forwards the data to its card. To consume the receipt, the card performs the following:

1. Recreate ECDH secret, decrypt, and deserialize the payload.
2. Derive the public key corresponding to the `owner` private key (in the phonon)
3. Return phonon data: `ownerPubKey`, `networkDescriptor`, `assetId`, `txId`, `idx`, `amount`, and `decimals`

At this point, the recipient may verify that the phonon corresponds to the correct number/type of tokens which exist on the correct network. Once satisfied and ready to store the phonon the recipient calls `receiveTransfer` with the encrypted blob, which decrypts, deserializes, and stores all of the data (including the private key). At this point, the sender should receive the good or service and, ideally, an "ack" message from the receipient.

> Since the phonon data (sans private key) can be inspected without storing the phonon, the recipient may wish to save the phonon data somewhere else. This may be especially useful for a merchant who may be storing too many phonons for his card to handle. If storing the phonon in a different place, it is important that the recipient also store the **counterparty's identity public key** so that the phonon may be decrypted at a later time.

> **NOTE:** This scheme *is* susceptible to malicious behavior. A recipient could claim to never receive the payment and not credit the sender. Like physical cash, once it leaves the sender, it cannot be taken back. Therefore it is recommended that Phonon Network transactions be relatively small in value.

### Storing Phonons Off-Card

Like the sender's "view data" function indicated above, the recipient can also view the phonon data (**not** including the private key) before putting the phonon on his card. This is done by passing the encrypted blob and specifying that the card should not store the phonon contained within.

This option may be advantagous

### Checking Certificates

Although not strictly part of the Phonon Network specification, it is encouraged that interfaces check the certification of counterparty cards. This gives the user confidence that he is transacting with a valid card (i.e. one that is *not* running malicious code).

Any interface is free to implement which certificates to check (e.g. the GridPlus Lattice1 validates the existence of a GridPlus cert) - this could also be configurable for the user, who may trust certain card issuers and not others.
