import {
  Addressable,
  AddressLike,
  AbiCoder,
  BlockTag,
  concat,
  Contract,
  encodeBytes32String,
  getBytes,
  hexlify,
  isHexString,
  JsonRpcProvider,
  keccak256,
  Overrides,
  Provider,
  Signer,
  toBeHex,
  toUtf8Bytes,
  TransactionReceipt,
  zeroPadValue,
} from 'ethers'
import { getContractForNetwork } from './configuration.js'
import {
  address,
  DEFAULT_REGISTRY_ADDRESS,
  interpretIdentifier,
  MESSAGE_PREFIX,
  MetaSignature,
  stringToBytes32,
} from './helpers.js'

/**
 * A class that can be used to interact with the ERC1056 contract on behalf of a local controller key-pair
 */
export class EthrDidController {
  private contract: Contract
  private readonly signer?: Signer
  private readonly address: string
  public readonly did: string
  private readonly legacyNonce: boolean

  /**
   * Creates an EthrDidController instance.
   *
   * @param identifier - required - a `did:ethr` string or a publicKeyHex or an ethereum address
   * @param signer - optional - a Signer that represents the current controller key (owner) of the identifier. If a
   *   'signer' is not provided, then a 'contract' with an attached signer can be used.
   * @param contract - optional - a Contract instance representing a ERC1056 contract. At least one of `contract`,
   *   `provider`, or `rpcUrl` is required
   * @param chainNameOrId - optional - the network name or chainID, defaults to 'mainnet'
   * @param provider - optional - a web3 Provider. At least one of `contract`, `provider`, or `rpcUrl` is required
   * @param rpcUrl - optional - a JSON-RPC URL that can be used to connect to an ethereum network. At least one of
   *   `contract`, `provider`, or `rpcUrl` is required
   * @param registry - optional - The ERC1056 registry address. Defaults to
   *   '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'. Only used with 'provider' or 'rpcUrl'
   * @param legacyNonce - optional - If the legacy nonce tracking method should be accounted for. If lesser version of
   *   did-ethr-registry contract v1.0.0 is used then this should be true.
   */
  constructor(
    identifier: string | address,
    contract?: Contract,
    signer?: Signer,
    chainNameOrId = 'mainnet',
    provider?: Provider,
    rpcUrl?: string,
    registry: string = DEFAULT_REGISTRY_ADDRESS,
    legacyNonce = true
  ) {
    this.legacyNonce = legacyNonce
    // initialize identifier
    const { address, publicKey, network } = interpretIdentifier(identifier)
    const net = network || chainNameOrId
    // initialize contract connection
    if (contract) {
      this.contract = contract
    } else if (provider || signer?.provider || rpcUrl) {
      const prov = provider || signer?.provider
      this.contract = getContractForNetwork({ name: net, provider: prov, registry, rpcUrl })
    } else {
      throw new Error(' either a contract instance or a provider or rpcUrl is required to initialize')
    }
    this.signer = signer
    this.address = address
    let networkString = net ? `${net}:` : ''
    if (networkString in ['mainnet:', '0x1:']) {
      networkString = ''
    }
    this.did = publicKey ? `did:ethr:${networkString}${publicKey}` : `did:ethr:${networkString}${address}`
  }

  /**
   * @returns the encoded attribute value in hex or utf8 bytes
   * @param attrValue - the attribute value to encode (e.g. service endpoint, public key, etc.)
   *
   * @remarks The incoming attribute value may be a hex encoded key, or an utf8 encoded string (like service endpoints)
   **/
  encodeAttributeValue(attrValue: string | `0x${string}`): Uint8Array | `0x${string}` {
    return isHexString(attrValue) ? attrValue : toUtf8Bytes(attrValue)
  }

  async getOwner(address: address, blockTag?: BlockTag): Promise<string> {
    return this.contract.identityOwner(address, { blockTag })
  }

  async attachContract(controller?: AddressLike): Promise<Contract> {
    let currentOwner = controller ? await controller : await this.getOwner(this.address, 'latest')
    if (typeof currentOwner !== 'string') currentOwner = await (controller as Addressable).getAddress()
    let signer
    if (this.signer) {
      signer = this.signer
    } else {
      if (!this.contract) throw new Error(`No contract configured`)
      if (!this.contract.runner) throw new Error(`No runner configured for contract`)
      if (!this.contract.runner.provider) throw new Error(`No provider configured for runner in contract`)
      signer = (await (<JsonRpcProvider>this.contract.runner.provider).getSigner(currentOwner)) || this.contract.signer
    }
    return this.contract.connect(signer) as Contract // Needed because ethers attach returns a BaseContract
  }

  async changeOwner(newOwner: address, options: Overrides = {}): Promise<TransactionReceipt> {
    // console.log(`changing owner for ${oldOwner} on registry at ${registryContract.address}`)
    const overrides = {
      gasLimit: 123456,
      ...options,
    } as Overrides
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from

    const ownerChange = await contract.changeOwner(this.address, newOwner, overrides)
    return await ownerChange.wait()
  }

  async createChangeOwnerHash(newOwner: address) {
    const paddedNonce = await this.getPaddedNonceCompatibility()

    const dataToHash = concat([
      MESSAGE_PREFIX,
      await this.contract.getAddress(),
      paddedNonce,
      this.address,
      getBytes(concat([toUtf8Bytes('changeOwner'), newOwner])),
    ])
    return keccak256(dataToHash)
  }

  async changeOwnerSigned(
    newOwner: address,
    metaSignature: MetaSignature,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      ...options,
    }

    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from

    const ownerChange = await contract.changeOwnerSigned(
      this.address,
      metaSignature.sigV,
      metaSignature.sigR,
      metaSignature.sigS,
      newOwner,
      overrides
    )
    return await ownerChange.wait()
  }

  /**
   * Creates the EIP-712 hash for a changeOwnerWithPubkey operation.
   * This hash is what gets signed by the BLS keypair.
   *
   * Message Structure (Simplified):
   * - Uses 3-field structure: ChangeOwnerWithPubkey(address identity, address oldOwner, address newOwner)
   * - No signer or nonce fields (signature proves ownership, ownership change prevents replays)
   * - Each field serves a specific, necessary purpose:
   *   * identity: identifies which DID is being changed
   *   * oldOwner: the current owner at signing time (proof of authorization + replay protection)
   *   * newOwner: the new owner address to be set
   *
   * Replay Protection Mechanism:
   * - This uses owner-based replay protection instead of nonce-based
   * - The oldOwner field is included in the signed message
   * - If someone changes the owner, old signatures become invalid automatically
   * - Contract enforces: require(oldOwner == identityOwner(identity))
   * - No need to track a nonce counter - ownership state change is the replay protection
   *
   * How it Works:
   * 1. Get current owner: oldOwner = await this.getOwner(identity)
   * 2. Build message: {identity, oldOwner, newOwner}
   * 3. Compute EIP-712 hash using domain separator and struct hash
   * 4. Sign the hash with BLS private key
   * 5. When contract verifies:
   *    - Checks BLS signature is valid for the hash
   *    - Checks oldOwner == current owner (verifies authorization + prevents replay)
   *    - Updates owner to newOwner
   *
   * Security Implications:
   * - Only the current owner can create a valid signature (via BLS key ownership check)
   * - If owner changes between signing and submission, oldOwner check fails
   * - Simpler than traditional nonce-based replay protection
   * - Cleaner security model: signature proves ownership, ownership state provides replay protection
   *
   * @param newOwner - The new owner address to be set
   * @returns The EIP-712 hash ready for signing with BLS private key
   *
   * @throws Error if no provider is configured
   */
  async createChangeOwnerWithPubkeyHash(newOwner: address): Promise<string> {
    const oldOwner = await this.getOwner(this.address)
    const registryAddress = await this.contract.getAddress()

    // Get chain ID
    const provider = this.contract.runner?.provider
    if (!provider) throw new Error('No provider configured')
    const network = await provider.getNetwork()
    const chainId = network.chainId

    // Build the message
    const message = {
      identity: this.address,
      oldOwner,
      newOwner,
    }

    // Compute the hash using EIP-712
    const coder = AbiCoder.defaultAbiCoder()
    const typeHash = keccak256(toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)'))
    const structHash = keccak256(
      coder.encode(
        ['bytes32', 'address', 'address', 'address'],
        [typeHash, message.identity, message.oldOwner, message.newOwner]
      )
    )

    const domainSeparator = keccak256(
      coder.encode(
        ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
        [
          keccak256(toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
          keccak256(toUtf8Bytes('EthereumDIDRegistry')),
          keccak256(toUtf8Bytes('1')),
          chainId,
          registryAddress,
        ]
      )
    )

    return keccak256(concat(['0x1901', domainSeparator, structHash]))
  }

  /**
   * Changes the owner of an identity using a BLS signature.
   *
   * This method submits a BLS-signed owner change transaction to the EthereumDIDRegistry.
   * The signature must be over an EIP-712 hash created with createChangeOwnerWithPubkeyHash().
   *
   * Message Structure:
   * - The signature is over a message with 3 fields: (identity, oldOwner, newOwner)
   * - oldOwner must equal the current owner at verification time
   * - This ensures only the current owner can change ownership
   *
   * Replay Protection:
   * - Signatures use owner-based replay protection
   * - The oldOwner field in the signed message must match the current owner
   * - If ownership changes, the old signature is automatically invalid
   * - Example: if Alice signs "change from alice to bob", and Bob becomes owner,
   *   the signature is no longer valid because oldOwner (alice) != currentOwner (bob)
   * - No nonce counter is needed - ownership state change provides the protection
   *
   * Transaction Flow:
   * 1. Controller calls this method with newOwner, publicKey, signature
   * 2. Fetches current owner: oldOwner = await this.getOwner(identity)
   * 3. Submits transaction: contract.changeOwnerWithPubkey(identity, oldOwner, newOwner, publicKey, signature)
   * 4. Contract verifies:
   *    - BLS signature is valid
   *    - oldOwner matches current owner (prevents use after ownership change)
   *    - newOwner is not address(0)
   * 5. If all checks pass, owner is updated to newOwner
   *
   * Error Handling:
   * - "bad_signature": BLS signature verification failed
   * - "invalid_owner": oldOwner does not match current owner (possibly due to ownership change)
   * - "unauthorized": signer derived from publicKey is not the current owner
   * - "invalid_new_owner": newOwner is address(0)
   * - "unsupported_pubkey_type": publicKey length is not 96 bytes
   *
   * @param newOwner - The new owner address to be set
   * @param publicKey - The BLS12-381 public key (96 bytes for G2 point)
   * @param signature - The BLS signature bytes over the EIP-712 hash
   * @param options - Transaction overrides (gasLimit, from, etc.)
   * @returns The transaction receipt confirming the owner change
   *
   * @throws Error if owner change fails or if transaction is not confirmed
   */
  async changeOwnerWithPubkey(
    newOwner: address,
    publicKey: Uint8Array,
    signature: Uint8Array,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      ...options,
    }

    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from

    // Get the current owner for the signature
    const oldOwner = await this.getOwner(this.address)

    const txResponse = await contract.changeOwnerWithPubkey(
      this.address,
      oldOwner,
      newOwner,
      publicKey,
      signature,
      overrides
    )

    return await txResponse.wait()
  }

  async addDelegate(
    delegateType: string,
    delegateAddress: address,
    exp: number,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      ...options,
    }
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from

    const delegateTypeBytes = stringToBytes32(delegateType)
    const addDelegateTx = await contract.addDelegate(this.address, delegateTypeBytes, delegateAddress, exp, overrides)
    return await addDelegateTx.wait()
  }

  async createAddDelegateHash(delegateType: string, delegateAddress: address, exp: number) {
    const paddedNonce = await this.getPaddedNonceCompatibility()

    const dataToHash = concat([
      MESSAGE_PREFIX,
      await this.contract.getAddress(),
      paddedNonce,
      this.address,
      concat([
        toUtf8Bytes('addDelegate'),
        encodeBytes32String(delegateType),
        delegateAddress,
        zeroPadValue(toBeHex(exp), 32),
      ]),
    ])
    return keccak256(dataToHash)
  }

  async addDelegateSigned(
    delegateType: string,
    delegateAddress: address,
    exp: number,
    metaSignature: MetaSignature,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      ...options,
    }
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from

    const delegateTypeBytes = stringToBytes32(delegateType)
    const addDelegateTx = await contract.addDelegateSigned(
      this.address,
      metaSignature.sigV,
      metaSignature.sigR,
      metaSignature.sigS,
      delegateTypeBytes,
      delegateAddress,
      exp,
      overrides
    )
    return await addDelegateTx.wait()
  }

  async revokeDelegate(
    delegateType: string,
    delegateAddress: address,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      ...options,
    }
    delegateType = delegateType.startsWith('0x') ? delegateType : stringToBytes32(delegateType)
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from
    const addDelegateTx = await contract.revokeDelegate(this.address, delegateType, delegateAddress, overrides)
    return await addDelegateTx.wait()
  }

  async createRevokeDelegateHash(delegateType: string, delegateAddress: address) {
    const paddedNonce = await this.getPaddedNonceCompatibility()

    const dataToHash = concat([
      MESSAGE_PREFIX,
      await this.contract.getAddress(),
      paddedNonce,
      this.address,
      getBytes(concat([toUtf8Bytes('revokeDelegate'), encodeBytes32String(delegateType), delegateAddress])),
    ])
    return keccak256(dataToHash)
  }

  async revokeDelegateSigned(
    delegateType: string,
    delegateAddress: address,
    metaSignature: MetaSignature,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      ...options,
    }
    delegateType = delegateType.startsWith('0x') ? delegateType : stringToBytes32(delegateType)
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from
    const addDelegateTx = await contract.revokeDelegateSigned(
      this.address,
      metaSignature.sigV,
      metaSignature.sigR,
      metaSignature.sigS,
      delegateType,
      delegateAddress,
      overrides
    )
    return await addDelegateTx.wait()
  }

  async setAttribute(
    attrName: string,
    attrValue: string,
    exp: number,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      controller: undefined,
      ...options,
    }
    attrName = attrName.startsWith('0x') ? attrName : stringToBytes32(attrName)
    attrValue = attrValue.startsWith('0x') ? attrValue : hexlify(toUtf8Bytes(attrValue))
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from
    const setAttrTx = await contract.setAttribute(this.address, attrName, attrValue, exp, overrides)
    return await setAttrTx.wait()
  }

  async createSetAttributeHash(attrName: string, attrValue: string, exp: number) {
    const paddedNonce = await this.getPaddedNonceCompatibility(true)
    const encodedValue = this.encodeAttributeValue(attrValue)
    const dataToHash = concat([
      MESSAGE_PREFIX,
      await this.contract.getAddress(),
      paddedNonce,
      this.address,
      concat([
        toUtf8Bytes('setAttribute'),
        encodeBytes32String(attrName),
        encodedValue,
        zeroPadValue(toBeHex(exp), 32),
      ]),
    ])
    return keccak256(dataToHash)
  }

  async setAttributeSigned(
    attrName: string,
    attrValue: string,
    exp: number,
    metaSignature: MetaSignature,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    const overrides = {
      gasLimit: 123456,
      controller: undefined,
      ...options,
    }
    attrName = attrName.startsWith('0x') ? attrName : stringToBytes32(attrName)
    attrValue = attrValue.startsWith('0x') ? attrValue : hexlify(toUtf8Bytes(attrValue))
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from
    const setAttrTx = await contract.setAttributeSigned(
      this.address,
      metaSignature.sigV,
      metaSignature.sigR,
      metaSignature.sigS,
      attrName,
      attrValue,
      exp,
      overrides
    )
    return await setAttrTx.wait()
  }

  async revokeAttribute(attrName: string, attrValue: string, options: Overrides = {}): Promise<TransactionReceipt> {
    // console.log(`revoking attribute ${attrName}(${attrValue}) for ${identity}`)
    const overrides = {
      gasLimit: 123456,
      ...options,
    }
    attrName = attrName.startsWith('0x') ? attrName : stringToBytes32(attrName)
    attrValue = attrValue.startsWith('0x') ? attrValue : hexlify(toUtf8Bytes(attrValue))
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from
    const revokeAttributeTX = await contract.revokeAttribute(this.address, attrName, attrValue, overrides)
    return await revokeAttributeTX.wait()
  }

  async createRevokeAttributeHash(attrName: string, attrValue: string) {
    const paddedNonce = await this.getPaddedNonceCompatibility(true)
    const encodedValue = this.encodeAttributeValue(attrValue)
    const dataToHash = concat([
      MESSAGE_PREFIX,
      await this.contract.getAddress(),
      paddedNonce,
      this.address,
      getBytes(concat([toUtf8Bytes('revokeAttribute'), encodeBytes32String(attrName), encodedValue])),
    ])
    return keccak256(dataToHash)
  }

  /**
   * The legacy version of the ethr-did-registry contract tracks the nonce as a property of the original owner, and not
   * as a property of the signer (current owner). That's why we need to differentiate between deployments here, or
   * otherwise our signature will be computed wrong resulting in a failed TX.
   *
   * Not only that, but the nonce is loaded differently for [set/revoke]AttributeSigned methods.
   */
  private async getPaddedNonceCompatibility(attribute = false) {
    let nonceKey
    if (this.legacyNonce && attribute) {
      nonceKey = this.address
    } else {
      nonceKey = await this.getOwner(this.address)
    }
    return zeroPadValue(toBeHex(await this.contract.nonce(nonceKey)), 32)
  }

  async revokeAttributeSigned(
    attrName: string,
    attrValue: string,
    metaSignature: MetaSignature,
    options: Overrides = {}
  ): Promise<TransactionReceipt> {
    // console.log(`revoking attribute ${attrName}(${attrValue}) for ${identity}`)
    const overrides = {
      gasLimit: 123456,
      ...options,
    }
    attrName = attrName.startsWith('0x') ? attrName : stringToBytes32(attrName)
    attrValue = attrValue.startsWith('0x') ? attrValue : hexlify(toUtf8Bytes(attrValue))
    const contract = await this.attachContract(overrides.from ?? undefined)
    delete overrides.from
    const revokeAttributeTX = await contract.revokeAttributeSigned(
      this.address,
      metaSignature.sigV,
      metaSignature.sigR,
      metaSignature.sigS,
      attrName,
      attrValue,
      overrides
    )
    return await revokeAttributeTX.wait()
  }
}
