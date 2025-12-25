import { bls12_381 as bls } from '@noble/curves/bls12-381';

/**
 * BLS12-381 helper utilities for ethr-did-registry integration
 *
 * The SDK uses @noble/curves/bls12-381 which generates:
 * - G1 public keys (48 bytes compressed)
 * - G2 signatures (96 bytes compressed)
 *
 * The contract uses @onematrix/bls-solidity which expects:
 * - G1 public keys (48 or 96 bytes)
 * - G2 signatures (192 bytes uncompressed) - G2 compression not supported
 */

/**
 * Generate a fresh BLS12-381 keypair
 * @returns Keypair with G1 public key (48 bytes compressed)
 */
export function generateBlsKeypair() {
  const secretKey = bls.utils.randomPrivateKey()  // 32 bytes
  const publicKey = bls.getPublicKey(secretKey)    // 48 bytes (G1 compressed)

  return {
    secretKey,
    publicKey,
    publicKeyHex: '0x' + Buffer.from(publicKey).toString('hex')
  }
}

/**
 * Sign a message with BLS private key
 * @param message Message bytes to sign (typically EIP-712 hash)
 * @param secretKey BLS private key (32 bytes)
 * @returns Signature with both compressed (96B) and expanded (192B) formats
 */
export function signWithBls(message, secretKey) {
  const signature = bls.sign(message, secretKey)  // 96 bytes (G2 compressed)
  const signatureExpanded = expandG2Signature(signature)  // 192 bytes (G2 uncompressed)

  return {
    signature,
    signatureHex: '0x' + Buffer.from(signature).toString('hex'),
    signatureExpanded,
    signatureExpandedHex: '0x' + Buffer.from(signatureExpanded).toString('hex')
  }
}

/**
 * Expand compressed G2 signature (96 bytes) to uncompressed format (192 bytes)
 *
 * The @onematrix/bls-solidity library does not support G2 compression.
 * We need to expand the SDK's compressed G2 signatures to uncompressed format.
 *
 * G2 point format:
 * - Compressed: 96 bytes = x (48 bytes with compression flag)
 * - Uncompressed: 192 bytes = x (96 bytes) + y (96 bytes)
 *
 * @param compressed Compressed G2 signature (96 bytes)
 * @returns Uncompressed G2 signature (192 bytes)
 */
export function expandG2Signature(compressed) {
  if (compressed.length !== 96) {
    throw new Error(`Invalid compressed G2 signature length: ${compressed.length} (expected 96 bytes)`)
  }

  // Use the noble library to decode the compressed signature to a point
  const sigPoint = bls.Signature.fromHex(compressed)

  // Convert to uncompressed format using toRawBytes(false)
  // false = uncompressed format
  const uncompressed = sigPoint.toRawBytes(false)

  if (uncompressed.length !== 192) {
    throw new Error(`Failed to expand G2 signature: got ${uncompressed.length} bytes (expected 192)`)
  }

  return uncompressed
}

/**
 * Verify a BLS signature locally (for testing)
 * @param message Message that was signed
 * @param signature Signature to verify (96 bytes compressed)
 * @param publicKey Public key (48 bytes compressed G1)
 * @returns true if signature is valid
 */
export function verifyBlsSignature(message, signature, publicKey) {
  try {
    return bls.verify(signature, message, publicKey)
  } catch (error) {
    return false
  }
}

/**
 * Derive Ethereum address from G1 public key
 * @param publicKey G1 public key (48 bytes compressed or 96 bytes uncompressed)
 * @returns Ethereum address (20 bytes)
 */
export function deriveAddressFromG1(publicKey) {
  let uncompressedKey

  if (publicKey.length === 48) {
    // Expand compressed G1 to uncompressed
    const point = bls.G1.ProjectivePoint.fromHex(publicKey)
    uncompressedKey = point.toRawBytes(false)  // false = uncompressed
  } else if (publicKey.length === 96) {
    uncompressedKey = publicKey
  } else {
    throw new Error(`Invalid G1 public key length: ${publicKey.length} (expected 48 or 96 bytes)`)
  }

  // Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey)
  const { keccak_256 } = require('@noble/hashes/sha3')
  const hash = keccak_256(uncompressedKey)
  const address = hash.slice(-20)

  return '0x' + Buffer.from(address).toString('hex')
}
