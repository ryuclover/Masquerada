import {
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

const DEVICE_AUTH_DOMAIN = Buffer.from('Masquerada/device-auth/v1', 'utf8')
const LENGTH_PREFIX_BYTES = 2

export const DEVICE_AUTH_CHALLENGE_BYTES = 32
export const DEVICE_AUTH_SIGNATURE_BYTES = 64
export const DEVICE_AUTH_PUBLIC_KEY_MAX_BYTES = 128

export type DeviceAuthErrorCode =
  | 'DEVICE_AUTH_INVALID_CHALLENGE'
  | 'DEVICE_AUTH_INVALID_SIGNATURE'
  | 'DEVICE_AUTH_INVALID_PUBLIC_KEY'
  | 'DEVICE_AUTH_INVALID_PRIVATE_KEY'
  | 'DEVICE_AUTH_SIGNING_FAILED'

const ERROR_MESSAGES: Record<DeviceAuthErrorCode, string> = {
  DEVICE_AUTH_INVALID_CHALLENGE: 'O challenge de autenticação do dispositivo é inválido.',
  DEVICE_AUTH_INVALID_SIGNATURE: 'A assinatura de autenticação do dispositivo é inválida.',
  DEVICE_AUTH_INVALID_PUBLIC_KEY: 'A public key de autenticação do dispositivo é inválida.',
  DEVICE_AUTH_INVALID_PRIVATE_KEY: 'A private key da identidade do dispositivo é inválida.',
  DEVICE_AUTH_SIGNING_FAILED: 'Não foi possível assinar o challenge de autenticação.'
}

export class DeviceAuthError extends Error {
  readonly code: DeviceAuthErrorCode

  constructor(code: DeviceAuthErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'DeviceAuthError'
    this.code = code
  }
}

export type SignDeviceAuthChallenge = (challenge: Buffer) => Buffer

export function generateDeviceAuthChallenge(): Buffer {
  return randomBytes(DEVICE_AUTH_CHALLENGE_BYTES)
}

export function createDeviceAuthChallengeSigner(
  privateKey: KeyObject
): SignDeviceAuthChallenge {
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new DeviceAuthError('DEVICE_AUTH_INVALID_PRIVATE_KEY')
  }

  return (challenge: Buffer): Buffer => {
    const message = createDeviceAuthMessage(challenge)
    let signature: Buffer

    try {
      signature = sign(null, message, privateKey)
    } catch {
      throw new DeviceAuthError('DEVICE_AUTH_SIGNING_FAILED')
    }

    if (signature.length !== DEVICE_AUTH_SIGNATURE_BYTES) {
      throw new DeviceAuthError('DEVICE_AUTH_SIGNING_FAILED')
    }

    return signature
  }
}

export function verifyDeviceAuthSignature(
  publicKeySpki: Buffer,
  challenge: Buffer,
  signature: Buffer
): boolean {
  const publicKey = parseDeviceAuthPublicKey(publicKeySpki)
  const message = createDeviceAuthMessage(challenge)
  assertExactBufferLength(
    signature,
    DEVICE_AUTH_SIGNATURE_BYTES,
    'DEVICE_AUTH_INVALID_SIGNATURE'
  )

  return verify(null, message, publicKey, signature)
}

function createDeviceAuthMessage(challenge: Buffer): Buffer {
  assertExactBufferLength(
    challenge,
    DEVICE_AUTH_CHALLENGE_BYTES,
    'DEVICE_AUTH_INVALID_CHALLENGE'
  )

  const message = Buffer.alloc(
    LENGTH_PREFIX_BYTES +
      DEVICE_AUTH_DOMAIN.length +
      LENGTH_PREFIX_BYTES +
      DEVICE_AUTH_CHALLENGE_BYTES
  )
  let offset = 0

  offset = message.writeUInt16BE(DEVICE_AUTH_DOMAIN.length, offset)
  offset += DEVICE_AUTH_DOMAIN.copy(message, offset)
  offset = message.writeUInt16BE(DEVICE_AUTH_CHALLENGE_BYTES, offset)
  challenge.copy(message, offset)

  return message
}

function parseDeviceAuthPublicKey(publicKeySpki: Buffer): KeyObject {
  if (
    !Buffer.isBuffer(publicKeySpki) ||
    publicKeySpki.length === 0 ||
    publicKeySpki.length > DEVICE_AUTH_PUBLIC_KEY_MAX_BYTES
  ) {
    throw new DeviceAuthError('DEVICE_AUTH_INVALID_PUBLIC_KEY')
  }

  try {
    const publicKey = createPublicKey({ key: publicKeySpki, format: 'der', type: 'spki' })
    const canonicalSpki = publicKey.export({ format: 'der', type: 'spki' })

    if (
      publicKey.type !== 'public' ||
      publicKey.asymmetricKeyType !== 'ed25519' ||
      !canonicalSpki.equals(publicKeySpki)
    ) {
      throw new DeviceAuthError('DEVICE_AUTH_INVALID_PUBLIC_KEY')
    }

    return publicKey
  } catch (error) {
    if (error instanceof DeviceAuthError) {
      throw error
    }

    throw new DeviceAuthError('DEVICE_AUTH_INVALID_PUBLIC_KEY')
  }
}

function assertExactBufferLength(
  value: Buffer,
  expectedLength: number,
  errorCode: 'DEVICE_AUTH_INVALID_CHALLENGE' | 'DEVICE_AUTH_INVALID_SIGNATURE'
): void {
  if (!Buffer.isBuffer(value) || value.length !== expectedLength) {
    throw new DeviceAuthError(errorCode)
  }
}

