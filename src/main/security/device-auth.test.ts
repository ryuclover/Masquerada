import {
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  createDeviceAuthChallengeSigner,
  DEVICE_AUTH_CHALLENGE_BYTES,
  DEVICE_AUTH_PUBLIC_KEY_MAX_BYTES,
  DEVICE_AUTH_SIGNATURE_BYTES,
  generateDeviceAuthChallenge,
  verifyDeviceAuthSignature,
  type DeviceAuthErrorCode
} from './device-auth'

describe('prova de posse da identidade do dispositivo', () => {
  it('verifica uma assinatura válida', () => {
    const identity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()

    const signature = identity.signChallenge(challenge)

    expect(signature).toHaveLength(DEVICE_AUTH_SIGNATURE_BYTES)
    expect(verifyDeviceAuthSignature(identity.publicKeySpki, challenge, signature)).toBe(true)
  })

  it('não verifica a assinatura com challenge diferente', () => {
    const identity = createTestIdentity()
    const originalChallenge = generateDeviceAuthChallenge()
    const differentChallenge = generateDeviceAuthChallenge()
    const signature = identity.signChallenge(originalChallenge)

    expect(verifyDeviceAuthSignature(identity.publicKeySpki, differentChallenge, signature)).toBe(
      false
    )
  })

  it('não verifica a assinatura com outra public key', () => {
    const firstIdentity = createTestIdentity()
    const secondIdentity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()
    const signature = firstIdentity.signChallenge(challenge)

    expect(verifyDeviceAuthSignature(secondIdentity.publicKeySpki, challenge, signature)).toBe(
      false
    )
  })

  it('não verifica uma assinatura adulterada', () => {
    const identity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()
    const signature = identity.signChallenge(challenge)
    signature[0] = (signature[0] ?? 0) ^ 0x01

    expect(verifyDeviceAuthSignature(identity.publicKeySpki, challenge, signature)).toBe(false)
  })

  it('rejeita uma assinatura truncada', () => {
    const identity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()
    const signature = identity.signChallenge(challenge).subarray(0, DEVICE_AUTH_SIGNATURE_BYTES - 1)

    expectDeviceAuthError(
      () => verifyDeviceAuthSignature(identity.publicKeySpki, challenge, signature),
      'DEVICE_AUTH_INVALID_SIGNATURE'
    )
  })

  it('rejeita assinatura que não seja Buffer sem coerção silenciosa', () => {
    const identity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()
    const signature = new Uint8Array(DEVICE_AUTH_SIGNATURE_BYTES) as unknown as Buffer

    expectDeviceAuthError(
      () => verifyDeviceAuthSignature(identity.publicKeySpki, challenge, signature),
      'DEVICE_AUTH_INVALID_SIGNATURE'
    )
  })

  it('rejeita challenges com tamanho diferente do formato canônico', () => {
    const identity = createTestIdentity()

    for (const invalidLength of [0, DEVICE_AUTH_CHALLENGE_BYTES - 1, DEVICE_AUTH_CHALLENGE_BYTES + 1]) {
      expectDeviceAuthError(
        () => identity.signChallenge(Buffer.alloc(invalidLength)),
        'DEVICE_AUTH_INVALID_CHALLENGE'
      )
    }
  })

  it('rejeita challenge que não seja Buffer sem coerção silenciosa', () => {
    const identity = createTestIdentity()
    const challenge = new Uint8Array(DEVICE_AUTH_CHALLENGE_BYTES) as unknown as Buffer

    expectDeviceAuthError(
      () => identity.signChallenge(challenge),
      'DEVICE_AUTH_INVALID_CHALLENGE'
    )
  })

  it('rejeita public key malformada ou não canônica', () => {
    const identity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()
    const signature = identity.signChallenge(challenge)
    const nonCanonicalSpki = Buffer.concat([identity.publicKeySpki, Buffer.from([0])])

    expectDeviceAuthError(
      () => verifyDeviceAuthSignature(Buffer.alloc(44), challenge, signature),
      'DEVICE_AUTH_INVALID_PUBLIC_KEY'
    )
    expectDeviceAuthError(
      () => verifyDeviceAuthSignature(nonCanonicalSpki, challenge, signature),
      'DEVICE_AUTH_INVALID_PUBLIC_KEY'
    )
    expectDeviceAuthError(
      () =>
        verifyDeviceAuthSignature(
          Buffer.alloc(DEVICE_AUTH_PUBLIC_KEY_MAX_BYTES + 1),
          challenge,
          signature
        ),
      'DEVICE_AUTH_INVALID_PUBLIC_KEY'
    )
  })

  it('rejeita uma public key válida de algoritmo diferente', () => {
    const identity = createTestIdentity()
    const challenge = generateDeviceAuthChallenge()
    const signature = identity.signChallenge(challenge)
    const otherAlgorithm = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const otherPublicKeySpki = exportPublicKeySpki(otherAlgorithm.publicKey)

    expectDeviceAuthError(
      () => verifyDeviceAuthSignature(otherPublicKeySpki, challenge, signature),
      'DEVICE_AUTH_INVALID_PUBLIC_KEY'
    )
  })

  it('não cria signer com private key de outro algoritmo', () => {
    const otherAlgorithm = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })

    expectDeviceAuthError(
      () => createDeviceAuthChallengeSigner(otherAlgorithm.privateKey),
      'DEVICE_AUTH_INVALID_PRIVATE_KEY'
    )
  })

  it('aplica domain separation à mensagem assinada', () => {
    const keyPair = generateKeyPairSync('ed25519')
    const publicKeySpki = exportPublicKeySpki(keyPair.publicKey)
    const challenge = generateDeviceAuthChallenge()
    const signature = createDeviceAuthChallengeSigner(keyPair.privateKey)(challenge)
    const otherDomainMessage = Buffer.concat([
      Buffer.from('Masquerada/device-auth/v2', 'utf8'),
      challenge
    ])

    expect(verify(null, challenge, keyPair.publicKey, signature)).toBe(false)
    expect(verify(null, otherDomainMessage, keyPair.publicKey, signature)).toBe(false)

    const rawChallengeSignature = sign(null, challenge, keyPair.privateKey)
    expect(verifyDeviceAuthSignature(publicKeySpki, challenge, rawChallengeSignature)).toBe(false)
  })

  it('gera challenges binários de tamanho fixo e diferentes em chamadas sucessivas', () => {
    const firstChallenge = generateDeviceAuthChallenge()
    const secondChallenge = generateDeviceAuthChallenge()

    expect(Buffer.isBuffer(firstChallenge)).toBe(true)
    expect(firstChallenge).toHaveLength(DEVICE_AUTH_CHALLENGE_BYTES)
    expect(firstChallenge.equals(secondChallenge)).toBe(false)
  })

  it('mantém limites públicos explícitos e restritos', () => {
    expect(DEVICE_AUTH_CHALLENGE_BYTES).toBe(32)
    expect(DEVICE_AUTH_SIGNATURE_BYTES).toBe(64)
    expect(DEVICE_AUTH_PUBLIC_KEY_MAX_BYTES).toBe(128)
  })
})

function createTestIdentity(): {
  publicKeySpki: Buffer
  signChallenge: (challenge: Buffer) => Buffer
} {
  const keyPair = generateKeyPairSync('ed25519')

  return {
    publicKeySpki: exportPublicKeySpki(keyPair.publicKey),
    signChallenge: createDeviceAuthChallengeSigner(keyPair.privateKey)
  }
}

function exportPublicKeySpki(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: 'der', type: 'spki' })
}

function expectDeviceAuthError(operation: () => unknown, code: DeviceAuthErrorCode): void {
  expect(operation).toThrowError(expect.objectContaining({ code }))
}
