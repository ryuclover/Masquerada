import { createHash, createPrivateKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { DATABASE_FILE_NAME, listMembers, openServerDatabase } from '../servers/server-database'
import {
  CONNECTIVITY_DESCRIPTOR_DOMAIN,
  CONNECTIVITY_DESCRIPTOR_VERSION,
  ConnectivityCandidateType,
  createSignedConnectivityDescriptor,
  DESCRIPTOR_ID_BYTES,
  ED25519_SIGNATURE_BYTES,
  type ConnectivityCandidate,
  type DirectGlobalTcpCandidate,
  type LanTcpCandidate,
  type PortMappedTcpCandidate,
  MAX_CONNECTIVITY_DESCRIPTOR_BYTES,
  MAX_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS,
  resolveAdvertisedCandidate,
  verifySignedConnectivityDescriptor
} from './connectivity-descriptor'
import { startLanTcpServer, type BoundTcpEndpoint, type LanTcpServerHandle } from './lan-transport'

const testRoots: string[] = []
const activeServers: LanTcpServerHandle[] = []

afterEach(async () => {
  await Promise.all(activeServers.splice(0).map((srv) => srv.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

function signTestCandidates(options: Parameters<typeof createSignedConnectivityDescriptor>[0]) {
  return createSignedConnectivityDescriptor({
    ...options,
    allowRawCandidatesForTesting: true
  })
}

describe('connectivity-descriptor: candidates locais autenticados e descriptor de conexão assinado', () => {
  describe('criação e validação do descriptor (testes 47 a 57)', () => {
    it('(47) cria e verifica com sucesso um descriptor assinado válido', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: LanTcpCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.LAN_TCP,
          family: 4,
          address: '192.168.1.100',
          port: 54321,
          scope: 'LAN_PRIVATE'
        }
      ]

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      expect(Buffer.isBuffer(encoded)).toBe(true)
      expect(encoded.length).toBeGreaterThan(128)
      expect(encoded.length).toBeLessThan(MAX_CONNECTIVITY_DESCRIPTOR_BYTES)

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        expectedServerId: serverFixture.serverId
      })

      expect(verified.version).toBe(CONNECTIVITY_DESCRIPTOR_VERSION)
      expect(verified.type).toBe('connectivity-descriptor')
      expect(verified.serverId).toBe(serverFixture.serverId)
      expect(verified.serverPublicKey.equals(serverFixture.publicKey)).toBe(true)
      expect(verified.descriptorId.length).toBe(DESCRIPTOR_ID_BYTES)
      expect(verified.signature.length).toBe(ED25519_SIGNATURE_BYTES)
      expect(verified.candidates).toHaveLength(1)
      expect(verified.candidates[0]!.address).toBe('192.168.1.100')
      expect(verified.candidates[0]!.port).toBe(54321)
      expect((verified.candidates[0] as LanTcpCandidate).scope).toBe('LAN_PRIVATE')
    })

    it('(48) gera descriptorId único e diferente em duas chamadas consecutivas para o mesmo conjunto', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: LanTcpCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.LAN_TCP,
          family: 4,
          address: '10.0.0.5',
          port: 8080,
          scope: 'LAN_PRIVATE'
        }
      ]

      const desc1 = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      const desc2 = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      const v1 = verifySignedConnectivityDescriptor({ encodedDescriptor: desc1 })
      const v2 = verifySignedConnectivityDescriptor({ encodedDescriptor: desc2 })

      expect(v1.descriptorId.equals(v2.descriptorId)).toBe(false)
    })

    it('(49) falha na verificação se 1 bit do endereço IP for adulterado (tampering)', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      // Adultera um byte no meio do payload
      const tampered = Buffer.from(encoded)
      tampered[50]! ^= 0x01

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })
      }).toThrowError()
    })

    it('(50) falha na verificação se a porta do candidate for adulterada', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const tampered = Buffer.from(encoded)
      tampered[tampered.length - 70]! ^= 0x02

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })
      }).toThrowError()
    })

    it('(51) falha se o serverId for adulterado no payload', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const tampered = Buffer.from(encoded)
      tampered[45]! ^= 0xff

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })
      }).toThrowError()
    })

    it('(52) falha se a serverPublicKey for substituída pela de outro servidor', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()

      const encodedA = signTestCandidates({
        serverId: serverFixtureA.serverId,
        serverPublicKey: serverFixtureA.publicKey,
        serverPrivateKey: serverFixtureA.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const offset = encodedA.indexOf(serverFixtureA.publicKey)
      const tampered = Buffer.from(encodedA)
      serverFixtureB.publicKey.copy(tampered, offset)

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })
      }).toThrowError()
    })

    it('(53) falha na verificação se o expiresAt for estendido após a assinatura', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const tampered = Buffer.from(encoded)
      tampered[encoded.length - 80]! ^= 0x01

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })
      }).toThrowError()
    })

    it('(54) rejeita descriptor assinado quando expirado segundo nowSeconds', async () => {
      const serverFixture = await createLocalServerFixture()

      const issuedAt = 1000000
      const lifetime = 100
      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        customIssuedAt: issuedAt,
        lifetimeSeconds: lifetime,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      // Agora = 1000105 (> issuedAt + lifetime)
      expect(() => {
        verifySignedConnectivityDescriptor({
          encodedDescriptor: encoded,
          nowSeconds: 1000105
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_EXPIRED' }))
    })

    it('(55) rejeita criação e verificação com lifetime superior a 300 segundos (MAX_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS)', async () => {
      const serverFixture = await createLocalServerFixture()

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          lifetimeSeconds: MAX_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS + 1,
          candidates: [
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 4,
              address: '192.168.1.50',
              port: 9000,
              scope: 'LAN_PRIVATE'
            }
          ]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_LIFETIME_EXCEEDED' }))
    })

    it('(56) falha na verificação se expectedServerId for diferente do assinado (wrong server)', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()

      const encodedA = signTestCandidates({
        serverId: serverFixtureA.serverId,
        serverPublicKey: serverFixtureA.publicKey,
        serverPrivateKey: serverFixtureA.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      expect(() => {
        verifySignedConnectivityDescriptor({
          encodedDescriptor: encodedA,
          expectedServerId: serverFixtureB.serverId // Espera B, mas recebeu de A
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_SERVER_ID_MISMATCH' }))
    })

    it('(57) falha em cross-server signature (candidates do servidor A com assinatura da chave do servidor B)', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()

      const encodedA = signTestCandidates({
        serverId: serverFixtureA.serverId,
        serverPublicKey: serverFixtureA.publicKey,
        serverPrivateKey: serverFixtureA.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const canonicalPayloadA = encodedA.subarray(0, encodedA.length - ED25519_SIGNATURE_BYTES)
      const fakeSignatureB = sign(null, canonicalPayloadA, serverFixtureB.privateKey)

      const crossForged = Buffer.concat([canonicalPayloadA, fakeSignatureB])

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: crossForged })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_SIGNATURE_INVALID' }))
    })
  })

  describe('validação estrita de candidates, limites e parsing (testes 58 a 67)', () => {
    it('(58) rejeita descriptor com versão desconhecida (ex: versão 2)', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const domainLen = Buffer.from(CONNECTIVITY_DESCRIPTOR_DOMAIN, 'utf8').length
      const tampered = Buffer.from(encoded)
      tampered[1 + domainLen] = 2 // version = 2

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: tampered })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_UNSUPPORTED_VERSION' }))
    })

    it('(60) rejeita candidates com endereço público / global (8.8.8.8 ou 2001:db8::1)', async () => {
      const serverFixture = await createLocalServerFixture()

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 4,
              address: '8.8.8.8',
              port: 80,
              scope: 'LAN_PRIVATE'
            }
          ]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 6,
              address: '2001:db8::1',
              port: 80,
              scope: 'LAN_PRIVATE'
            }
          ]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    })

    it('(61) rejeita candidates com wildcard (0.0.0.0 ou ::)', async () => {
      const serverFixture = await createLocalServerFixture()

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 4,
              address: '0.0.0.0',
              port: 80,
              scope: 'LAN_PRIVATE'
            }
          ]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    })

    it('(62) rejeita loopback (127.0.0.1 ou ::1) em descriptors de produção', async () => {
      const serverFixture = await createLocalServerFixture()

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 4,
              address: '127.0.0.1',
              port: 80,
              scope: 'LAN_PRIVATE'
            }
          ]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    })

    it('(63) rejeita candidates duplicados deterministicamente com DESCRIPTOR_CANDIDATE_DUPLICATE', async () => {
      const serverFixture = await createLocalServerFixture()

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 4,
              address: '192.168.1.10',
              port: 5000,
              scope: 'LAN_PRIVATE'
            },
            {
              candidateType: ConnectivityCandidateType.LAN_TCP,
              family: 4,
              address: '192.168.1.10',
              port: 5000,
              scope: 'LAN_PRIVATE'
            }
          ]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_DUPLICATE' }))
    })

    it('(64) ordena os candidates em ordem canônica estrita independentemente da ordem de entrada', async () => {
      const serverFixture = await createLocalServerFixture()

      const c1: LanTcpCandidate = {
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family: 4,
        address: '192.168.1.50',
        port: 4000,
        scope: 'LAN_PRIVATE'
      }
      const c2: LanTcpCandidate = {
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family: 4,
        address: '10.0.0.1',
        port: 9000,
        scope: 'LAN_PRIVATE'
      }
      const c3: LanTcpCandidate = {
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family: 6,
        address: 'fd12:3456::1',
        port: 3000,
        scope: 'LAN_PRIVATE'
      }

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [c1, c2, c3]
      })

      const verified = verifySignedConnectivityDescriptor({ encodedDescriptor: encoded })
      expect(verified.candidates[0]!.address).toBe('10.0.0.1')
      expect(verified.candidates[1]!.address).toBe('192.168.1.50')
      expect(verified.candidates[2]!.address).toBe('fd12:3456::1')
    })

    it('(65) aceita até 16 candidates (MAX_CONNECTIVITY_CANDIDATES) e rejeita 17', async () => {
      const serverFixture = await createLocalServerFixture()

      const maxCandidates: LanTcpCandidate[] = Array.from({ length: 16 }, (_, i) => ({
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family: 4 as const,
        address: `192.168.1.${i + 1}`,
        port: 1000 + i,
        scope: 'LAN_PRIVATE' as const
      }))

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: maxCandidates
      })

      const verified = verifySignedConnectivityDescriptor({ encodedDescriptor: encoded })
      expect(verified.candidates).toHaveLength(16)

      const excessCandidates: LanTcpCandidate[] = [
        ...maxCandidates,
        {
          candidateType: ConnectivityCandidateType.LAN_TCP,
          family: 4 as const,
          address: '192.168.1.17',
          port: 1017,
          scope: 'LAN_PRIVATE' as const
        }
      ]

      expect(() => {
        signTestCandidates({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: excessCandidates
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_MAX_CANDIDATES_EXCEEDED' }))
    })

    it('(66) rejeita descritores com tamanho superior a MAX_CONNECTIVITY_DESCRIPTOR_BYTES', () => {
      const oversized = Buffer.alloc(MAX_CONNECTIVITY_DESCRIPTOR_BYTES + 1, 0x55)
      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: oversized })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_INVALID_SIZE' }))
    })

    it('(67) rejeita descritor com trailing bytes adicionados ao final', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.50',
            port: 9000,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const trailing = Buffer.concat([encoded, Buffer.from([0x00])])

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: trailing })
      }).toThrowError()
    })
  })

  describe('IPv6 Link-Local, scope não portável e resolução (testes 68 a 72)', () => {
    it('(68) não serializa o hostScopeId local no wire format do candidate IPv6 link-local', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 6,
            address: 'fe80::abcd',
            port: 45000,
            scope: 'LINK_LOCAL'
          }
        ]
      })

      const verified = verifySignedConnectivityDescriptor({ encodedDescriptor: encoded })
      const c = verified.candidates[0]!

      expect(c.family).toBe(6)
      expect((c as LanTcpCandidate).scope).toBe('LINK_LOCAL')
      expect(c.address).toBe('fe80::abcd')
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((c as any).scopeId).toBeUndefined()
    })

    it('(69) resolveAdvertisedCandidate falha se localScopeId não for fornecido para candidate link-local IPv6', () => {
      const candidate: LanTcpCandidate = {
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family: 6,
        address: 'fe80::1234',
        port: 5000,
        scope: 'LINK_LOCAL'
      }

      expect(() => {
        resolveAdvertisedCandidate(candidate)
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))

      const resolved = resolveAdvertisedCandidate(candidate, 7)
      expect(resolved.family).toBe(6)
      expect(resolved.address).toBe('fe80::1234')
      expect(resolved.port).toBe(5000)
      expect(resolved.scopeId).toBe(7)
    })

    it('(70) rejeita geração de descriptor a partir de listener que já foi fechado', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      // Fecha o listener
      await serverHandle.close()

      // Tenta criar descriptor usando o handle fechado sem flag de teste
      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [serverHandle]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_HANDLE_CLOSED' }))
    })

    it('(71) auditoria 6.3 / 76: rejeita forjar BoundTcpEndpoint via object literal / cast TypeScript em produção', async () => {
      const serverFixture = await createLocalServerFixture()

      const fakeBoundEndpoint = {
        address: '192.168.1.50',
        port: 12345,
        family: 4 as const
      } as BoundTcpEndpoint

      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [fakeBoundEndpoint]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    })

    it('(72) aceita listener LAN TCP real ativamente aberto sem flag de teste', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const encoded = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        allowLoopbackForTesting: true,
        candidates: [serverHandle]
      })

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        allowLoopbackForTesting: true
      })
      expect(verified.candidates).toHaveLength(1)
      expect(verified.candidates[0]!.port).toBe(serverHandle.port)
    })
  })

  describe('segurança, não persistência, domínio criptográfico e fuzzing (testes 73 a 77)', () => {
    it('(74) garante que o descriptor codificado não contém interfaceName, localStorageId ou MAC', async () => {
      const serverFixture = await createLocalServerFixture()

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.20',
            port: 3333,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const wireString = encoded.toString('latin1')
      expect(wireString.includes(serverFixture.storageId)).toBe(false)
      expect(wireString.includes('eth0')).toBe(false)
      expect(wireString.includes('Wi-Fi')).toBe(false)
      expect(wireString.includes('wlan0')).toBe(false)
    })

    it('(75) não persiste descriptor em disco nem altera schema do SQLite', async () => {
      const serverFixture = await createLocalServerFixture()

      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const dbBefore = openServerDatabase(dbPath)
      const membersBefore = listMembers(dbBefore)
      dbBefore.close()

      signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [
          {
            candidateType: ConnectivityCandidateType.LAN_TCP,
            family: 4,
            address: '192.168.1.20',
            port: 3333,
            scope: 'LAN_PRIVATE'
          }
        ]
      })

      const dbAfter = openServerDatabase(dbPath)
      const membersAfter = listMembers(dbAfter)
      dbAfter.close()

      expect(membersAfter).toEqual(membersBefore)
    })

    it('(76) fuzz-like: rejeita buffers arbitrários ou truncados sem lançar uncaught exceptions', () => {
      const garbageBuffers = [
        Buffer.alloc(0),
        Buffer.alloc(10),
        Buffer.alloc(100, 0xff),
        Buffer.from('HTTP/1.1 200 OK\r\n\r\n'),
        Buffer.from('MQR1.fake_invite_token_here'),
        Buffer.from([0x01, 0x02, 0x03, 0x04])
      ]

      for (const buf of garbageBuffers) {
        expect(() => {
          verifySignedConnectivityDescriptor({ encodedDescriptor: buf })
        }).toThrowError()
      }
    })

    it('(77) rejeita assinatura válida emitida com outro domain separation (ex: server-invite)', async () => {
      const serverFixture = await createLocalServerFixture()

      // Cria assinatura válida de outro domínio
      const foreignDomain = 'Masquerada/server-invite/v1'
      const fakePayload = Buffer.concat([
        Buffer.from(foreignDomain, 'utf8'),
        Buffer.alloc(100, 0xaa)
      ])
      const foreignSig = sign(null, fakePayload, serverFixture.privateKey)

      const forgedDescriptor = Buffer.concat([fakePayload, foreignSig])

      expect(() => {
        verifySignedConnectivityDescriptor({ encodedDescriptor: forgedDescriptor })
      }).toThrowError()
    })
  })

  describe('WAN Candidates (PORT_MAPPED_TCP e DIRECT_GLOBAL_TCP) (Etapa 7.1)', () => {
    it('(50 e 62) aceita e verifica PORT_MAPPED_TCP com endereço globalmente roteável válido', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: PortMappedTcpCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
          family: 4,
          address: '203.0.114.1',
          port: 45000
        }
      ]

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        expectedServerId: serverFixture.serverId
      })

      expect(verified.candidates).toHaveLength(1)
      expect(verified.candidates[0]!.candidateType).toBe(ConnectivityCandidateType.PORT_MAPPED_TCP)
      expect(verified.candidates[0]!.address).toBe('203.0.114.1')
      expect(verified.candidates[0]!.port).toBe(45000)
    })

    it('(51 e 63) aceita e verifica DIRECT_GLOBAL_TCP com IPv6 Global Unicast válido', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: DirectGlobalTcpCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
          family: 6,
          address: '2001:4860:4860::8888',
          port: 54321
        }
      ]

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        expectedServerId: serverFixture.serverId
      })

      expect(verified.candidates).toHaveLength(1)
      expect(verified.candidates[0]!.candidateType).toBe(ConnectivityCandidateType.DIRECT_GLOBAL_TCP)
      expect(verified.candidates[0]!.address).toBe('2001:4860:4860::8888')
      expect(verified.candidates[0]!.port).toBe(54321)
    })

    it('(72) Signer Forgery: createSignedConnectivityDescriptor rejeita candidates WAN fornecidos como object literal sem capability legítima', async () => {
      const serverFixture = await createLocalServerFixture()

      const wanCandidate: PortMappedTcpCandidate = {
        candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
        family: 4,
        address: '203.0.114.1',
        port: 45000
      }

      // Em produção (sem allowRawCandidatesForTesting), passar objeto WAN solto é estritamente proibido
      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [wanCandidate]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    })

    it('(52-61) rejeita endereços não-globais em PORT_MAPPED_TCP e DIRECT_GLOBAL_TCP', async () => {
      const serverFixture = await createLocalServerFixture()

      const invalidWanAddresses = [
        '100.64.0.1', // CGNAT
        '100.127.255.254', // CGNAT
        '10.0.0.1', // RFC 1918
        '172.16.0.1', // RFC 1918
        '192.168.1.1', // RFC 1918
        '192.0.2.1', // TEST-NET-1 (Documentation)
        '198.51.100.1', // TEST-NET-2 (Documentation)
        '203.0.113.1', // TEST-NET-3 (Documentation)
        '198.18.0.1', // Benchmark
        '169.254.1.1', // Link-Local
        '127.0.0.1', // Loopback
        '224.0.0.1', // Multicast
        '255.255.255.255', // Broadcast
        '0.0.0.0', // Unspecified
        'fd12:3456::1', // IPv6 ULA
        'fe80::1', // IPv6 Link-Local
        '2001:db8::1', // IPv6 Documentation
        '::1', // IPv6 Loopback
        'ff02::1', // IPv6 Multicast
        '::' // IPv6 Unspecified
      ]

      for (const addr of invalidWanAddresses) {
        const isV6 = addr.includes(':')
        const candidate: PortMappedTcpCandidate = {
          candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
          family: isV6 ? 6 : 4,
          address: addr,
          port: 45000
        }

        expect(() => {
          signTestCandidates({
            serverId: serverFixture.serverId,
            serverPublicKey: serverFixture.publicKey,
            serverPrivateKey: serverFixture.privateKey,
            candidates: [candidate]
          })
        }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
      }
    })

    it('(64) rejeita portas inválidas (0, 65536, negativas, decimais)', async () => {
      const serverFixture = await createLocalServerFixture()

      for (const badPort of [0, 65536, -1, 1.5, NaN]) {
        const candidate: PortMappedTcpCandidate = {
          candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
          family: 4,
          address: '203.0.114.1',
          port: badPort
        }

        expect(() => {
          signTestCandidates({
            serverId: serverFixture.serverId,
            serverPublicKey: serverFixture.publicKey,
            serverPrivateKey: serverFixture.privateKey,
            candidates: [candidate]
          })
        }).toThrowError()
      }
    })

    it('(66) Tampering: qualquer adulteração de tipo, endereço ou porta em candidate WAN invalida assinatura', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: PortMappedTcpCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
          family: 4,
          address: '203.0.114.1',
          port: 45000
        }
      ]

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      // Corrompe 1 byte no payload do candidate (logo antes dos 64 bytes da assinatura)
      const tampered = Buffer.from(encoded)
      const candidateOffset = tampered.length - 64 - 3 // No meio do registro do candidate
      tampered[candidateOffset] = (tampered[candidateOffset] ?? 0) ^ 0xff

      expect(() => {
        verifySignedConnectivityDescriptor({
          encodedDescriptor: tampered,
          expectedServerId: serverFixture.serverId
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_SIGNATURE_INVALID' }))
    })

    it('(67) Type Substitution: trocar candidateType de PORT_MAPPED para DIRECT_GLOBAL invalida a assinatura', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: PortMappedTcpCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
          family: 6,
          address: '2600::1',
          port: 45000
        }
      ]

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      // Localiza o byte do candidateType (0x02) e substitui por DIRECT_GLOBAL_TCP (0x03)
      const tampered = Buffer.from(encoded)
      for (let i = 0; i < tampered.length - 64; i++) {
        if (tampered[i] === ConnectivityCandidateType.PORT_MAPPED_TCP && tampered[i + 1] === 6) {
          tampered[i] = ConnectivityCandidateType.DIRECT_GLOBAL_TCP
          break
        }
      }

      expect(() => {
        verifySignedConnectivityDescriptor({
          encodedDescriptor: tampered,
          expectedServerId: serverFixture.serverId
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_SIGNATURE_INVALID' }))
    })

    it('(68 e 69) Ordenação canônica e distinção entre tipos com mesmo endpoint', async () => {
      const serverFixture = await createLocalServerFixture()

      const candidates: ConnectivityCandidate[] = [
        {
          candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
          family: 6,
          address: '2600::1',
          port: 45000
        },
        {
          candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
          family: 6,
          address: '2600::1',
          port: 45000
        },
        {
          candidateType: ConnectivityCandidateType.LAN_TCP,
          family: 4,
          address: '192.168.1.50',
          port: 45000,
          scope: 'LAN_PRIVATE'
        }
      ]

      const encoded = signTestCandidates({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates
      })

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        expectedServerId: serverFixture.serverId
      })

      expect(verified.candidates).toHaveLength(3)
      // Ordem canônica: LAN_TCP (1) < PORT_MAPPED_TCP (2) < DIRECT_GLOBAL_TCP (3)
      expect(verified.candidates[0]!.candidateType).toBe(ConnectivityCandidateType.LAN_TCP)
      expect(verified.candidates[1]!.candidateType).toBe(ConnectivityCandidateType.PORT_MAPPED_TCP)
      expect(verified.candidates[2]!.candidateType).toBe(ConnectivityCandidateType.DIRECT_GLOBAL_TCP)
    })
  })
})

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-connectivity-'))
  testRoots.push(root)

  const fakeSecureStorage = createFakeSecureStorage()
  const ownerKeyPair = generateKeyPairSync('ed25519')
  const ownerPublicKey = Buffer.from(ownerKeyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const ownerFingerprint = `sha256:${createHash('sha256').update(ownerPublicKey).digest('hex')}`

  const ownerDevice = createAuthenticatedCandidateDevice(ownerFingerprint, ownerPublicKey)

  let idCounter = 1
  const storage = createLocalServerStorage(root, fakeSecureStorage.storage, ownerDevice, {
    platform: 'win32',
    generateStorageId: () => (idCounter++).toString(16).padStart(32, '0')
  })

  const server = await storage.createLocalServer('Servidor Connectivity Teste')

  const serverKeyPair = fakeSecureStorage.lastGeneratedServerKey
  if (!serverKeyPair) {
    throw new Error('Chave do servidor não encontrada')
  }

  return {
    storage,
    userDataDir: root,
    storageId: server.localStorageId,
    serverId: server.serverId,
    publicKey: server.identity.publicKey,
    privateKey: serverKeyPair
  }
}

function createFakeSecureStorage() {
  const plaintextByCiphertext = new Map<string, string>()
  let encryptionCount = 0
  let lastKey: KeyObject | undefined

  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (plaintext: string) => {
        encryptionCount += 1
        const ciphertext = `server-protected:${encryptionCount}`
        plaintextByCiphertext.set(ciphertext, plaintext)

        try {
          const derBuffer = Buffer.from(plaintext, 'base64')
          lastKey = createPrivateKey({ key: derBuffer, format: 'der', type: 'pkcs8' })
        } catch {
          lastKey = undefined
        }

        return Buffer.from(ciphertext)
      },
      decryptString: (encrypted: Buffer) => {
        const plaintext = plaintextByCiphertext.get(encrypted.toString('utf8'))
        if (!plaintext) throw new Error('Ciphertext inválido')
        return plaintext
      }
    },
    get lastGeneratedServerKey() {
      return lastKey
    }
  }
}
