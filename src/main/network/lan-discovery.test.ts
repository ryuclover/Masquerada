import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { DATABASE_FILE_NAME, listMembers, openServerDatabase } from '../servers/server-database'
import {
  createSignedConnectivityDescriptor,
  type LanTcpCandidate
} from './connectivity-descriptor'
import {
  DISCOVERY_NONCE_BYTES,
  discoverLanServer,
  encodeDiscoveryQuery,
  encodeDiscoveryResponse,
  MAX_DISCOVERY_DATAGRAM_BYTES,
  parseAndVerifyDiscoveryResponse,
  parseDiscoveryQuery,
  startLanDiscoveryResponder,
  type LanDiscoveryResponder
} from './lan-discovery'
import { ConnectivitySubsystem } from './connectivity-subsystem'
import {
  connectLanTcpPeer,
  startLanTcpServer,
  type LanTcpServerHandle
} from './lan-transport'

const testRoots: string[] = []
const activeServers: LanTcpServerHandle[] = []
const activeResponders: LanDiscoveryResponder[] = []

afterEach(async () => {
  await Promise.all(activeResponders.splice(0).map((r) => r.close()))
  await Promise.all(activeServers.splice(0).map((s) => s.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('lan-discovery: descoberta LAN direcionada e autenticada sobre UDP', () => {
  describe('parsing, codificação e verificações estritas (testes 30 a 33)', () => {
    it('(30) rejeita resposta stale / replay de nonce com DISCOVERY_NONCE_MISMATCH', async () => {
      const serverFixture = await createLocalServerFixture()
      const nonceA = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x01)
      const nonceB = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x02)

      const candidates: LanTcpCandidate[] = [
        {
          candidateType: 1,
          family: 4,
          address: '192.168.1.10',
          port: 5000,
          scope: 'LAN_PRIVATE'
        }
      ]
      const signedDesc = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates,
        allowRawCandidatesForTesting: true
      })

      // Resposta codificada vinculada ao nonceA
      const respA = encodeDiscoveryResponse(
        nonceA,
        serverFixture.serverId,
        serverFixture.privateKey,
        signedDesc
      )

      // Cliente B esperando nonceB recebe respA -> falha
      expect(() => {
        parseAndVerifyDiscoveryResponse(respA, serverFixture.serverId, nonceB)
      }).toThrowError(expect.objectContaining({ code: 'DISCOVERY_NONCE_MISMATCH' }))
    })

    it('(31) rejeita respostas adulteradas (tampering de nonce, descriptor ou assinatura)', async () => {
      const serverFixture = await createLocalServerFixture()
      const nonce = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0xaa)

      const candidates: LanTcpCandidate[] = [
        {
          candidateType: 1,
          family: 4,
          address: '192.168.1.10',
          port: 5000,
          scope: 'LAN_PRIVATE'
        }
      ]
      const signedDesc = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates,
        allowRawCandidatesForTesting: true
      })

      const resp = encodeDiscoveryResponse(
        nonce,
        serverFixture.serverId,
        serverFixture.privateKey,
        signedDesc
      )

      // 1. Tampering no nonce
      const tamperedNonce = Buffer.from(resp)
      tamperedNonce[10]! ^= 0x01
      expect(() => {
        parseAndVerifyDiscoveryResponse(tamperedNonce, serverFixture.serverId, nonce)
      }).toThrowError()

      // 2. Tampering no descriptor
      const tamperedDesc = Buffer.from(resp)
      tamperedDesc[50]! ^= 0x01
      expect(() => {
        parseAndVerifyDiscoveryResponse(tamperedDesc, serverFixture.serverId, nonce)
      }).toThrowError()

      // 3. Tampering na assinatura
      const tamperedSig = Buffer.from(resp)
      tamperedSig[tamperedSig.length - 10]! ^= 0x01
      expect(() => {
        parseAndVerifyDiscoveryResponse(tamperedSig, serverFixture.serverId, nonce)
      }).toThrowError()
    })

    it('(32) rejeita datagramas malformados (magic errado, versão errada, flags não-zero)', async () => {
      const serverFixture = await createLocalServerFixture()
      const nonce = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x12)

      const candidates: LanTcpCandidate[] = [
        {
          candidateType: 1,
          family: 4,
          address: '192.168.1.10',
          port: 5000,
          scope: 'LAN_PRIVATE'
        }
      ]
      const signedDesc = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates,
        allowRawCandidatesForTesting: true
      })

      const validResp = encodeDiscoveryResponse(
        nonce,
        serverFixture.serverId,
        serverFixture.privateKey,
        signedDesc
      )

      // Magic errado
      const badMagic = Buffer.from(validResp)
      badMagic[0] = 0x58 // 'X'
      expect(() => {
        parseAndVerifyDiscoveryResponse(badMagic, serverFixture.serverId, nonce)
      }).toThrowError(expect.objectContaining({ code: 'DISCOVERY_MAGIC_MISMATCH' }))

      // Versão errada
      const badVer = Buffer.from(validResp)
      badVer[4] = 2
      expect(() => {
        parseAndVerifyDiscoveryResponse(badVer, serverFixture.serverId, nonce)
      }).toThrowError(expect.objectContaining({ code: 'DISCOVERY_UNSUPPORTED_VERSION' }))

      // Flags != 0
      const badFlags = Buffer.from(validResp)
      badFlags[6] = 1
      expect(() => {
        parseAndVerifyDiscoveryResponse(badFlags, serverFixture.serverId, nonce)
      }).toThrowError(expect.objectContaining({ code: 'DISCOVERY_FLAGS_NON_ZERO' }))
    })

    it('(33) rejeita resposta de outro servidor quando expectedServerId for divergente', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()
      const nonce = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x77)

      const candidatesB: LanTcpCandidate[] = [
        {
          candidateType: 1,
          family: 4,
          address: '192.168.1.20',
          port: 6000,
          scope: 'LAN_PRIVATE'
        }
      ]
      const signedDescB = createSignedConnectivityDescriptor({
        serverId: serverFixtureB.serverId,
        serverPublicKey: serverFixtureB.publicKey,
        serverPrivateKey: serverFixtureB.privateKey,
        candidates: candidatesB,
        allowRawCandidatesForTesting: true
      })

      const respB = encodeDiscoveryResponse(
        nonce,
        serverFixtureB.serverId,
        serverFixtureB.privateKey,
        signedDescB
      )

      // Espera A, mas recebe B
      expect(() => {
        parseAndVerifyDiscoveryResponse(respB, serverFixtureA.serverId, nonce)
      }).toThrowError()
    })
  })

  describe('anti-amplificação, rate limit e replay suppression (testes 34 a 37)', () => {
    it('(34) anti-amplificação: o tamanho do datagrama de resposta nunca excede 1200 bytes', async () => {
      const serverFixture = await createLocalServerFixture()
      const nonce = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x99)

      const candidates: LanTcpCandidate[] = Array.from({ length: 8 }, (_, i) => ({
        candidateType: 1,
        family: 4 as const,
        address: `192.168.1.${i + 1}`,
        port: 5000 + i,
        scope: 'LAN_PRIVATE' as const
      }))

      const signedDesc = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates,
        allowRawCandidatesForTesting: true
      })

      const resp = encodeDiscoveryResponse(
        nonce,
        serverFixture.serverId,
        serverFixture.privateKey,
        signedDesc
      )

      expect(resp.length).toBeLessThanOrEqual(MAX_DISCOVERY_DATAGRAM_BYTES)
    })

    it('(35) responder ignora silenciosamente queries para outros serverIds sem gerar resposta nem assinatura', async () => {
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

      const responder = await startLanDiscoveryResponder({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        boundHandles: [serverHandle],
        bindAddress: '127.0.0.1',
        port: 45544,
        allowLoopbackForTesting: true
      })
      activeResponders.push(responder)

      // Envia query para outro serverId
      const fakeServerId = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
      const queryNonce = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x44)
      const queryBuf = encodeDiscoveryQuery(fakeServerId, queryNonce)

      const clientSock = createSocket('udp4')
      await new Promise<void>((resolve) => {
        clientSock.send(queryBuf, 45544, '127.0.0.1', () => resolve())
      })

      await new Promise((r) => setTimeout(r, 100))
      expect(responder.getProcessedQueryCount()).toBe(0)
      clientSock.close()
    })

    it('(36) replay cache suprime queries duplicadas com mesmo source, nonce e serverId', async () => {
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

      const responder = await startLanDiscoveryResponder({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        boundHandles: [serverHandle],
        bindAddress: '127.0.0.1',
        port: 45545,
        allowLoopbackForTesting: true
      })
      activeResponders.push(responder)

      const queryNonce = Buffer.alloc(DISCOVERY_NONCE_BYTES, 0x55)
      const queryBuf = encodeDiscoveryQuery(serverFixture.serverId, queryNonce)

      const clientSock = createSocket('udp4')
      let receivedResponses = 0
      clientSock.on('message', () => {
        receivedResponses++
      })

      // Envia a mesma query 3 vezes
      await new Promise<void>((resolve) => clientSock.send(queryBuf, 45545, '127.0.0.1', () => resolve()))
      await new Promise<void>((resolve) => clientSock.send(queryBuf, 45545, '127.0.0.1', () => resolve()))
      await new Promise<void>((resolve) => clientSock.send(queryBuf, 45545, '127.0.0.1', () => resolve()))

      await new Promise((r) => setTimeout(r, 150))

      // Somente a primeira gerou processamento e resposta
      expect(responder.getProcessedQueryCount()).toBe(1)
      expect(receivedResponses).toBe(1)
      clientSock.close()
    })

    it('(37) rejeita iniciar responder sem listeners LAN TCP ativos válidos', async () => {
      const serverFixture = await createLocalServerFixture()

      await expect(
        startLanDiscoveryResponder({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          boundHandles: [],
          bindAddress: '127.0.0.1',
          port: 45546,
          allowLoopbackForTesting: true
        })
      ).rejects.toThrowError(expect.objectContaining({ code: 'DISCOVERY_NO_ACTIVE_LISTENERS' }))
    })
  })

  describe('fluxo end-to-end, integração com TCP e não persistência (testes 38 a 47)', () => {
    it('(38 e 39) end-to-end: descobre servidor LAN direcionado sobre UDP sem iniciar conexão TCP automaticamente', async () => {
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

      const responder = await startLanDiscoveryResponder({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        boundHandles: [serverHandle],
        bindAddress: '127.0.0.1',
        port: 45547,
        allowLoopbackForTesting: true
      })
      activeResponders.push(responder)

      const discovered = await discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        port: 45547,
        targetUnicastAddress: '127.0.0.1',
        allowLoopbackForTesting: true
      })

      expect(discovered.serverId).toBe(serverFixture.serverId)
      expect(discovered.endpoints).toHaveLength(1)
      expect(discovered.endpoints[0]!.port).toBe(serverHandle.port)
      expect(discovered.endpoints[0]!.address).toBe('127.0.0.1')

      // Confirma que nenhuma conexão TCP foi aberta automaticamente
      expect(serverHandle.getActiveConnectionCount()).toBe(0)
    })

    it('(40) discovery -> TCP -> handshake -> admission: conecta ao candidate descoberto e admite novo membro', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

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

      const responder = await startLanDiscoveryResponder({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        boundHandles: [serverHandle],
        bindAddress: '127.0.0.1',
        port: 45548,
        allowLoopbackForTesting: true
      })
      activeResponders.push(responder)

      // 1. Descoberta via UDP
      const discovered = await discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        port: 45548,
        targetUnicastAddress: '127.0.0.1',
        allowLoopbackForTesting: true
      })

      const targetEndpoint = discovered.endpoints[0]!

      // 2. Conexão TCP e Admissão criptográfica
      const clientConn = connectLanTcpPeer({
        endpoint: targetEndpoint,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const res = await clientConn.waitForAdmission()
      expect(res.status).toBe('admitted')
      expect(clientConn.getState()).toBe('MEMBER_CONNECTED')

      clientConn.destroy()
    })

    it('(41) falha no handshake TCP se o candidate apontar para endpoint com wrong server identity', async () => {
      const serverFixtureA = await createLocalServerFixture()
      const serverFixtureB = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandleB = await startLanTcpServer({
        bindAddress: '127.0.0.1',
        port: 0,
        storage: serverFixtureB.storage,
        localStorageId: serverFixtureB.storageId,
        serverId: serverFixtureB.serverId,
        serverPublicKey: serverFixtureB.publicKey,
        serverPrivateKey: serverFixtureB.privateKey
      })
      activeServers.push(serverHandleB)

      // Tenta conectar ao endpoint de B esperando Server A
      const clientConn = connectLanTcpPeer({
        endpoint: {
          family: 4,
          address: '127.0.0.1',
          port: serverHandleB.port
        },
        expectedServerId: serverFixtureA.serverId, // Espera A, mas encontra B
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'fake_invite'
      })

      await expect(clientConn.waitForAdmission()).rejects.toThrowError()
      clientConn.destroy()
    })

    it('(45) cancela a descoberta quando AbortSignal é disparado', async () => {
      const serverFixture = await createLocalServerFixture()
      const controller = new AbortController()

      const discoveryPromise = discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        port: 45549,
        targetUnicastAddress: '127.0.0.1',
        signal: controller.signal,
        timeoutMs: 5000,
        allowLoopbackForTesting: true
      })

      controller.abort()

      await expect(discoveryPromise).rejects.toThrowError(
        expect.objectContaining({ code: 'DISCOVERY_ABORTED' })
      )
    })

    it('shutdown da subsystem cancela discovery pendente e bloqueia trabalho novo', async () => {
      const serverFixture = await createLocalServerFixture()
      const subsystem = new ConnectivitySubsystem()
      const discovery = discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        port: 45549,
        targetUnicastAddress: '127.0.0.1',
        timeoutMs: 5000,
        allowLoopbackForTesting: true,
        subsystem
      })
      const aborted = expect(discovery).rejects.toMatchObject({ code: 'DISCOVERY_ABORTED' })
      const shuttingDown = subsystem.shutdown()
      await aborted
      await shuttingDown
      await expect(discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        targetUnicastAddress: '127.0.0.1',
        allowLoopbackForTesting: true,
        subsystem
      })).rejects.toMatchObject({ code: 'CONNECTIVITY_SHUT_DOWN' })
    })

    it('(46) fuzz-like: parseDiscoveryQuery rejeita buffers truncados ou lixo aleatório sem lançar exceções', () => {
      const garbageBuffers = [
        Buffer.alloc(0),
        Buffer.alloc(5),
        Buffer.alloc(50, 0xff),
        Buffer.from('GET / HTTP/1.1\r\n\r\n'),
        Buffer.from('MQDL\x01\x01\x00\x00'), // Incompleto
        Buffer.alloc(1300, 0x41) // Oversized
      ]

      for (const buf of garbageBuffers) {
        expect(parseDiscoveryQuery(buf)).toBeNull()
      }
    })

    it('(47) não persiste nenhum dado de descoberta no SQLite ou filesystem', async () => {
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

      const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
      const dbBefore = openServerDatabase(dbPath)
      const membersBefore = listMembers(dbBefore)
      dbBefore.close()

      const responder = await startLanDiscoveryResponder({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        boundHandles: [serverHandle],
        bindAddress: '127.0.0.1',
        port: 45550,
        allowLoopbackForTesting: true
      })
      activeResponders.push(responder)

      await discoverLanServer({
        expectedServerId: serverFixture.serverId,
        localInterfaceAddress: '127.0.0.1',
        port: 45550,
        targetUnicastAddress: '127.0.0.1',
        allowLoopbackForTesting: true
      })

      const dbAfter = openServerDatabase(dbPath)
      const membersAfter = listMembers(dbAfter)
      dbAfter.close()

      expect(membersAfter).toEqual(membersBefore)
    })
  })
})

function createClientFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(keyPair.publicKey.export({ format: 'der', type: 'spki' }))
  const fingerprint = `sha256:${createHash('sha256').update(publicKey).digest('hex')}`
  return {
    fingerprint,
    publicKey,
    privateKey: keyPair.privateKey
  }
}

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-discovery-'))
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

  const server = await storage.createLocalServer('Servidor Discovery Teste')

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
