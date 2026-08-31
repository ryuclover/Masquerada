import { describe, it, expect, afterEach } from 'vitest'
import { createSocket, type Socket as DgramSocket, type RemoteInfo } from 'node:dgram'
import { randomBytes, generateKeyPairSync, createHash, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import {
  encodePcpMapRequest,
  decodePcpMapResponse,
  createPcpPortMapping,
  isLegitimateActivePortMapping,
  validatePcpEpochTransition,
  PCP_VERSION,
  PCP_MAP_OPCODE,
  PCP_PACKET_BYTES,
  PCP_NONCE_BYTES,
  PcpResultCode,
  PcpError,
  encodeIpv4ToMappedIpv6,
  decodeMappedIpv6ToIpv4
} from './pcp-client'
import {
  startLanTcpServer,
  type LanTcpServerHandle
} from './lan-transport'
import {
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  ConnectivityCandidateType
} from './connectivity-descriptor'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createPrivateKey } from 'node:crypto'

interface FakePcpServer {
  readonly socket: DgramSocket
  readonly port: number
  readonly address: string
  readonly getReceivedRequests: () => Buffer[]
  readonly setNextResponse: (fn: (req: Buffer, rinfo: RemoteInfo) => Buffer | null) => void
  readonly close: () => Promise<void>
}

async function startFakePcpServer(bindAddress = '127.0.0.1'): Promise<FakePcpServer> {
  const socket = createSocket('udp4')
  const receivedRequests: Buffer[] = []
  let responseHandler: ((req: Buffer, rinfo: RemoteInfo) => Buffer | null) | null = null

  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, bindAddress, () => {
      socket.off('error', reject)
      resolve()
    })
  })

  const addressInfo = socket.address()

  socket.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
    receivedRequests.push(Buffer.from(msg))
    if (responseHandler) {
      const resp = responseHandler(msg, rinfo)
      if (resp) {
        socket.send(resp, rinfo.port, rinfo.address)
      }
    }
  })

  return {
    socket,
    port: addressInfo.port,
    address: addressInfo.address,
    getReceivedRequests: () => receivedRequests,
    setNextResponse: (fn) => {
      responseHandler = fn
    },
    close: async () => {
      socket.removeAllListeners()
      await new Promise<void>((resolve) => socket.close(() => resolve()))
    }
  }
}

function buildFakePcpResponse(options: {
  version?: number
  isResponse?: boolean
  opcode?: number
  resultCode?: PcpResultCode
  lifetimeSeconds?: number
  epochTime?: number
  mappingNonce: Buffer
  internalPort: number
  assignedExternalPort: number
  assignedExternalAddress: string
  extraBytes?: Buffer
}): Buffer {
  const buf = Buffer.alloc(PCP_PACKET_BYTES + (options.extraBytes ? options.extraBytes.length : 0), 0)
  let offset = 0

  buf.writeUInt8(options.version ?? PCP_VERSION, offset++)
  const isResp = options.isResponse ?? true
  const opcode = options.opcode ?? PCP_MAP_OPCODE
  buf.writeUInt8((isResp ? 0x80 : 0x00) | (opcode & 0x7f), offset++)
  buf.writeUInt8(0, offset++) // Reserved
  buf.writeUInt8(options.resultCode ?? PcpResultCode.SUCCESS, offset++)
  buf.writeUInt32BE(options.lifetimeSeconds ?? 3600, offset)
  offset += 4
  buf.writeUInt32BE(options.epochTime ?? 1000, offset)
  offset += 4
  offset += 12 // 96 bits reserved

  options.mappingNonce.copy(buf, offset)
  offset += PCP_NONCE_BYTES

  buf.writeUInt8(6, offset++) // Protocol TCP
  offset += 3 // Reserved
  buf.writeUInt16BE(options.internalPort, offset)
  offset += 2
  buf.writeUInt16BE(options.assignedExternalPort, offset)
  offset += 2

  const ipBuf = encodeIpv4ToMappedIpv6(options.assignedExternalAddress)
  ipBuf.copy(buf, offset)
  offset += 16

  if (options.extraBytes) {
    options.extraBytes.copy(buf, offset)
  }

  return buf
}

const testRoots: string[] = []
const activeServers: LanTcpServerHandle[] = []
const activeFakeGateways: FakePcpServer[] = []

afterEach(async () => {
  await Promise.all(activeFakeGateways.splice(0).map((srv) => srv.close()))
  await Promise.all(activeServers.splice(0).map((srv) => srv.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-pcp-'))
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

  const server = await storage.createLocalServer('Servidor PCP Teste')

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

describe('pcp-client: PCP MAP seguro, ActivePortMapping e PORT_MAPPED_TCP', () => {
  describe('RFC 6887 Encoders & Decoders (60 bytes exato)', () => {
    it('(61) codifica MAP request de 60 bytes exatos com campos corretos', () => {
      const nonce = randomBytes(12)
      const req = encodePcpMapRequest({
        requestedLifetimeSeconds: 3600,
        clientIpAddress: '192.168.1.100',
        mappingNonce: nonce,
        internalPort: 54321,
        suggestedExternalPort: 0,
        suggestedExternalIp: undefined
      })

      expect(req.length).toBe(60)
      expect(req.readUInt8(0)).toBe(2) // Version 2
      expect(req.readUInt8(1)).toBe(1) // R=0, Opcode=1 (MAP)
      expect(req.readUInt16BE(2)).toBe(0) // Reserved
      expect(req.readUInt32BE(4)).toBe(3600) // Lifetime
      expect(decodeMappedIpv6ToIpv4(req.subarray(8, 24))).toBe('192.168.1.100')
      expect(req.subarray(24, 36).equals(nonce)).toBe(true)
      expect(req.readUInt8(36)).toBe(6) // TCP
      expect(req.readUInt16BE(40)).toBe(54321) // Internal port
      expect(req.readUInt16BE(42)).toBe(0) // Suggested port
      expect(req.subarray(44, 60).equals(Buffer.alloc(16, 0))).toBe(true) // All zeros
    })

    it('(62) decodifica MAP response válida de 60 bytes', () => {
      const nonce = randomBytes(12)
      const respBuf = buildFakePcpResponse({
        mappingNonce: nonce,
        internalPort: 54321,
        assignedExternalPort: 45000,
        assignedExternalAddress: '203.0.114.50'
      })

      const decoded = decodePcpMapResponse(respBuf)
      expect(decoded.version).toBe(2)
      expect(decoded.resultCode).toBe(PcpResultCode.SUCCESS)
      expect(decoded.lifetimeSeconds).toBe(3600)
      expect(decoded.epochTime).toBe(1000)
      expect(decoded.mappingNonce.equals(nonce)).toBe(true)
      expect(decoded.internalPort).toBe(54321)
      expect(decoded.assignedExternalPort).toBe(45000)
      expect(decoded.assignedExternalAddress).toBe('203.0.114.50')
    })

    it('(62b) rejeita resposta com tamanho incorreto ou opções não suportadas', () => {
      const nonce = randomBytes(12)
      const shortBuf = Buffer.alloc(59, 0)
      expect(() => decodePcpMapResponse(shortBuf)).toThrowError(
        expect.objectContaining({ code: 'PCP_RESPONSE_INVALID' })
      )

      // Resposta com trailing options (ex: 64 bytes)
      const extraBuf = buildFakePcpResponse({
        mappingNonce: nonce,
        internalPort: 54321,
        assignedExternalPort: 45000,
        assignedExternalAddress: '203.0.114.50',
        extraBytes: Buffer.alloc(4, 0)
      })

      expect(() => decodePcpMapResponse(extraBuf)).toThrowError(
        expect.objectContaining({ code: 'PCP_UNSUPPORTED_RESPONSE_OPTIONS' })
      )
    })

    it('(62c) rejeita resposta com versão incompatível ou R bit ausente', () => {
      const nonce = randomBytes(12)
      const badVer = buildFakePcpResponse({
        version: 1,
        mappingNonce: nonce,
        internalPort: 54321,
        assignedExternalPort: 45000,
        assignedExternalAddress: '203.0.114.50'
      })
      expect(() => decodePcpMapResponse(badVer)).toThrowError(
        expect.objectContaining({ code: 'PCP_RESPONSE_INVALID' })
      )

      const badR = buildFakePcpResponse({
        isResponse: false,
        mappingNonce: nonce,
        internalPort: 54321,
        assignedExternalPort: 45000,
        assignedExternalAddress: '203.0.114.50'
      })
      expect(() => decodePcpMapResponse(badR)).toThrowError(
        expect.objectContaining({ code: 'PCP_RESPONSE_INVALID' })
      )
    })
  })

  describe('PCP Exchange & ActivePortMapping Creation', () => {
    it('(70 e 69) executa exchange UDP real e produz ActivePortMapping com IP global válido', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88', // Global Unicast IPv4
          lifetimeSeconds: 1800,
          epochTime: 500
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port,
        requestedLifetimeSeconds: 1800
      })

      expect(isLegitimateActivePortMapping(mapping)).toBe(true)
      expect(mapping.isActive()).toBe(true)
      expect(mapping.getExternalEndpoint()).toEqual({
        family: 4,
        address: '203.0.114.88',
        port: 49152
      })
      expect(mapping.getGrantedLifetime()).toBe(1800)
      expect(mapping.getGateway()).toBe('127.0.0.1')

      await mapping.close()
    })

    it('(66) rejeita externalAddress privado e executa best-effort deletion', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '192.168.50.1' // Endereço privado
        })
      })

      await expect(
        createPcpPortMapping({
          listener: serverHandle,
          customGatewayAddress: fakePcpServer.address,
          customGatewayPort: fakePcpServer.port
        })
      ).rejects.toMatchObject({
        code: 'PCP_EXTERNAL_ADDRESS_NOT_GLOBAL'
      })

      // Verifica se houve tentativa de envio de deleção (lifetime 0)
      const requests = fakePcpServer.getReceivedRequests()
      expect(requests.length).toBeGreaterThanOrEqual(2)
      const lastReq = requests[requests.length - 1]!
      expect(lastReq.readUInt32BE(4)).toBe(0) // Lifetime = 0
    })

    it('(67 e 68) rejeita externalAddress CGNAT, Documentation e Reserved', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      for (const badAddr of ['100.64.0.5', '198.51.100.1', '127.0.0.1', '224.0.0.1']) {
        fakePcpServer.setNextResponse((req) => {
          const nonce = req.subarray(24, 36)
          const intPort = req.readUInt16BE(40)
          return buildFakePcpResponse({
            mappingNonce: nonce,
            internalPort: intPort,
            assignedExternalPort: 49152,
            assignedExternalAddress: badAddr
          })
        })

        await expect(
          createPcpPortMapping({
            listener: serverHandle,
            customGatewayAddress: fakePcpServer.address,
            customGatewayPort: fakePcpServer.port
          })
        ).rejects.toMatchObject({
          code: 'PCP_EXTERNAL_ADDRESS_NOT_GLOBAL'
        })
      }
    })

    it('(73) rejeita listener inválido ou forjado antes de I/O de rede', async () => {
      // Objeto forjado sem WeakSet
      const fakeHandle = {
        endpoint: { address: '127.0.0.1', port: 12345, family: 4 },
        host: '127.0.0.1',
        port: 12345,
        isClosed: () => false,
        close: async () => {},
        getActiveConnectionCount: () => 0,
        getIpConnectionCount: () => 0
      } as unknown as LanTcpServerHandle

      await expect(
        createPcpPortMapping({
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          listener: fakeHandle as any,
          customGatewayAddress: '127.0.0.1',
          customGatewayPort: 5351
        })
      ).rejects.toMatchObject({
        code: 'PCP_LISTENER_INVALID'
      })
    })

    it('(74) rejeita listener que já foi encerrado', async () => {
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

      await serverHandle.close()

      await expect(
        createPcpPortMapping({
          listener: serverHandle,
          customGatewayAddress: '127.0.0.1',
          customGatewayPort: 5351
        })
      ).rejects.toMatchObject({
        code: 'PCP_LISTENER_CLOSED'
      })
    })

    it('(77) timeout controlado quando o servidor PCP não responde', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      // Fake server não responde nada
      fakePcpServer.setNextResponse(() => null)

      await expect(
        createPcpPortMapping({
          listener: serverHandle,
          customGatewayAddress: fakePcpServer.address,
          customGatewayPort: fakePcpServer.port,
          timeoutMs: 50,
          maxRetransmissions: 2
        })
      ).rejects.toMatchObject({
        code: 'PCP_TIMEOUT'
      })
    })

    it('(78) trata erro retornado pelo servidor PCP (non-zero ResultCode)', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          resultCode: PcpResultCode.NOT_AUTHORIZED,
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 0,
          assignedExternalAddress: '0.0.0.0'
        })
      })

      await expect(
        createPcpPortMapping({
          listener: serverHandle,
          customGatewayAddress: fakePcpServer.address,
          customGatewayPort: fakePcpServer.port
        })
      ).rejects.toMatchObject({
        code: 'PCP_SERVER_ERROR',
        resultCode: PcpResultCode.NOT_AUTHORIZED
      })
    })
  })

  describe('Lifecycle, Renewal, Epoch & Deletion', () => {
    it('(83, 84 e 85) close() envia Lifetime 0 de forma idempotente e invalida capability', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88'
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port
      })

      expect(mapping.isActive()).toBe(true)

      // Fecha o mapping
      await mapping.close()
      expect(mapping.isActive()).toBe(false)

      // Chamada subsequente é estritamente idempotente
      await mapping.close()
      await mapping.close()
      expect(mapping.isActive()).toBe(false)
    })

    it('(86) fechamento do LanTcpServerHandle em cascata invalida o ActivePortMapping', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88'
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port
      })

      expect(mapping.isActive()).toBe(true)

      // Fecha o listener
      await serverHandle.close()

      // ActivePortMapping torna-se inativo imediatamente
      expect(mapping.isActive()).toBe(false)
    })
  })

  describe('SignedConnectivityDescriptor Integration', () => {
    it('(87) createSignedConnectivityDescriptor aceita ActivePortMapping e produz PORT_MAPPED_TCP assinado', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88'
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port
      })

      const encoded = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [mapping]
      })

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        expectedServerId: serverFixture.serverId
      })

      expect(verified.candidates).toHaveLength(1)
      const candidate = verified.candidates[0]!
      expect(candidate.candidateType).toBe(ConnectivityCandidateType.PORT_MAPPED_TCP)
      expect(candidate.address).toBe('203.0.114.88')
      expect(candidate.port).toBe(49152)

      await mapping.close()
    })

    it('(88) clampa o lifetime do descritor para nunca exceder a lease do ActivePortMapping', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88',
          lifetimeSeconds: 70 // Lease curta de 70 segundos
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port,
        requestedLifetimeSeconds: 70
      })

      // Caller pede lifetime de 300 segundos, mas mapping só tem 70
      const encoded = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [mapping],
        lifetimeSeconds: 300
      })

      const verified = verifySignedConnectivityDescriptor({
        encodedDescriptor: encoded,
        expectedServerId: serverFixture.serverId
      })

      expect(verified.expiresAt).toBeLessThanOrEqual(mapping.getExpiresAt())
      await mapping.close()
    })

    it('(89) rejeita assinatura se o ActivePortMapping estiver inativo ou fechado', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88'
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port
      })

      await mapping.close()

      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [mapping]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_HANDLE_CLOSED' }))
    })

    it('(90) rejeita ActivePortMapping forjado por object literal', async () => {
      const serverFixture = await createLocalServerFixture()
      const forgedMapping = {
        isActive: () => true,
        getExternalEndpoint: () => ({ family: 4, address: '203.0.114.88', port: 49152 }),
        getExpiresAt: () => Math.floor(Date.now() / 1000) + 3600,
        close: async () => {}
      }

      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          candidates: [forgedMapping as any]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_CANDIDATE_INVALID' }))
    })

    it('(93) descritor assinado não vaza nenhum metadado privado PCP no payload', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88'
        })
      })

      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port
      })

      const encoded = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [mapping]
      })

      const encodedStr = encoded.toString('utf8')
      expect(encodedStr.includes('PCP')).toBe(false)
      expect(encodedStr.includes('gateway')).toBe(false)
      expect(encodedStr.includes('epoch')).toBe(false)

      await mapping.close()
    })

    it('(7.12) regressão do relógio monotônico invalida o mapping sem reviver a capability', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88',
          lifetimeSeconds: 300,
          epochTime: 100
        })
      })

      let simulatedMonotonicSec = 1000
      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port,
        requestedLifetimeSeconds: 300,
        monotonicClock: () => simulatedMonotonicSec
      })

      expect(mapping.isActive()).toBe(true)
      simulatedMonotonicSec = 999
      expect(mapping.isActive()).toBe(false)

      simulatedMonotonicSec = 2000
      expect(mapping.isActive()).toBe(false)
      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [mapping]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_HANDLE_CLOSED' }))
    })
  })

  describe('RFC 6887 Section 8.5 — PCP Epoch Time Validation', () => {
    it('(101) primeira response aceita qualquer uint32 válido como baseline', () => {
      const baselines = [0, 100, 12345678, 0xffffffff]
      for (const epoch of baselines) {
        const res = validatePcpEpochTransition(null, epoch, 500)
        expect(res.result).toBe('VALID')
        expect(res.nextState).toEqual({
          prevServerEpoch: epoch,
          prevClientMonotonicSeconds: 500
        })
      }
    })

    it('(102) rejeita epoch fora da faixa uint32 ou não inteiro', () => {
      const invalidEpochs = [-1, 0x100000000, 1.5, NaN, Infinity]
      for (const epoch of invalidEpochs) {
        const res = validatePcpEpochTransition(null, epoch, 500)
        expect(res.result).toBe('STATE_LOSS_SUSPECTED')
        expect(res.nextState).toBeNull()
      }
    })

    it('(103) progressão normal de epoch avança baseline', () => {
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 500 }
      const res = validatePcpEpochTransition(state0, 110, 510)
      expect(res.result).toBe('VALID')
      expect(res.nextState).toEqual({
        prevServerEpoch: 110,
        prevClientMonotonicSeconds: 510
      })
    })

    it('(104) retrocesso aparente de até 1 segundo é tolerado para reordenação de pacotes', () => {
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 500 }
      const res = validatePcpEpochTransition(state0, 99, 500)
      expect(res.result).toBe('VALID')
      expect(res.nextState).toEqual({
        prevServerEpoch: 99,
        prevClientMonotonicSeconds: 500
      })
    })

    it('(105) retrocesso de 2 ou mais segundos detecta anomalia / provável reinício do roteador', () => {
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 500 }
      const res = validatePcpEpochTransition(state0, 98, 502)
      expect(res.result).toBe('STATE_LOSS_SUSPECTED')
      expect(res.nextState).toBeNull()
    })

    it('(106) detecta anomalia quando o relógio do servidor avança excessivamente (server delta muito grande)', () => {
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 500 }
      // client avançou 10s, mas server avançou 1000s
      const res = validatePcpEpochTransition(state0, 1100, 510)
      expect(res.result).toBe('STATE_LOSS_SUSPECTED')
      expect(res.nextState).toBeNull()
    })

    it('(107) detecta anomalia quando o relógio do cliente avança muito mais que o servidor (client delta muito grande)', () => {
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 500 }
      // client avançou 1000s, mas server avançou apenas 10s
      const res = validatePcpEpochTransition(state0, 110, 1500)
      expect(res.result).toBe('STATE_LOSS_SUSPECTED')
      expect(res.nextState).toBeNull()
    })

    it('(108) limites exatos da tolerância de 1/16 (6,25%) e quantização +2 segundos', () => {
      // serverDelta = 100. serverDeltaTolerance = floor(100/16) = 6. serverDelta - 6 = 94.
      // Se clientDelta + 2 < 94 => anomalia. Se clientDelta + 2 >= 94 => válido.
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 0 }

      // clientDelta = 91 -> 91 + 2 = 93 < 94 -> anomalia
      expect(validatePcpEpochTransition(state0, 200, 91).result).toBe('STATE_LOSS_SUSPECTED')
      // clientDelta = 92 -> 92 + 2 = 94 -> válido
      expect(validatePcpEpochTransition(state0, 200, 92).result).toBe('VALID')

      // clientDelta = 100. clientDeltaTolerance = floor(100/16) = 6. clientDelta - 6 = 94.
      // Se serverDelta + 2 < 94 => anomalia. Se serverDelta + 2 >= 94 => válido.
      // serverDelta = 91 -> 91 + 2 = 93 < 94 -> anomalia
      expect(validatePcpEpochTransition(state0, 191, 100).result).toBe('STATE_LOSS_SUSPECTED')
      // serverDelta = 92 -> 92 + 2 = 94 -> válido
      expect(validatePcpEpochTransition(state0, 192, 100).result).toBe('VALID')
    })

    it('(109) relógio monotônico do cliente retrocedendo resulta em fail-closed', () => {
      const state0 = { prevServerEpoch: 100, prevClientMonotonicSeconds: 500 }
      const res = validatePcpEpochTransition(state0, 110, 499)
      expect(res.result).toBe('STATE_LOSS_SUSPECTED')
      expect(res.nextState).toBeNull()
    })

    it('(110) baselines de diferentes gateways são estritamente independentes', () => {
      const gwA_init = validatePcpEpochTransition(null, 1000, 10)
      const gwB_init = validatePcpEpochTransition(null, 50, 10)

      expect(gwA_init.nextState?.prevServerEpoch).toBe(1000)
      expect(gwB_init.nextState?.prevServerEpoch).toBe(50)

      // Transição válida em A
      const gwA_next = validatePcpEpochTransition(gwA_init.nextState, 1010, 20)
      expect(gwA_next.result).toBe('VALID')

      // Transição válida em B
      const gwB_next = validatePcpEpochTransition(gwB_init.nextState, 60, 20)
      expect(gwB_next.result).toBe('VALID')
    })

    it('(111) renewal com anomalia de epoch desativa a capability e impede criação de novos descritores', async () => {
      const serverFixture = await createLocalServerFixture()
      const fakePcpServer = await startFakePcpServer('127.0.0.1')
      activeFakeGateways.push(fakePcpServer)

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

      let epochToReturn = 100
      fakePcpServer.setNextResponse((req) => {
        const nonce = req.subarray(24, 36)
        const intPort = req.readUInt16BE(40)
        return buildFakePcpResponse({
          mappingNonce: nonce,
          internalPort: intPort,
          assignedExternalPort: 49152,
          assignedExternalAddress: '203.0.114.88',
          lifetimeSeconds: 300,
          epochTime: epochToReturn
        })
      })

      let simulatedMonotonicSec = 1000
      const mapping = await createPcpPortMapping({
        listener: serverHandle,
        customGatewayAddress: fakePcpServer.address,
        customGatewayPort: fakePcpServer.port,
        requestedLifetimeSeconds: 300,
        monotonicClock: () => simulatedMonotonicSec
      })

      expect(mapping.isActive()).toBe(true)

      // Descritor assinado inicial é aceito
      const descBefore = createSignedConnectivityDescriptor({
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        candidates: [mapping]
      })
      expect(descBefore.length).toBeGreaterThan(0)

      // Simula anomalia no próximo renewal (Epoch reinicia para 10 -> retrocesso de 90s)
      epochToReturn = 10
      simulatedMonotonicSec += 1 // 1s depois

      // Dispara o renewal
      await mapping.executeRenewalForTesting()

      // A capability agora deve estar desativada devido ao epoch reset
      expect(mapping.isActive()).toBe(false)

      // Nova tentativa de gerar descritor deve falhar fechada
      expect(() => {
        createSignedConnectivityDescriptor({
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          candidates: [mapping]
        })
      }).toThrowError(expect.objectContaining({ code: 'DESCRIPTOR_HANDLE_CLOSED' }))

      await mapping.close()
    })
  })

  describe('Fuzz-like & Error Taxonomy', () => {
    it('(97) decoders PCP lidam com buffers aleatórios e truncados sem lançar exceções inesperadas', () => {
      for (let len = 0; len < 100; len++) {
        const randomBuf = randomBytes(len)
        try {
          decodePcpMapResponse(randomBuf)
        } catch (err) {
          expect(err).toBeInstanceOf(PcpError)
        }
      }
    })
  })
})
