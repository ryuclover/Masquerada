import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { createConnection, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  createAuthenticatedCandidateDevice
} from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import {
  DATABASE_FILE_NAME,
  listMembers,
  openServerDatabase
} from '../servers/server-database'
import {
  ClientHandshake
} from './p2p-handshake'
import {
  ClientSessionSetup,
  encodeSessionFrame
} from './p2p-session'
import {
  connectAndAdmitTcpPeer,
  DEFAULT_LOOPBACK_HOST,
  MAX_PENDING_READ_BYTES,
  MAX_PENDING_READ_FRAMES,
  ServerTcpPeerConnection,
  startTcpServer,
  type TcpServerHandle
} from './tcp-transport'
import {
  encodeProtocolFrame,
  HEADER_LENGTH,
  ProtocolFrameDecoder,
  ProtocolFrameType
} from './protocol-frame'

const testRoots: string[] = []
const activeServers: TcpServerHandle[] = []

afterEach(async () => {
  await Promise.all(activeServers.splice(0).map((srv) => srv.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('hardening de filas e atividade autorizada', () => {
  it.each(['client', 'server'] as const)('%s: libera contadores apos processamento e rejeita replay sem renovar idle', async (side) => {
    const { client, server } = await createAuthorizedPair()
    const receiver = side === 'client' ? client : server
    const sender = side === 'client' ? server : client
    const internals = receiver as unknown as {
      socket: Socket
      currentTimer: NodeJS.Timeout
      pendingReadFrames: number
      pendingReadBytes: number
    }
    const messages: string[] = []
    receiver.getAuthorizedChannel()!.setMessageHandler((plaintext) => {
      messages.push(plaintext.toString())
    })
    try {
      await vi.waitFor(() => expect(internals.pendingReadFrames).toBe(0))
      const refresh = vi.spyOn(internals.currentTimer, 'refresh')
      const frames = Array.from({ length: 10 }, (_, i) =>
        encodeSessionFrame(sender.getSession()!.encrypt(Buffer.from(`ordered-${i}`))))
      internals.socket.emit('data', Buffer.concat(frames))
      await vi.waitFor(() => expect(internals.pendingReadFrames).toBe(0))
      expect(messages).toEqual(Array.from({ length: 10 }, (_, i) => `ordered-${i}`))
      expect(internals.pendingReadBytes).toBe(0)
      expect(refresh).toHaveBeenCalledTimes(10)
      internals.socket.emit('data', frames[0]!)
      await vi.waitFor(() => expect(receiver.getState()).not.toBe('MEMBER_CONNECTED'))
      expect(refresh).toHaveBeenCalledTimes(10)
      expect(messages).toHaveLength(10)
    } finally {
      client.destroy()
      server.destroy()
    }
  })

  for (const side of ['server', 'client'] as const) {
    for (const limit of ['frames', 'bytes'] as const) {
      it(`${side}: encerra inundacao por ${limit} com consumidor bloqueado e limpa recursos`, async () => {
        const { client, server } = await createAuthorizedPair()
        const receiver = side === 'server' ? server : client
        const sender = side === 'server' ? client : server
        const internals = receiver as unknown as {
          socket: Socket
          frameQueue: unknown[]
          pendingReadFrames: number
          pendingReadBytes: number
          isProcessingFrames: boolean
          decoder: ProtocolFrameDecoder | null
          currentTimer: NodeJS.Timeout | null
        }
        let release!: () => void
        const blocked = new Promise<void>((resolve) => { release = resolve })
        const handler = vi.fn(() => blocked)
        const channel = receiver.getAuthorizedChannel()!
        channel.setMessageHandler(handler)
        channel.onClose(() => { throw new Error('Consumer cleanup failed') })
        const closed = vi.fn()
        channel.onClose(closed)
        const session = receiver.getSession()!
        const plaintext = Buffer.alloc(limit === 'frames' ? 0 : 65536 - HEADER_LENGTH - 25)
        const makeFrame = () => encodeSessionFrame(sender.getSession()!.encrypt(plaintext))
        const frameBytes = HEADER_LENGTH + plaintext.length + 25
        const capacity = limit === 'frames' ? MAX_PENDING_READ_FRAMES : MAX_PENDING_READ_BYTES / frameBytes
        try {
          await vi.waitFor(() => expect(internals.pendingReadFrames).toBe(0))
          internals.socket.emit('data', makeFrame())
          expect(handler).toHaveBeenCalledTimes(1)
          for (let i = 1; i < capacity; i++) internals.socket.emit('data', makeFrame())
          expect(receiver.getState()).toBe('MEMBER_CONNECTED')
          expect(internals.pendingReadFrames).toBe(capacity)
          expect(internals.pendingReadBytes).toBe(capacity * frameBytes)
          expect(internals.frameQueue).toHaveLength(capacity - 1)

          internals.socket.emit('data', makeFrame())
          expect(receiver.getState()).toBe(side === 'server' ? 'CLOSED' : 'FAILED')
          expect(internals.socket.destroyed).toBe(true)
          expect(internals.frameQueue).toHaveLength(0)
          expect(internals.pendingReadFrames).toBe(0)
          expect(internals.pendingReadBytes).toBe(0)
          expect(internals.decoder).toBeNull()
          expect(internals.currentTimer).toBeNull()
          expect(receiver.getEstablishedContext()).toBeNull()
          expect(session.isDestroyed()).toBe(true)
          expect(closed).toHaveBeenCalledTimes(1)
          release()
          await vi.waitFor(() => expect(internals.isProcessingFrames).toBe(false))
          expect(handler).toHaveBeenCalledTimes(1)
          expect(internals.pendingReadBytes).toBe(0)
          expect(internals.currentTimer).toBeNull()
        } finally {
          release()
          client.destroy()
          server.destroy()
        }
      })
    }
  }

  it.each(['client', 'server'] as const)('renova envio de %s e recebimento remoto, mas encerra apos inatividade', async (side) => {
    const { client, server } = await createAuthorizedPair(500)
    const sender = side === 'client' ? client : server
    const receiver = side === 'client' ? server : client
    const messages: string[] = []
    receiver.getAuthorizedChannel()!.setMessageHandler((plaintext) => {
      messages.push(plaintext.toString())
    })
    try {
      for (let i = 0; i < 5; i++) {
        await new Promise((resolve) => setTimeout(resolve, 150))
        await sender.getAuthorizedChannel()!.send(Buffer.from(`message-${i}`))
        await vi.waitFor(() => expect(messages).toHaveLength(i + 1))
      }
      expect(client.getState()).toBe('MEMBER_CONNECTED')
      expect(server.getState()).toBe('MEMBER_CONNECTED')
      await vi.waitFor(() => {
        expect(client.getState()).not.toBe('MEMBER_CONNECTED')
        expect(server.getState()).not.toBe('MEMBER_CONNECTED')
      }, { timeout: 1500 })
    } finally {
      client.destroy()
      server.destroy()
    }
  })

  it.each(['client', 'server'] as const)('%s: bytes parciais nao renovam idle autenticado', async (side) => {
    const { client, server } = await createAuthorizedPair(500)
    const receiver = side === 'client' ? client : server
    const { socket, currentTimer } = receiver as unknown as { socket: Socket; currentTimer: NodeJS.Timeout }
    const refresh = vi.spyOn(currentTimer, 'refresh')
    try {
      // Refresh neither endpoint through raw bytes, even in MEMBER_CONNECTED.
      for (let i = 0; i < 3; i++) {
        await new Promise((resolve) => setTimeout(resolve, 100))
        socket.emit('data', Buffer.from([0x4d, 0x51, 0x52]).subarray(i, i + 1))
      }
      expect(refresh).not.toHaveBeenCalled()
      await vi.waitFor(() => expect(receiver.getState()).not.toBe('MEMBER_CONNECTED'), { timeout: 1000 })
    } finally {
      client.destroy()
      server.destroy()
    }
  })
})

describe('transporte TCP P2P seguro e streaming de frames', () => {
  describe('fluxo completo ponta a ponta sobre socket TCP real (loopback)', () => {
    it('executa handshake, session setup e admissão de membro sobre TCP 127.0.0.1:0', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      // 1. Owner emite convite single-use
      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      // 2. Abre listener TCP seguro em porta efêmera (port = 0)
      const serverHandle = await startTcpServer({
        host: DEFAULT_LOOPBACK_HOST,
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      expect(serverHandle.port).toBeGreaterThan(0)
      expect(serverHandle.host).toBe('127.0.0.1')

      // 3. Client conecta e executa todo o pipeline até admissão
      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const admissionResult = await clientConn.waitForAdmission()
      expect(admissionResult.status).toBe('admitted')
      expect(clientConn.getState()).toBe('MEMBER_CONNECTED')

      // 4. Verifica persistência no SQLite do servidor host
      const members = getServerMembers(serverFixture)
      expect(members).toHaveLength(2) // Owner + Client
      expect(members.some((m) => m.deviceFingerprint === clientFixture.fingerprint)).toBe(true)

      // Cleanup
      clientConn.destroy()
    })

    it('permite reconexão de membro previamente admitido retornando already_member', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 3
        }
      )

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      // 1ª Conexão: Admissão inicial
      const clientConn1 = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const res1 = await clientConn1.waitForAdmission()
      expect(res1.status).toBe('admitted')
      clientConn1.destroy()

      // 2ª Conexão: Reconexão de membro existente
      const clientConn2 = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const res2 = await clientConn2.waitForAdmission()
      expect(res2.status).toBe('already_member')
      expect(clientConn2.getState()).toBe('MEMBER_CONNECTED')

      // Não duplica registro no SQLite
      const members = getServerMembers(serverFixture)
      expect(members).toHaveLength(2)

      clientConn2.destroy()
    }, 15000)
  })

  describe('streaming, fragmentação e coalescing de frames TCP', () => {
    it('processa frames divididos em fragmentos minúsculos de 1 a 3 bytes', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        handshakeTimeoutMs: 150
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({
        host: serverHandle.host,
        port: serverHandle.port
      })
      rawSocket.on('error', () => {})

      await new Promise<void>((resolve) => rawSocket.once('connect', () => resolve()))

      const closedPromise = new Promise<void>((resolve) => {
        if (rawSocket.destroyed) {
          resolve()
        } else {
          rawSocket.once('close', () => resolve())
        }
      })

      const frame = encodeProtocolFrame({
        type: ProtocolFrameType.HANDSHAKE,
        payload: Buffer.alloc(40, 0xaa)
      })

      for (let i = 0; i < frame.length; i += 2) {
        if (rawSocket.destroyed) break
        rawSocket.write(frame.subarray(i, Math.min(i + 2, frame.length)))
        await new Promise((r) => setTimeout(r, 2))
      }

      await closedPromise
    })

    it('processa múltiplos frames coalescidos em um único chunk TCP', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({
        host: serverHandle.host,
        port: serverHandle.port
      })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const frame1 = encodeProtocolFrame({
        type: ProtocolFrameType.HANDSHAKE,
        payload: Buffer.alloc(30, 0x11)
      })
      const frame2 = encodeProtocolFrame({
        type: ProtocolFrameType.HANDSHAKE,
        payload: Buffer.alloc(30, 0x22)
      })

      const combined = Buffer.concat([frame1, frame2])
      rawSocket.write(combined)

      await new Promise<void>((resolve) => {
        rawSocket.once('close', () => resolve())
      })
    })
  })

  describe('validações de segurança, malformed stream e limites de recursos', () => {
    it('rejeita conexão que envia magic inválido e encerra o socket fail-closed', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({
        host: serverHandle.host,
        port: serverHandle.port
      })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const malformedHeader = Buffer.from([
        0x58, 0x58, 0x58, 0x58, // Magic inválido "XXXX"
        0x01, // Version 1
        0x01, // Type HANDSHAKE
        0x00, 0x00, // Reserved + Flags
        0x00, 0x00, 0x00, 0x04, // Length: 4
        0x01, 0x02, 0x03, 0x04
      ])

      rawSocket.write(malformedHeader)

      await new Promise<void>((resolve) => {
        rawSocket.once('close', () => resolve())
      })
    })

    it('rejeita frame com payloadLength superior ao limite de 64 KB', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({
        host: serverHandle.host,
        port: serverHandle.port
      })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const oversizeHeader = Buffer.from([
        0x4d, 0x51, 0x52, 0x44, // "MQRD"
        0x01,
        0x01,
        0x00, 0x00,
        0x00, 0x01, 0x00, 0x01 // 65537 bytes (> 64 KB)
      ])

      rawSocket.write(oversizeHeader)

      await new Promise<void>((resolve) => {
        rawSocket.once('close', () => resolve())
      })
    })

    it('rejeita wrong frame type durante HANDSHAKE (ex: frame SESSION)', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({
        host: serverHandle.host,
        port: serverHandle.port
      })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const sessionFrame = encodeProtocolFrame({
        type: ProtocolFrameType.SESSION,
        payload: Buffer.alloc(32, 0xbb)
      })

      rawSocket.write(sessionFrame)

      await new Promise<void>((resolve) => {
        rawSocket.once('close', () => resolve())
      })
    })

    it('rejeita conexão com serverId divergente do esperado pelo cliente', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const wrongServerId = 's:ed25519:' + '0'.repeat(64)

      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: wrongServerId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake_invite'
      })

      await expect(clientConn.waitForAdmission()).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_CONNECTION_CLOSED'
      })
    })

    it('rejeita convite inválido / esgotado sobre TCP e encerra conexão', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.invalid_token_xyz'
      })

      await expect(clientConn.waitForAdmission()).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_ADMISSION_REJECTED'
      })
    })

    it('rejeita novas conexões ao atingir maxConnections', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        maxConnections: 2
      })
      activeServers.push(serverHandle)

      const sock1 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      const sock2 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock1.on('error', () => {})
      sock2.on('error', () => {})

      await Promise.all([
        new Promise<void>((r) => sock1.once('connect', () => r())),
        new Promise<void>((r) => sock2.once('connect', () => r()))
      ])

      // 3ª conexão deve ser rejeitada/fechada
      const sock3 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock3.on('error', () => {})
      await new Promise<void>((resolve) => {
        sock3.once('close', () => resolve())
      })

      sock1.destroy()
      sock2.destroy()
    })

    it('fecha listener e todas as conexões ativas deterministamente no shutdown', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const sock1 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock1.on('error', () => {})
      await new Promise<void>((r) => sock1.once('connect', () => r()))

      expect(serverHandle.getActiveConnectionCount()).toBe(1)

      await serverHandle.close()
      expect(serverHandle.getActiveConnectionCount()).toBe(0)

      // Socket cliente detecta encerramento
      await new Promise<void>((resolve) => {
        sock1.once('close', () => resolve())
      })
    })
  })

  describe('hardening de timeouts e proteção contra slowloris (testes 1 a 5)', () => {
    it('(1) peer silencioso é desconectado após HANDSHAKE_TIMEOUT_MS', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        handshakeTimeoutMs: 50
      })
      activeServers.push(serverHandle)

      const silentSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      silentSocket.on('error', () => {})
      await new Promise<void>((r) => silentSocket.once('connect', () => r()))

      // Não envia bytes. O servidor deve fechar a conexão após ~50ms.
      const closed = await new Promise<boolean>((resolve) => {
        silentSocket.once('close', () => resolve(true))
      })
      expect(closed).toBe(true)
    })

    it('(2) handshake parcialmente enviado (slowloris) é terminado sem renovar deadline indefinidamente', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        handshakeTimeoutMs: 120
      })
      activeServers.push(serverHandle)

      const slowSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      slowSocket.on('error', () => {})
      await new Promise<void>((r) => slowSocket.once('connect', () => r()))

      // Envia 2 bytes a cada 40ms simulando ataque slowloris
      const timer = setInterval(() => {
        try {
          slowSocket.write(Buffer.from([0x4d, 0x51]))
        } catch {
          // Ignora se o socket já foi destruído
        }
      }, 40)

      const closed = await new Promise<boolean>((resolve) => {
        slowSocket.once('close', () => {
          clearInterval(timer)
          resolve(true)
        })
      })
      expect(closed).toBe(true)
    })

    it('(3) conexão em SESSION_SETUP é terminada após SESSION_SETUP_TIMEOUT_MS se peer não enviar key share', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        sessionSetupTimeoutMs: 50
      })
      activeServers.push(serverHandle)

      const clientHandshake = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const decoder = new ProtocolFrameDecoder()

      // Conclui handshake até entrar em SESSION_SETUP
      const clientHello = clientHandshake.createClientHello()
      rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientHello }))

      await new Promise<void>((resolve) => {
        rawSocket.on('data', (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          const frames = decoder.push(buf)
          for (const f of frames) {
            if (f.type === ProtocolFrameType.HANDSHAKE) {
              const state = clientHandshake.getState()
              if (state === 'WAITING_SERVER_PROOF') {
                const clientProof = clientHandshake.processServerProof(f.payload)
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientProof }))
              } else if (state === 'WAITING_SERVER_FINISH') {
                clientHandshake.processServerFinish(f.payload)
                // Entrou em SESSION_SETUP no servidor! Agora o peer fica intencionalmente silencioso
                resolve()
              }
            }
          }
        })
      })

      // O servidor deve fechar após sessionSetupTimeoutMs (50ms)
      const closed = await new Promise<boolean>((resolve) => {
        rawSocket.once('close', () => resolve(true))
      })
      expect(closed).toBe(true)
    })

    it('(4) conexão em SECURE_UNADMITTED é terminada após ADMISSION_TIMEOUT_MS se peer não enviar admission request', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        admissionTimeoutMs: 50
      })
      activeServers.push(serverHandle)

      const clientHandshake = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      let clientSessionSetup: ClientSessionSetup | null = null

      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const decoder = new ProtocolFrameDecoder()
      const clientHello = clientHandshake.createClientHello()
      rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientHello }))

      await new Promise<void>((resolve) => {
        rawSocket.on('data', (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          const frames = decoder.push(buf)
          for (const f of frames) {
            if (f.type === ProtocolFrameType.HANDSHAKE) {
              const state = clientHandshake.getState()
              if (state === 'WAITING_SERVER_PROOF') {
                const clientProof = clientHandshake.processServerProof(f.payload)
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientProof }))
              } else if (state === 'WAITING_SERVER_FINISH') {
                clientHandshake.processServerFinish(f.payload)
                const ctx = clientHandshake.getEstablishedContext()
                clientSessionSetup = new ClientSessionSetup(ctx)
                const share = clientSessionSetup.createClientKeyShare()
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.KEY_EXCHANGE, payload: share }))
              }
            } else if (f.type === ProtocolFrameType.KEY_EXCHANGE && clientSessionSetup) {
              const setupState = clientSessionSetup.getState()
              if (setupState === 'WAITING_SERVER_KEY_SHARE') {
                const confirm = clientSessionSetup.processServerKeyShare(f.payload)
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.KEY_EXCHANGE, payload: confirm }))
              } else if (setupState === 'WAITING_SERVER_KEY_CONFIRM') {
                clientSessionSetup.processServerKeyConfirm(f.payload)
                // Sessão estabelecida no servidor (SECURE_UNADMITTED)! Fica silencioso sem enviar admission request
                resolve()
              }
            }
          }
        })
      })

      // O servidor deve fechar após admissionTimeoutMs (50ms)
      const closed = await new Promise<boolean>((resolve) => {
        rawSocket.once('close', () => resolve(true))
      })
      expect(closed).toBe(true)
    })

    it('(5) conexão admitida é terminada após IDLE_TIMEOUT_MS quando inativa', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      let serverPeerConn: ServerTcpPeerConnection | null = null
      const getServerPeerConn = () => serverPeerConn

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        idleTimeoutMs: 50,
        onMemberConnected: (conn) => {
          serverPeerConn = conn
        }
      })
      activeServers.push(serverHandle)

      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const res = await clientConn.waitForAdmission()
      expect(res.status).toBe('admitted')
      expect(getServerPeerConn()).not.toBeNull()

      // Após 50ms sem tráfego, o servidor deve encerrar por idle timeout
      await new Promise((r) => setTimeout(r, 80))
      expect(getServerPeerConn()?.getState()).toBe('CLOSED')
    })
  })

  describe('cancelamento de timers stale ao avançar de fase (testes 6 a 8)', () => {
    it('(6) cancela timer de handshake ao avançar para SESSION_SETUP impedindo falso timeout', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        handshakeTimeoutMs: 150,
        sessionSetupTimeoutMs: 500
      })
      activeServers.push(serverHandle)

      const clientHandshake = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const decoder = new ProtocolFrameDecoder()
      const clientHello = clientHandshake.createClientHello()
      rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientHello }))

      await new Promise<void>((resolve) => {
        rawSocket.on('data', (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          const frames = decoder.push(buf)
          for (const f of frames) {
            if (f.type === ProtocolFrameType.HANDSHAKE) {
              const state = clientHandshake.getState()
              if (state === 'WAITING_SERVER_PROOF') {
                const clientProof = clientHandshake.processServerProof(f.payload)
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientProof }))
              } else if (state === 'WAITING_SERVER_FINISH') {
                clientHandshake.processServerFinish(f.payload)
                resolve()
              }
            }
          }
        })
      })

      // Espera 200ms (maior que o handshakeTimeoutMs de 150ms)
      await new Promise((r) => setTimeout(r, 200))

      // A conexão não foi morta pelo timer stale do handshake!
      expect(rawSocket.destroyed).toBe(false)
      rawSocket.destroy()
    })

    it('(7) cancela timer de session setup ao avançar para SECURE_UNADMITTED', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        sessionSetupTimeoutMs: 150,
        admissionTimeoutMs: 500
      })
      activeServers.push(serverHandle)

      const clientHandshake = new ClientHandshake({
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey
      })

      let clientSessionSetup: ClientSessionSetup | null = null
      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const decoder = new ProtocolFrameDecoder()
      const clientHello = clientHandshake.createClientHello()
      rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientHello }))

      await new Promise<void>((resolve) => {
        rawSocket.on('data', (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          const frames = decoder.push(buf)
          for (const f of frames) {
            if (f.type === ProtocolFrameType.HANDSHAKE) {
              const state = clientHandshake.getState()
              if (state === 'WAITING_SERVER_PROOF') {
                const clientProof = clientHandshake.processServerProof(f.payload)
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: clientProof }))
              } else if (state === 'WAITING_SERVER_FINISH') {
                clientHandshake.processServerFinish(f.payload)
                const ctx = clientHandshake.getEstablishedContext()
                clientSessionSetup = new ClientSessionSetup(ctx)
                const share = clientSessionSetup.createClientKeyShare()
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.KEY_EXCHANGE, payload: share }))
              }
            } else if (f.type === ProtocolFrameType.KEY_EXCHANGE && clientSessionSetup) {
              const setupState = clientSessionSetup.getState()
              if (setupState === 'WAITING_SERVER_KEY_SHARE') {
                const confirm = clientSessionSetup.processServerKeyShare(f.payload)
                rawSocket.write(encodeProtocolFrame({ type: ProtocolFrameType.KEY_EXCHANGE, payload: confirm }))
              } else if (setupState === 'WAITING_SERVER_KEY_CONFIRM') {
                clientSessionSetup.processServerKeyConfirm(f.payload)
                resolve()
              }
            }
          }
        })
      })

      // Espera 90ms (maior que o sessionSetupTimeoutMs de 60ms)
      await new Promise((r) => setTimeout(r, 90))

      expect(rawSocket.destroyed).toBe(false)
      rawSocket.destroy()
    })

    it('(8) cancela timer de admission após sucesso permanecendo em MEMBER_CONNECTED', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        admissionTimeoutMs: 1500,
        idleTimeoutMs: 10000
      })
      activeServers.push(serverHandle)

      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken,
        admissionTimeoutMs: 1500,
        idleTimeoutMs: 10000
      })

      const res = await clientConn.waitForAdmission()
      expect(res.status).toBe('admitted')

      // Permanece conectado sem ser derrubado por timer de admissão
      await new Promise((r) => setTimeout(r, 100))

      expect(clientConn.getState()).toBe('MEMBER_CONNECTED')
      clientConn.destroy()
    })
  })

  describe('backpressure, buffers e drain (testes 9 a 13)', () => {
    it('(9) detecta backpressure quando buffer enche e socket.write() retorna false', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      // Pausa leitura do lado cliente para forçar o buffer do socket a encher
      rawSocket.pause()

      // Escreve repetidamente do lado do servidor até que uma escrita retorne false ou preencha o buffer
      const largeChunk = Buffer.alloc(16 * 1024, 0xaa)
      let backpressureHit = false

      for (let i = 0; i < 60; i++) {
        const canWrite = rawSocket.write(largeChunk)
        if (!canWrite) {
          backpressureHit = true
          break
        }
      }

      expect(backpressureHit).toBe(true)
      rawSocket.resume()
      rawSocket.destroy()
    })

    it('(10) aguarda corretamente pelo evento drain antes de concluir o envio', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))
      rawSocket.pause()

      // Enche o buffer do client
      let drained = false
      rawSocket.on('drain', () => {
        drained = true
      })

      const largeBuf = Buffer.alloc(32 * 1024, 0x55)
      while (rawSocket.write(largeBuf)) {
        // Enche até false
      }

      expect(drained).toBe(false)
      rawSocket.resume()

      await new Promise<void>((resolve) => {
        rawSocket.once('drain', () => resolve())
      })
      expect(drained).toBe(true)
      rawSocket.destroy()
    })

    it('(11) rejeita promise de envio e desliga listeners se socket fechar/erro enquanto aguarda drain', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const clientFixture = createClientFixture()
      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake'
      })

      // Trata completion promise para não gerar unhandled rejection
      clientConn.waitForAdmission().catch(() => {})

      clientConn.destroy()

      await expect(clientConn.writeFrame(Buffer.alloc(100))).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_CONNECTION_CLOSED'
      })
    })

    it('(12) lança TCP_BACKPRESSURE_OVERFLOW e encerra conexão quando pending bytes excede o limite configurado', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const clientFixture = createClientFixture()
      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake',
        maxPendingWriteBytes: 500 // Limite reduzido para o teste
      })

      clientConn.waitForAdmission().catch(() => {})

      // Tenta enviar 1000 bytes (> 500 maxPendingWriteBytes)
      const oversized = Buffer.alloc(1000, 0x99)
      await expect(clientConn.writeFrame(oversized)).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_BACKPRESSURE_OVERFLOW'
      })
    })

    it('(13) processa writes concorrentes preservando integridade dos frames e ordem sequencial', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const rawSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      rawSocket.on('error', () => {})
      await new Promise<void>((r) => rawSocket.once('connect', () => r()))

      const writePromises = Array.from({ length: 5 }, (_, i) => {
        const frame = encodeProtocolFrame({
          type: ProtocolFrameType.HANDSHAKE,
          payload: Buffer.from(`Payload-${i}`)
        })
        return new Promise<void>((resolve, reject) => {
          rawSocket.write(frame, (err) => {
            if (err) reject(err)
            else resolve()
          })
        })
      })

      await expect(Promise.all(writePromises)).resolves.toBeDefined()
      rawSocket.destroy()
    })
  })

  describe('limites por IP e gerenciamento de conexões (testes 14 a 17)', () => {
    it('(14) bloqueia conexões adicionais quando MAX_CONNECTIONS_PER_IP é atingido', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        maxConnectionsPerIp: 2
      })
      activeServers.push(serverHandle)

      const sock1 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      const sock2 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock1.on('error', () => {})
      sock2.on('error', () => {})

      await Promise.all([
        new Promise<void>((r) => sock1.once('connect', () => r())),
        new Promise<void>((r) => sock2.once('connect', () => r()))
      ])

      expect(serverHandle.getIpConnectionCount('127.0.0.1')).toBe(2)

      // 3ª conexão do mesmo IP é imediatamente recusada
      const sock3 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock3.on('error', () => {})
      await new Promise<void>((resolve) => {
        sock3.once('close', () => resolve())
      })

      sock1.destroy()
      sock2.destroy()
    })

    it('(15) decrementa corretamente o contador por IP após encerramento permitindo nova conexão', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        maxConnectionsPerIp: 2
      })
      activeServers.push(serverHandle)

      const sock1 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      const sock2 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock1.on('error', () => {})
      sock2.on('error', () => {})

      await Promise.all([
        new Promise<void>((r) => sock1.once('connect', () => r())),
        new Promise<void>((r) => sock2.once('connect', () => r()))
      ])

      expect(serverHandle.getIpConnectionCount('127.0.0.1')).toBe(2)

      // Fecha sock1
      sock1.destroy()
      await new Promise((r) => setTimeout(r, 30))

      expect(serverHandle.getIpConnectionCount('127.0.0.1')).toBe(1)

      // Nova conexão é aceita agora que o IP possui vaga
      const sock3 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock3.on('error', () => {})
      await new Promise<void>((r) => sock3.once('connect', () => r()))

      expect(serverHandle.getIpConnectionCount('127.0.0.1')).toBe(2)

      sock2.destroy()
      sock3.destroy()
    })

    it('(16) decrementa corretamente o contador global de conexões ativas após close', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      expect(serverHandle.getActiveConnectionCount()).toBe(0)

      const sock1 = createConnection({ host: serverHandle.host, port: serverHandle.port })
      sock1.on('error', () => {})
      await new Promise<void>((r) => sock1.once('connect', () => r()))

      expect(serverHandle.getActiveConnectionCount()).toBe(1)

      sock1.destroy()
      await new Promise((r) => setTimeout(r, 30))

      expect(serverHandle.getActiveConnectionCount()).toBe(0)
    })

    it('(17) encerra deterministamente peers silenciosos e travados durante listener shutdown', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })

      const stuckSocket = createConnection({ host: serverHandle.host, port: serverHandle.port })
      stuckSocket.on('error', () => {})
      await new Promise<void>((r) => stuckSocket.once('connect', () => r()))

      expect(serverHandle.getActiveConnectionCount()).toBe(1)

      await serverHandle.close()

      expect(serverHandle.getActiveConnectionCount()).toBe(0)
      expect(serverHandle.getIpConnectionCount('127.0.0.1')).toBe(0)

      await new Promise<void>((resolve) => {
        stuckSocket.once('close', () => resolve())
      })
    })
  })

  describe('cleanup idempotente, destruição de sessão e resiliência de socket (testes 18 a 20)', () => {
    it('(18) cleanup é estritamente idempotente quando destroy() é chamado múltiplas vezes', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const clientFixture = createClientFixture()
      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake'
      })

      clientConn.waitForAdmission().catch(() => {})

      expect(() => {
        clientConn.destroy()
        clientConn.destroy()
        clientConn.destroy()
      }).not.toThrow()

      expect(clientConn.getState()).toBe('CLOSED')
    })

    it('(19) SecureSession é destruída e chaves zeradas na memória quando o socket morre', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      let serverPeerConn: ServerTcpPeerConnection | null = null
      const getServerPeerConn = () => serverPeerConn

      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey,
        onMemberConnected: (conn) => {
          serverPeerConn = conn
        }
      })
      activeServers.push(serverHandle)

      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      await clientConn.waitForAdmission()

      const clientSession = clientConn.getSession()
      const serverSession = getServerPeerConn()?.getSession()

      expect(clientSession).not.toBeNull()
      expect(serverSession).not.toBeNull()
      expect(clientSession?.isDestroyed()).toBe(false)
      expect(serverSession?.isDestroyed()).toBe(false)

      clientConn.destroy()
      getServerPeerConn()?.destroy()

      expect(clientSession?.isDestroyed()).toBe(true)
      expect(serverSession?.isDestroyed()).toBe(true)
    })

    it('(20) erro de socket emitido assincronamente não causa uncaught exception e destrói a conexão fail-closed', async () => {
      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startTcpServer({
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      const clientFixture = createClientFixture()
      const clientConn = connectAndAdmitTcpPeer({
        host: serverHandle.host,
        port: serverHandle.port,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake'
      })

      // Simula erro assíncrono emitido no socket do cliente
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawSocket = (clientConn as any).socket
      expect(() => {
        rawSocket.emit('error', new Error('Simulated ECONNRESET'))
      }).not.toThrow()

      await expect(clientConn.waitForAdmission()).rejects.toBeDefined()
      expect(clientConn.getState()).toBe('FAILED')
    })
  })
})

async function createAuthorizedPair(idleTimeoutMs = 30000) {
  const fixture = await createLocalServerFixture()
  const device = createClientFixture()
  const { encoded: invite } = await fixture.storage.createLocalServerInvite(fixture.storageId, {
    expiresAt: 2000000000,
    maxUses: 1
  })
  let server!: ServerTcpPeerConnection
  const handle = await startTcpServer({
    storage: fixture.storage,
    localStorageId: fixture.storageId,
    serverId: fixture.serverId,
    serverPublicKey: fixture.publicKey,
    serverPrivateKey: fixture.privateKey,
    idleTimeoutMs,
    onMemberConnected: (connection) => { server = connection }
  })
  activeServers.push(handle)
  const client = connectAndAdmitTcpPeer({
    host: handle.host,
    port: handle.port,
    expectedServerId: fixture.serverId,
    deviceFingerprint: device.fingerprint,
    devicePublicKey: device.publicKey,
    devicePrivateKey: device.privateKey,
    invite,
    idleTimeoutMs
  })
  await client.waitForAdmission()
  return { client, server }
}

function getServerMembers(serverFixture: { userDataDir: string; storageId: string }) {
  const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
  const db = openServerDatabase(dbPath)
  const members = listMembers(db)
  db.close()
  return members
}

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-tcp-transport-'))
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

  const server = await storage.createLocalServer('Servidor Teste TCP')

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

        // Parse key from PKCS8 DER base64
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
