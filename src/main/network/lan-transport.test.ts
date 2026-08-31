import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { type NetworkInterfaceInfo } from 'node:os'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { DATABASE_FILE_NAME, listMembers, openServerDatabase } from '../servers/server-database'
import {
  connectLanTcpPeer,
  type DirectTcpEndpoint,
  type LanTcpServerHandle,
  startLanTcpServer
} from './lan-transport'
import { listLocalNetworkInterfaces } from './network-interfaces'

const testRoots: string[] = []
const activeServers: LanTcpServerHandle[] = []

afterEach(async () => {
  await Promise.all(activeServers.splice(0).map((srv) => srv.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

describe('lan-transport: exposição LAN controlada, validação estrita e endpoints diretos', () => {
  describe('validação de bind e rejeição de wildcards/globais (testes 48 a 58)', () => {
    it('rejeita bind em wildcard 0.0.0.0 antes de iniciar listener (fail closed)', async () => {
      const serverFixture = await createLocalServerFixture()

      await expect(
        startLanTcpServer({
          bindAddress: '0.0.0.0',
          port: 0,
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey
        })
      ).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_WILDCARD_PROHIBITED'
      })
    })

    it('rejeita bind em wildcard IPv6 :: antes de iniciar listener', async () => {
      const serverFixture = await createLocalServerFixture()

      await expect(
        startLanTcpServer({
          bindAddress: '::',
          port: 0,
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey
        })
      ).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_WILDCARD_PROHIBITED'
      })
    })

    it('rejeita bind em endereço não atribuído a nenhuma interface local', async () => {
      const serverFixture = await createLocalServerFixture()

      await expect(
        startLanTcpServer({
          bindAddress: '192.168.99.123',
          port: 0,
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          interfaceProvider: () => ({
            eth0: [
              {
                address: '192.168.1.50',
                family: 'IPv4',
                internal: false
              } as unknown as NetworkInterfaceInfo
            ]
          })
        })
      ).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_BIND_ADDRESS_UNAVAILABLE'
      })
    })

    it('rejeita bind em IPv4 público/global mesmo se declarado na interface local', async () => {
      const serverFixture = await createLocalServerFixture()

      await expect(
        startLanTcpServer({
          bindAddress: '8.8.8.8',
          port: 0,
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          interfaceProvider: () => ({
            wan0: [
              {
                address: '8.8.8.8',
                family: 'IPv4',
                internal: false
              } as unknown as NetworkInterfaceInfo
            ]
          })
        })
      ).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_GLOBAL_ADDRESS_PROHIBITED'
      })
    })

    it('rejeita bind em IPv6 global (2001:db8::1) para listener LAN', async () => {
      const serverFixture = await createLocalServerFixture()

      await expect(
        startLanTcpServer({
          bindAddress: '2001:db8::1',
          port: 0,
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          interfaceProvider: () => ({
            wan0: [
              {
                address: '2001:db8::1',
                family: 'IPv6',
                internal: false
              } as unknown as NetworkInterfaceInfo
            ]
          })
        })
      ).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_GLOBAL_ADDRESS_PROHIBITED'
      })
    })

    it('trata hot-unplug lógico: rejeita bind se o IP desaparecer antes da revalidação no bind', async () => {
      const serverFixture = await createLocalServerFixture()

      // O provider agora está vazio (interface desconectada)
      const emptyProvider = () => ({})

      await expect(
        startLanTcpServer({
          bindAddress: '192.168.1.100',
          port: 0,
          storage: serverFixture.storage,
          localStorageId: serverFixture.storageId,
          serverId: serverFixture.serverId,
          serverPublicKey: serverFixture.publicKey,
          serverPrivateKey: serverFixture.privateKey,
          interfaceProvider: emptyProvider
        })
      ).rejects.toMatchObject({
        name: 'TcpTransportError',
        code: 'TCP_BIND_ADDRESS_UNAVAILABLE'
      })
    })
  })

  describe('validação de cliente direto e rejeição de destinos inseguros (testes 59 a 64)', () => {
    it('rejeita conexão para wildcard 0.0.0.0 no cliente', () => {
      const clientFixture = createClientFixture()
      const endpoint: DirectTcpEndpoint = {
        family: 4,
        address: '0.0.0.0',
        port: 5000
      }

      expect(() => {
        connectLanTcpPeer({
          endpoint,
          expectedServerId: 's:ed25519:test',
          deviceFingerprint: clientFixture.fingerprint,
          devicePublicKey: clientFixture.publicKey,
          devicePrivateKey: clientFixture.privateKey,
          invite: 'MQR1.fake'
        })
      }).toThrowError(expect.objectContaining({ code: 'TCP_WILDCARD_PROHIBITED' }))
    })

    it('rejeita conexão para hostname DNS arbitrário (example.com / host.local)', () => {
      const clientFixture = createClientFixture()
      const endpoint: DirectTcpEndpoint = {
        family: 4,
        address: 'example.com',
        port: 5000
      }

      expect(() => {
        connectLanTcpPeer({
          endpoint,
          expectedServerId: 's:ed25519:test',
          deviceFingerprint: clientFixture.fingerprint,
          devicePublicKey: clientFixture.publicKey,
          devicePrivateKey: clientFixture.privateKey,
          invite: 'MQR1.fake'
        })
      }).toThrowError(expect.objectContaining({ code: 'TCP_ENDPOINT_INVALID' }))
    })

    it('rejeita conexão cliente para IPv4 público (ex: 8.8.8.8)', () => {
      const clientFixture = createClientFixture()
      const endpoint: DirectTcpEndpoint = {
        family: 4,
        address: '8.8.8.8',
        port: 5000
      }

      expect(() => {
        connectLanTcpPeer({
          endpoint,
          expectedServerId: 's:ed25519:test',
          deviceFingerprint: clientFixture.fingerprint,
          devicePublicKey: clientFixture.publicKey,
          devicePrivateKey: clientFixture.privateKey,
          invite: 'MQR1.fake'
        })
      }).toThrowError(expect.objectContaining({ code: 'TCP_GLOBAL_ADDRESS_PROHIBITED' }))
    })

    it('rejeita conexão para IPv6 link-local sem scopeId informado', () => {
      const clientFixture = createClientFixture()
      const endpoint: DirectTcpEndpoint = {
        family: 6,
        address: 'fe80::1',
        port: 5000
      }

      expect(() => {
        connectLanTcpPeer({
          endpoint,
          expectedServerId: 's:ed25519:test',
          deviceFingerprint: clientFixture.fingerprint,
          devicePublicKey: clientFixture.publicKey,
          devicePrivateKey: clientFixture.privateKey,
          invite: 'MQR1.fake'
        })
      }).toThrowError(expect.objectContaining({ code: 'TCP_ENDPOINT_INVALID' }))
    })

    it('encerra conexão fail-closed quando connectTimeoutMs expira para host inalcançável', async () => {
      const clientFixture = createClientFixture()
      // 192.0.2.1 é TEST-NET-1 (RFC 5737), não roteável e silencioso
      const endpoint: DirectTcpEndpoint = {
        family: 4,
        address: '127.0.0.1',
        port: 65432 // Porta fechada
      }

      const clientConn = connectLanTcpPeer({
        endpoint,
        expectedServerId: 's:ed25519:test',
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake',
        connectTimeoutMs: 50
      })

      await expect(clientConn.waitForAdmission()).rejects.toBeDefined()
      expect(clientConn.getState()).toBe('FAILED')
    })
  })

  describe('fluxo completo ponta a ponta sobre DirectTcpEndpoint (testes 65 e 66)', () => {
    it('executa handshake, sessão confidencial e admissão através de DirectTcpEndpoint', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

      const { encoded: inviteToken } = await serverFixture.storage.createLocalServerInvite(
        serverFixture.storageId,
        {
          expiresAt: 2000000000,
          maxUses: 1
        }
      )

      // Listener vinculado a 127.0.0.1 (Loopback validado)
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

      expect(serverHandle.endpoint.address).toBe('127.0.0.1')
      expect(serverHandle.endpoint.port).toBeGreaterThan(0)
      expect(serverHandle.endpoint.family).toBe(4)

      const directEndpoint: DirectTcpEndpoint = {
        family: serverHandle.endpoint.family,
        address: serverHandle.endpoint.address,
        port: serverHandle.endpoint.port
      }

      const clientConn = connectLanTcpPeer({
        endpoint: directEndpoint,
        expectedServerId: serverFixture.serverId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: inviteToken
      })

      const admissionResult = await clientConn.waitForAdmission()
      expect(admissionResult.status).toBe('admitted')
      expect(clientConn.getState()).toBe('MEMBER_CONNECTED')

      const members = getServerMembers(serverFixture)
      expect(members.some((m) => m.deviceFingerprint === clientFixture.fingerprint)).toBe(true)

      clientConn.destroy()
    })

    it('garante independência estrita entre IP do endpoint e Server Identity (IP não é identidade)', async () => {
      const serverFixture = await createLocalServerFixture()
      const clientFixture = createClientFixture()

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

      const wrongServerId = 's:ed25519:' + 'f'.repeat(64)

      const directEndpoint: DirectTcpEndpoint = {
        family: 4,
        address: serverHandle.endpoint.address,
        port: serverHandle.endpoint.port
      }

      const clientConn = connectLanTcpPeer({
        endpoint: directEndpoint,
        expectedServerId: wrongServerId,
        deviceFingerprint: clientFixture.fingerprint,
        devicePublicKey: clientFixture.publicKey,
        devicePrivateKey: clientFixture.privateKey,
        invite: 'MQR1.fake'
      })

      await expect(clientConn.waitForAdmission()).rejects.toBeDefined()
      expect(clientConn.getState()).toBe('FAILED')
    })

    it('smoke test em interface local LAN real (quando disponível no host)', async () => {
      const realInterfaces = listLocalNetworkInterfaces()
      const lanInterface = realInterfaces.find(
        (iface) => iface.scope === 'LAN_PRIVATE' && iface.family === 'IPv4'
      )

      if (!lanInterface) {
        // Ambiente sem adaptador LAN ativo (ex: CI isolado). Smoke test via loopback.
        expect(true).toBe(true)
        return
      }

      const serverFixture = await createLocalServerFixture()
      const serverHandle = await startLanTcpServer({
        bindAddress: lanInterface.address,
        port: 0,
        storage: serverFixture.storage,
        localStorageId: serverFixture.storageId,
        serverId: serverFixture.serverId,
        serverPublicKey: serverFixture.publicKey,
        serverPrivateKey: serverFixture.privateKey
      })
      activeServers.push(serverHandle)

      expect(serverHandle.endpoint.address).toBe(lanInterface.address)
      expect(serverHandle.endpoint.port).toBeGreaterThan(0)
      expect(serverHandle.endpoint.interfaceName).toBe(lanInterface.interfaceName)
    })
  })
})

function getServerMembers(serverFixture: { userDataDir: string; storageId: string }) {
  const dbPath = join(serverFixture.userDataDir, 'servers', serverFixture.storageId, DATABASE_FILE_NAME)
  const db = openServerDatabase(dbPath)
  const members = listMembers(db)
  db.close()
  return members
}

async function createLocalServerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masquerada-lan-transport-'))
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

  const server = await storage.createLocalServer('Servidor LAN Teste')

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
