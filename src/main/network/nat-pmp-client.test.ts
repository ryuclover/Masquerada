import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { createSocket } from 'node:dgram'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { generateKeyPairSync, createHash, createPrivateKey, type KeyObject } from 'node:crypto'

import {
  NAT_PMP_VERSION,
  NAT_PMP_OP_EXTERNAL_ADDRESS,
  NAT_PMP_OP_MAP_TCP,
  NAT_PMP_SERVER_PORT,
  NAT_PMP_EXTERNAL_ADDRESS_REQUEST_BYTES,
  NAT_PMP_EXTERNAL_ADDRESS_RESPONSE_BYTES,
  NAT_PMP_TCP_MAPPING_REQUEST_BYTES,
  NAT_PMP_TCP_MAPPING_RESPONSE_BYTES,
  NatPmpResultCode,
  NatPmpError,
  encodeNatPmpExternalAddressRequest,
  decodeNatPmpExternalAddressResponse,
  encodeNatPmpTcpMappingRequest,
  decodeNatPmpTcpMappingResponse,
  createNatPmpPortMapping,
  validateNatPmpEpochTransition,
  NatPmpActivePortMapping,
  type NatPmpErrorCode
} from './nat-pmp-client'

import { createPcpFirstPortMapping } from './pcp-nat-pmp-orchestrator'
import {
  decodePcpUnsupportedVersionResponse,
  createPcpPortMapping,
  isLegitimateActivePortMapping,
  PcpError,
  PcpResultCode
} from './pcp-client'
import { startLanTcpServer, type LanTcpServerHandle } from './lan-transport'
import {
  createSignedConnectivityDescriptor,
  verifySignedConnectivityDescriptor,
  ConnectivityCandidateType
} from './connectivity-descriptor'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'

// ─── FakeSecureStorage ───────────────────────────────────────────────────

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
        if (!plaintext) throw new Error('Ciphertext invalido')
        return plaintext
      }
    },
    get lastGeneratedServerKey() { return lastKey }
  }
}

// ─── LocalServerFixture ───────────────────────────────────────────────────

const testRoots: string[] = []
const activeServers: LanTcpServerHandle[] = []

afterEach(async () => {
  await Promise.all(activeServers.splice(0).map((srv) => srv.close()))
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

async function createLocalServerFixture(prefix = 'masq-natpmp-') {
  const root = await mkdtemp(join(tmpdir(), prefix))
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

  const server = await storage.createLocalServer('Servidor NAT-PMP Teste')
  const serverKeyPair = fakeSecureStorage.lastGeneratedServerKey
  if (!serverKeyPair) throw new Error('Chave do servidor nao encontrada')

  return {
    storage,
    userDataDir: root,
    storageId: server.localStorageId,
    serverId: server.serverId,
    publicKey: server.identity.publicKey,
    privateKey: serverKeyPair
  }
}

async function startTestServer(fixture: Awaited<ReturnType<typeof createLocalServerFixture>>): Promise<LanTcpServerHandle> {
  const handle = await startLanTcpServer({
    bindAddress: '127.0.0.1',
    port: 0,
    storage: fixture.storage,
    localStorageId: fixture.storageId,
    serverId: fixture.serverId,
    serverPublicKey: fixture.publicKey,
    serverPrivateKey: fixture.privateKey
  })
  activeServers.push(handle)
  return handle
}

// ─── FakeNatPmpServer ─────────────────────────────────────────────────────

async function startFakeNatPmpServer(bindAddress = '127.0.0.1') {
  const socket = createSocket('udp4')
  const receivedRequests: Buffer[] = []
  let responseHandler: ((req: Buffer, peer: { address: string; port: number }) => Buffer | null) | null = null

  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, bindAddress, () => { socket.off('error', reject); resolve() })
  })

  const addrInfo = socket.address()
  socket.on('message', (msg: Buffer, rinfo) => {
    receivedRequests.push(Buffer.from(msg))
    if (responseHandler) {
      const resp = responseHandler(msg, rinfo)
      if (resp) socket.send(resp, rinfo.port, rinfo.address)
    }
  })

  return {
    port: addrInfo.port,
    address: addrInfo.address,
    getReceivedRequests: () => receivedRequests,
    setResponseHandler: (fn: ((req: Buffer, peer: { address: string; port: number }) => Buffer | null) | null) => { responseHandler = fn },
    close: async () => {
      socket.removeAllListeners()
      await new Promise<void>((resolve) => socket.close(() => resolve()))
    }
  }
}

function buildFakeOp0Response(opts: {
  version?: number; op?: number; resultCode?: NatPmpResultCode;
  epochTime?: number; externalAddress?: string
}): Buffer {
  const buf = Buffer.alloc(NAT_PMP_EXTERNAL_ADDRESS_RESPONSE_BYTES, 0)
  buf.writeUInt8(opts.version ?? NAT_PMP_VERSION, 0)
  buf.writeUInt8(opts.op ?? (128 + NAT_PMP_OP_EXTERNAL_ADDRESS), 1)
  buf.writeUInt16BE(opts.resultCode ?? NatPmpResultCode.SUCCESS, 2)
  buf.writeUInt32BE(opts.epochTime ?? 12345, 4)
  const ip = opts.externalAddress ?? '8.8.4.4'
  const parts = ip.split('.').map(Number)
  buf[8] = parts[0]!; buf[9] = parts[1]!; buf[10] = parts[2]!; buf[11] = parts[3]!
  return buf
}

function buildFakeOp2Response(opts: {
  version?: number; op?: number; resultCode?: NatPmpResultCode; epochTime?: number;
  internalPort?: number; assignedExternalPort?: number; assignedLifetimeSeconds?: number
}): Buffer {
  const buf = Buffer.alloc(NAT_PMP_TCP_MAPPING_RESPONSE_BYTES, 0)
  buf.writeUInt8(opts.version ?? NAT_PMP_VERSION, 0)
  buf.writeUInt8(opts.op ?? (128 + NAT_PMP_OP_MAP_TCP), 1)
  buf.writeUInt16BE(opts.resultCode ?? NatPmpResultCode.SUCCESS, 2)
  buf.writeUInt32BE(opts.epochTime ?? 12345, 4)
  buf.writeUInt16BE(opts.internalPort ?? 0, 8)
  buf.writeUInt16BE(opts.assignedExternalPort ?? 44444, 10)
  buf.writeUInt32BE(opts.assignedLifetimeSeconds ?? 3600, 12)
  return buf
}

function buildPcpUnsupportedVersionResponse(epochTime = 1234): Buffer {
  const response = Buffer.alloc(8)
  response.writeUInt8(0, 0)
  response.writeUInt8(0, 1)
  response.writeUInt16BE(1, 2)
  response.writeUInt32BE(epochTime, 4)
  return response
}

function buildPcpMapResponse(request: Buffer, resultCode = PcpResultCode.SUCCESS): Buffer {
  const response = Buffer.alloc(60)
  response.writeUInt8(2, 0)
  response.writeUInt8(0x81, 1)
  response.writeUInt8(resultCode, 3)
  response.writeUInt32BE(resultCode === 0 ? 3600 : 0, 4)
  response.writeUInt32BE(5000, 8)
  request.subarray(24, 36).copy(response, 24)
  response.writeUInt8(6, 36)
  response.writeUInt16BE(request.readUInt16BE(40), 40)
  response.writeUInt16BE(resultCode === 0 ? 55001 : 0, 42)
  response.writeUInt16BE(0xffff, 54)
  response.set([8, 8, 4, 4], 56)
  return response
}

describe('NAT-PMP constants (RFC 6886)', () => {
  it('NAT_PMP_VERSION deve ser 0', () => { expect(NAT_PMP_VERSION).toBe(0) })
  it('NAT_PMP_OP_EXTERNAL_ADDRESS deve ser 0', () => { expect(NAT_PMP_OP_EXTERNAL_ADDRESS).toBe(0) })
  it('NAT_PMP_OP_MAP_TCP deve ser 2', () => { expect(NAT_PMP_OP_MAP_TCP).toBe(2) })
  it('porta do servidor deve ser 5351', () => { expect(NAT_PMP_SERVER_PORT).toBe(5351) })
  it('OP0 request deve ter 2 bytes', () => { expect(NAT_PMP_EXTERNAL_ADDRESS_REQUEST_BYTES).toBe(2) })
  it('OP0 response deve ter 12 bytes', () => { expect(NAT_PMP_EXTERNAL_ADDRESS_RESPONSE_BYTES).toBe(12) })
  it('OP2 request deve ter 12 bytes', () => { expect(NAT_PMP_TCP_MAPPING_REQUEST_BYTES).toBe(12) })
  it('OP2 response deve ter 16 bytes', () => { expect(NAT_PMP_TCP_MAPPING_RESPONSE_BYTES).toBe(16) })
  it('SUCCESS deve ser 0', () => { expect(NatPmpResultCode.SUCCESS).toBe(0) })
  it('UNSUPP_VERSION deve ser 1', () => { expect(NatPmpResultCode.UNSUPP_VERSION).toBe(1) })
  it('NOT_AUTHORIZED deve ser 2', () => { expect(NatPmpResultCode.NOT_AUTHORIZED).toBe(2) })
  it('NETWORK_FAILURE deve ser 3', () => { expect(NatPmpResultCode.NETWORK_FAILURE).toBe(3) })
  it('OUT_OF_RESOURCES deve ser 4', () => { expect(NatPmpResultCode.OUT_OF_RESOURCES).toBe(4) })
  it('UNSUPP_OPCODE deve ser 5', () => { expect(NatPmpResultCode.UNSUPP_OPCODE).toBe(5) })
})

describe('encodeNatPmpExternalAddressRequest', () => {
  it('deve retornar exatamente 2 bytes', () => {
    expect(encodeNatPmpExternalAddressRequest().length).toBe(2)
  })
  it('byte 0 deve ser Version=0', () => {
    expect(encodeNatPmpExternalAddressRequest().readUInt8(0)).toBe(0)
  })
  it('byte 1 deve ser OP=0', () => {
    expect(encodeNatPmpExternalAddressRequest().readUInt8(1)).toBe(0)
  })
  it('deve retornar novo buffer a cada chamada', () => {
    const b1 = encodeNatPmpExternalAddressRequest()
    const b2 = encodeNatPmpExternalAddressRequest()
    expect(b1).not.toBe(b2)
    expect(b1.equals(b2)).toBe(true)
  })
})

describe('decodeNatPmpExternalAddressResponse', () => {
  it('deve decodificar response valida', () => {
    const r = decodeNatPmpExternalAddressResponse(buildFakeOp0Response({ externalAddress: '198.51.100.1', epochTime: 9999 }))
    expect(r.resultCode).toBe(NatPmpResultCode.SUCCESS)
    expect(r.epochTime).toBe(9999)
    expect(r.externalAddress).toBe('198.51.100.1')
  })
  it('deve rejeitar buffer menor que 12 bytes', () => {
    expect(() => decodeNatPmpExternalAddressResponse(Buffer.alloc(8))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })
  it('deve rejeitar version != 0', () => {
    expect(() => decodeNatPmpExternalAddressResponse(buildFakeOp0Response({ version: 2 }))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })
  it('deve rejeitar op incorreto', () => {
    expect(() => decodeNatPmpExternalAddressResponse(buildFakeOp0Response({ op: 129 }))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })
  it('UNSUPP_VERSION -> NAT_PMP_UNSUPPORTED_VERSION', () => {
    expect(() => decodeNatPmpExternalAddressResponse(
      buildFakeOp0Response({ resultCode: NatPmpResultCode.UNSUPP_VERSION })
    )).toThrow(expect.objectContaining({ code: 'NAT_PMP_UNSUPPORTED_VERSION' }))
  })
  it('NOT_AUTHORIZED possui taxonomia específica', () => {
    expect(() => decodeNatPmpExternalAddressResponse(
      buildFakeOp0Response({ resultCode: NatPmpResultCode.NOT_AUTHORIZED })
    )).toThrow(expect.objectContaining({ code: 'NAT_PMP_NOT_AUTHORIZED', resultCode: NatPmpResultCode.NOT_AUTHORIZED }))
  })
  it('deve extrair 0.0.0.0 corretamente', () => {
    expect(decodeNatPmpExternalAddressResponse(buildFakeOp0Response({ externalAddress: '0.0.0.0' })).externalAddress).toBe('0.0.0.0')
  })
  it('deve extrair 255.255.255.255 corretamente', () => {
    expect(decodeNatPmpExternalAddressResponse(buildFakeOp0Response({ externalAddress: '255.255.255.255' })).externalAddress).toBe('255.255.255.255')
  })
  it('deve rejeitar null', () => {
    expect(() => decodeNatPmpExternalAddressResponse(null as unknown as Buffer)).toThrow(NatPmpError)
  })
  it('deve rejeitar undefined', () => {
    expect(() => decodeNatPmpExternalAddressResponse(undefined as unknown as Buffer)).toThrow(NatPmpError)
  })
})

describe('encodeNatPmpTcpMappingRequest', () => {
  it('deve retornar exatamente 12 bytes', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 8080, requestedLifetimeSeconds: 3600 }).length).toBe(12)
  })
  it('Version=0 em byte 0', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 1234, requestedLifetimeSeconds: 100 }).readUInt8(0)).toBe(0)
  })
  it('OP=2 em byte 1', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 1234, requestedLifetimeSeconds: 100 }).readUInt8(1)).toBe(2)
  })
  it('Reserved=0 em bytes 2-3', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 1234, requestedLifetimeSeconds: 100 }).readUInt16BE(2)).toBe(0)
  })
  it('internalPort em bytes 4-5', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 9999, requestedLifetimeSeconds: 100 }).readUInt16BE(4)).toBe(9999)
  })
  it('suggestedExternalPort=0 quando omitido', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 1234, requestedLifetimeSeconds: 100 }).readUInt16BE(6)).toBe(0)
  })
  it('suggestedExternalPort codificado quando fornecido', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 1234, suggestedExternalPort: 8888, requestedLifetimeSeconds: 100 }).readUInt16BE(6)).toBe(8888)
  })
  it('lifetime em bytes 8-11', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 1, requestedLifetimeSeconds: 7200 }).readUInt32BE(8)).toBe(7200)
  })
  it('deve rejeitar porta 0', () => {
    expect(() => encodeNatPmpTcpMappingRequest({ internalPort: 0, requestedLifetimeSeconds: 100 })).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_REQUEST_INVALID' })
    )
  })
  it('deve rejeitar porta 65536', () => {
    expect(() => encodeNatPmpTcpMappingRequest({ internalPort: 65536, requestedLifetimeSeconds: 100 })).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_REQUEST_INVALID' })
    )
  })
  it('deve rejeitar lifetime negativo', () => {
    expect(() => encodeNatPmpTcpMappingRequest({ internalPort: 80, requestedLifetimeSeconds: -1 })).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_REQUEST_INVALID' })
    )
  })
  it('deve aceitar lifetime=0 (delete)', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 80, requestedLifetimeSeconds: 0 }).readUInt32BE(8)).toBe(0)
  })
  it('deve aceitar porta maxima 65535', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 65535, requestedLifetimeSeconds: 100 }).readUInt16BE(4)).toBe(65535)
  })
})

describe('decodeNatPmpTcpMappingResponse', () => {
  it('deve decodificar response valida', () => {
    const r = decodeNatPmpTcpMappingResponse(buildFakeOp2Response({
      internalPort: 1234, assignedExternalPort: 55000, assignedLifetimeSeconds: 3600, epochTime: 54321
    }))
    expect(r.resultCode).toBe(NatPmpResultCode.SUCCESS)
    expect(r.epochTime).toBe(54321)
    expect(r.internalPort).toBe(1234)
    expect(r.assignedExternalPort).toBe(55000)
    expect(r.assignedLifetimeSeconds).toBe(3600)
  })
  it('deve rejeitar buffer menor que 16 bytes', () => {
    expect(() => decodeNatPmpTcpMappingResponse(Buffer.alloc(12))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })
  it('deve rejeitar version != 0', () => {
    expect(() => decodeNatPmpTcpMappingResponse(buildFakeOp2Response({ version: 1 }))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })
  it('deve rejeitar op != 130 (128+2)', () => {
    expect(() => decodeNatPmpTcpMappingResponse(buildFakeOp2Response({ op: 128 }))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })
  it('UNSUPP_VERSION -> NAT_PMP_UNSUPPORTED_VERSION', () => {
    expect(() => decodeNatPmpTcpMappingResponse(buildFakeOp2Response({ resultCode: NatPmpResultCode.UNSUPP_VERSION }))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_UNSUPPORTED_VERSION' })
    )
  })
  it('OUT_OF_RESOURCES possui taxonomia específica', () => {
    expect(() => decodeNatPmpTcpMappingResponse(buildFakeOp2Response({ resultCode: NatPmpResultCode.OUT_OF_RESOURCES }))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_OUT_OF_RESOURCES', resultCode: NatPmpResultCode.OUT_OF_RESOURCES })
    )
  })
  it('deve rejeitar undefined', () => {
    expect(() => decodeNatPmpTcpMappingResponse(undefined as unknown as Buffer)).toThrow(NatPmpError)
  })
})

describe('NatPmpError', () => {
  it('name deve ser NatPmpError', () => { expect(new NatPmpError('NAT_PMP_TIMEOUT').name).toBe('NatPmpError') })
  it('code deve ser armazenado', () => { expect(new NatPmpError('NAT_PMP_GATEWAY_NOT_FOUND').code).toBe('NAT_PMP_GATEWAY_NOT_FOUND') })
  it('resultCode deve ser armazenado', () => {
    expect(new NatPmpError('NAT_PMP_SERVER_ERROR', NatPmpResultCode.NOT_AUTHORIZED).resultCode).toBe(NatPmpResultCode.NOT_AUTHORIZED)
  })
  it('deve ser instancia de Error', () => { expect(new NatPmpError('NAT_PMP_TIMEOUT')).toBeInstanceOf(Error) })
  it('mensagem deve ser nao-vazia', () => { expect(new NatPmpError('NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL').message.length).toBeGreaterThan(0) })
  it('resultCode deve ser undefined quando nao fornecido', () => {
    expect(new NatPmpError('NAT_PMP_TIMEOUT').resultCode).toBeUndefined()
  })
})

describe('createNatPmpPortMapping — validacoes de listener', () => {
  it('deve rejeitar listener invalido (objeto comum)', async () => {
    await expect(createNatPmpPortMapping({ listener: {} as unknown as LanTcpServerHandle }))
      .rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_LISTENER_INVALID' }))
  })

  it('deve rejeitar listener nulo', async () => {
    await expect(createNatPmpPortMapping({ listener: null as unknown as LanTcpServerHandle }))
      .rejects.toThrow(NatPmpError)
  })

  it('deve rejeitar listener fechado', async () => {
    const fix = await createLocalServerFixture('masq-lc-')
    const handle = await startTestServer(fix)
    await handle.close()
    activeServers.splice(activeServers.indexOf(handle), 1)
    await expect(createNatPmpPortMapping({ listener: handle }))
      .rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_LISTENER_CLOSED' }))
  })

  it('production rejeita listener loopback antes de gateway/network I/O', async () => {
    const fix = await createLocalServerFixture('masq-rfc1918-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({ listener: handle })).rejects.toThrow(
      expect.objectContaining({ code: 'NAT_PMP_REQUEST_INVALID' })
    )
  })

  it('create rejeita lifetime zero em vez de interpretá-lo como delete', async () => {
    const fix = await createLocalServerFixture('masq-life-zero-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({
      listener: handle,
      requestedLifetimeSeconds: 0,
      customGatewayAddress: '127.0.0.1'
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_REQUEST_INVALID' }))
  })

  it('deve rejeitar quando gateway nao encontrado', async () => {
    const fix = await createLocalServerFixture('masq-lgw-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({
      listener: handle,
      gatewayProvider: { resolveGatewayForLocalAddress: async () => null }
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_GATEWAY_NOT_FOUND' }))
  })

  it('deve rejeitar gateway IP global (8.8.8.8)', async () => {
    const fix = await createLocalServerFixture('masq-lgwg-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({
      listener: handle,
      gatewayProvider: { resolveGatewayForLocalAddress: async () => '8.8.8.8' }
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_GATEWAY_INVALID' }))
  })

  it('deve rejeitar gateway CGNAT (100.64.0.1)', async () => {
    const fix = await createLocalServerFixture('masq-lcgn-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({
      listener: handle,
      gatewayProvider: { resolveGatewayForLocalAddress: async () => '100.64.0.1' }
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_GATEWAY_INVALID' }))
  })

  it('deve rejeitar gateway IPv6 (::1)', async () => {
    const fix = await createLocalServerFixture('masq-lipv6-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({ listener: handle, customGatewayAddress: '::1' }))
      .rejects.toThrow(NatPmpError)
  })
})

describe('createNatPmpPortMapping — transacao UDP', () => {
  let fakeGw: Awaited<ReturnType<typeof startFakeNatPmpServer>> | null = null

  beforeEach(async () => { fakeGw = await startFakeNatPmpServer('127.0.0.1') })
  afterEach(async () => { if (fakeGw) { await fakeGw.close(); fakeGw = null } })

  it('deve criar ActivePortMapping via OP0+OP2', async () => {
    const fix = await createLocalServerFixture('masq-udp01-')
    const handle = await startTestServer(fix)
    let reqCount = 0
    fakeGw!.setResponseHandler((req) => {
      reqCount++
      return req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 55000, assignedLifetimeSeconds: 3600 })
    })
    const mapping = await createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })
    expect(isLegitimateActivePortMapping(mapping)).toBe(true)
    expect(mapping.isActive()).toBe(true)
    const ext = mapping.getExternalEndpoint()
    expect(ext.address).toBe('8.8.4.4')
    expect(ext.port).toBe(55000)
    expect(ext.family).toBe(4)
    expect(mapping.getGrantedLifetime()).toBe(3600)
    expect(reqCount).toBeGreaterThanOrEqual(2)
  }, 10000)

  it('IP externo RFC1918 -> NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL', async () => {
    const fix = await createLocalServerFixture('masq-udp02-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS ? buildFakeOp0Response({ externalAddress: '192.168.1.1' }) : null
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL' }))
  }, 10000)

  it('IP externo CGNAT (100.64.x.x) -> NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL', async () => {
    const fix = await createLocalServerFixture('masq-udp03-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS ? buildFakeOp0Response({ externalAddress: '100.64.0.1' }) : null
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL' }))
  }, 10000)

  it('IP externo loopback (127.0.0.1) -> NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL', async () => {
    const fix = await createLocalServerFixture('masq-udp04-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS ? buildFakeOp0Response({ externalAddress: '127.0.0.1' }) : null
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL' }))
  }, 10000)

  it('IP externo documentation TEST-NET -> NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL', async () => {
    const fix = await createLocalServerFixture('masq-udp-doc-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS ? buildFakeOp0Response({ externalAddress: '203.0.113.10' }) : null
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL' }))
  }, 10000)

  it('OP0 UNSUPP_VERSION -> NAT_PMP_UNSUPPORTED_VERSION', async () => {
    const fix = await createLocalServerFixture('masq-udp05-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS ? buildFakeOp0Response({ resultCode: NatPmpResultCode.UNSUPP_VERSION }) : null
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_UNSUPPORTED_VERSION' }))
  }, 10000)

  it('OP0 NOT_AUTHORIZED possui taxonomia específica', async () => {
    const fix = await createLocalServerFixture('masq-udp06-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS ? buildFakeOp0Response({ resultCode: NatPmpResultCode.NOT_AUTHORIZED }) : null
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_NOT_AUTHORIZED' }))
  }, 10000)

  it('OP2 OUT_OF_RESOURCES possui taxonomia específica', async () => {
    const fix = await createLocalServerFixture('masq-udp07-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        : buildFakeOp2Response({ resultCode: NatPmpResultCode.OUT_OF_RESOURCES })
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_OUT_OF_RESOURCES' }))
  }, 10000)

  it('OP2 assignedExternalPort=0 -> NAT_PMP_RESPONSE_INVALID', async () => {
    const fix = await createLocalServerFixture('masq-udp08-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 0, assignedLifetimeSeconds: 3600 })
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' }))
  }, 10000)

  it('OP2 lifetime=0 -> NAT_PMP_RESPONSE_INVALID', async () => {
    const fix = await createLocalServerFixture('masq-udp09-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 44444, assignedLifetimeSeconds: 0 })
    )
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' }))
  }, 10000)

  it('resultado deve ser valido para SignedConnectivityDescriptor', async () => {
    const fix = await createLocalServerFixture('masq-udp10-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((req) =>
      req.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 62000, assignedLifetimeSeconds: 3600 })
    )
    const mapping = await createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1
    })
    const encoded = createSignedConnectivityDescriptor({
      serverId: fix.serverId,
      serverPublicKey: fix.publicKey,
      serverPrivateKey: fix.privateKey,
      candidates: [mapping]
    })
    const verified = verifySignedConnectivityDescriptor({
      encodedDescriptor: encoded, expectedServerId: fix.serverId
    })
    expect(verified.candidates).toHaveLength(1)
    expect(verified.candidates[0]!.candidateType).toBe(ConnectivityCandidateType.PORT_MAPPED_TCP)
    expect(verified.candidates[0]!.address).toBe('8.8.4.4')
  }, 10000)
})

describe('createNatPmpPortMapping — timeout e retransmissao', () => {
  let fakeGw: Awaited<ReturnType<typeof startFakeNatPmpServer>> | null = null

  beforeEach(async () => { fakeGw = await startFakeNatPmpServer('127.0.0.1') })
  afterEach(async () => { if (fakeGw) { await fakeGw.close(); fakeGw = null } })

  it('deve lancar NAT_PMP_TIMEOUT se gateway nao responder', async () => {
    const fix = await createLocalServerFixture('masq-to01-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler(null)
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port,
      initialTimeoutMs: 100, maxRetransmissions: 2
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_TIMEOUT' }))
  }, 10000)

  it('deve retransmitir OP0 multiplas vezes antes do timeout', async () => {
    const fix = await createLocalServerFixture('masq-to02-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler(null)
    await expect(createNatPmpPortMapping({
      listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port,
      initialTimeoutMs: 50, maxRetransmissions: 3
    })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_TIMEOUT' }))
    const reqs = fakeGw!.getReceivedRequests()
    expect(reqs.length).toBeGreaterThanOrEqual(3)
    expect(reqs[0]!.readUInt8(1)).toBe(NAT_PMP_OP_EXTERNAL_ADDRESS)
  }, 10000)
})

describe('createPcpFirstPortMapping — orchestrador PCP-first', () => {
  let fakeGw: Awaited<ReturnType<typeof startFakeNatPmpServer>> | null = null

  beforeEach(async () => { fakeGw = await startFakeNatPmpServer('127.0.0.1') })
  afterEach(async () => { if (fakeGw) { await fakeGw.close(); fakeGw = null } })

  it('disableNatPmpFallback=true deve propagar erro PCP sem tentar NAT-PMP', async () => {
    const fix = await createLocalServerFixture('masq-orch01-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler(null) // gateway nao responde
    await expect(createPcpFirstPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      timeoutMs: 50,
      maxRetransmissions: 1,
      disableNatPmpFallback: true
    })).rejects.toThrow()
  }, 10000)

  it('PCP timeout (nao UNSUPP_VERSION) nao deve acionar NAT-PMP', async () => {
    const fix = await createLocalServerFixture('masq-orch02-')
    const handle = await startTestServer(fix)
    let natPmpRequested = false
    fakeGw!.setResponseHandler((req) => {
      if (req.readUInt8(0) === 0) natPmpRequested = true
      return null
    })
    await expect(createPcpFirstPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      natPmpGatewayProvider: { resolveGatewayForLocalAddress: async () => '127.0.0.1' },
      timeoutMs: 50,
      maxRetransmissions: 1
    })).rejects.toThrow()
    expect(natPmpRequested).toBe(false)
  }, 10000)

  it('PCP SUCCESS retorna PCP e envia zero pacotes NAT-PMP', async () => {
    const fix = await createLocalServerFixture('masq-orch03-')
    const handle = await startTestServer(fix)
    let natPackets = 0
    fakeGw!.setResponseHandler((request) => {
      if (request.readUInt8(0) === 0) {
        natPackets += 1
        return null
      }
      return buildPcpMapResponse(request)
    })
    const result = await createPcpFirstPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      timeoutMs: 20,
      maxRetransmissions: 1
    })
    expect(result.protocol).toBe('PCP')
    expect(natPackets).toBe(0)
    await result.mapping.close()
  }, 10000)

  it('PCP Unsupported Version estrito executa OP0+OP2 e retorna NAT-PMP', async () => {
    const fix = await createLocalServerFixture('masq-orch04-')
    const handle = await startTestServer(fix)
    const wireVersions: number[] = []
    fakeGw!.setResponseHandler((request) => {
      wireVersions.push(request.readUInt8(0))
      if (request.readUInt8(0) === 2) return buildPcpUnsupportedVersionResponse()
      if (request.readUInt8(1) === NAT_PMP_OP_EXTERNAL_ADDRESS) {
        return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 2000 })
      }
      return buildFakeOp2Response({
        internalPort: handle.endpoint.port,
        assignedExternalPort: 56000,
        assignedLifetimeSeconds: 7200,
        epochTime: 2000
      })
    })
    const result = await createPcpFirstPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      timeoutMs: 20,
      maxRetransmissions: 1
    })
    expect(result.protocol).toBe('NAT_PMP')
    expect(wireVersions.slice(0, 3)).toEqual([2, 0, 0])
    expect(result.mapping.getExternalEndpoint()).toEqual({ family: 4, address: '8.8.4.4', port: 56000 })
    await result.mapping.close()
  }, 10000)

  it('PCP NOT_AUTHORIZED não faz downgrade', async () => {
    const fix = await createLocalServerFixture('masq-orch05-')
    const handle = await startTestServer(fix)
    let natPackets = 0
    fakeGw!.setResponseHandler((request) => {
      if (request.readUInt8(0) === 0) natPackets += 1
      return buildPcpMapResponse(request, PcpResultCode.NOT_AUTHORIZED)
    })
    await expect(createPcpFirstPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      timeoutMs: 20,
      maxRetransmissions: 1
    })).rejects.toThrow(expect.objectContaining({ code: 'PCP_SERVER_ERROR' }))
    expect(natPackets).toBe(0)
  }, 10000)
})

describe('NAT-PMP invariantes de seguranca (SEC-110 a SEC-118)', () => {
  it('SEC-110: listener invalido rejeitado imediatamente', async () => {
    await expect(createNatPmpPortMapping({ listener: {} as unknown as LanTcpServerHandle }))
      .rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_LISTENER_INVALID' }))
  })

  it('SEC-111: gateway IPv6 rejeitado (NAT-PMP e exclusivamente IPv4)', async () => {
    const fix = await createLocalServerFixture('masq-s111-')
    const handle = await startTestServer(fix)
    await expect(createNatPmpPortMapping({ listener: handle, customGatewayAddress: '::1' }))
      .rejects.toThrow(NatPmpError)
  })

  it('SEC-112: classifyNetworkAddress nao considera RFC1918 como global (fail-closed)', async () => {
    const { classifyNetworkAddress } = await import('./network-interfaces')
    expect(classifyNetworkAddress('192.168.1.100').isGloballyRoutableWan).toBe(false)
    expect(classifyNetworkAddress('10.0.0.1').isGloballyRoutableWan).toBe(false)
    expect(classifyNetworkAddress('172.16.0.1').isGloballyRoutableWan).toBe(false)
    expect(classifyNetworkAddress('100.64.0.1').isGloballyRoutableWan).toBe(false)
  })

  it('SEC-113: todos os NatPmpErrorCodes devem ter mensagem nao-vazia', () => {
    const codes: NatPmpErrorCode[] = [
      'NAT_PMP_LISTENER_INVALID', 'NAT_PMP_LISTENER_CLOSED', 'NAT_PMP_GATEWAY_NOT_FOUND',
      'NAT_PMP_GATEWAY_INVALID', 'NAT_PMP_REQUEST_INVALID', 'NAT_PMP_TIMEOUT',
      'NAT_PMP_RESPONSE_INVALID', 'NAT_PMP_RESPONSE_SOURCE_INVALID', 'NAT_PMP_SERVER_ERROR',
      'NAT_PMP_EXTERNAL_ADDRESS_NOT_GLOBAL', 'NAT_PMP_UNSUPPORTED_VERSION', 'NAT_PMP_MAPPING_CLOSED',
      'NAT_PMP_NOT_AUTHORIZED', 'NAT_PMP_NETWORK_FAILURE', 'NAT_PMP_OUT_OF_RESOURCES',
      'NAT_PMP_UNSUPPORTED_OPCODE', 'NAT_PMP_UNKNOWN_RESULT_CODE', 'NAT_PMP_MAPPING_EXPIRED',
      'NAT_PMP_EPOCH_STATE_LOSS'
    ]
    for (const code of codes) {
      const err = new NatPmpError(code)
      expect(err.message.length).toBeGreaterThan(0)
      expect(err.code).toBe(code)
      expect(err).toBeInstanceOf(Error)
    }
  })

  it('SEC-114: OP0 request tem exatamente 2 bytes (nao vaza metadados)', () => {
    const req = encodeNatPmpExternalAddressRequest()
    expect(req.length).toBe(2)
    expect(req[0]).toBe(0)
    expect(req[1]).toBe(0)
  })

  it('SEC-115: OP2 request termina no lifetime e nao inclui IP externo', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 8080, requestedLifetimeSeconds: 3600 })).toHaveLength(12)
  })

  it('SEC-116: objeto manual nao passa isLegitimateActivePortMapping', () => {
    expect(isLegitimateActivePortMapping({ isActive: () => true, getExternalEndpoint: () => ({}) })).toBe(false)
    expect(isLegitimateActivePortMapping(null)).toBe(false)
    expect(isLegitimateActivePortMapping(undefined)).toBe(false)
  })

  it('constructor NAT-PMP sem token interno não registra capability', () => {
    expect(() => new NatPmpActivePortMapping({} as never)).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_REQUEST_INVALID' })
    )
  })

  it('SEC-117: UNSUPP_VERSION e code 1 em ambos PCP e NAT-PMP (RFC 6887 e RFC 6886)', () => {
    expect(NatPmpResultCode.UNSUPP_VERSION).toBe(1)
  })

  it('SEC-118: OP2 request bytes 2-3 Reserved=0', () => {
    expect(encodeNatPmpTcpMappingRequest({ internalPort: 80, requestedLifetimeSeconds: 100 }).readUInt16BE(2)).toBe(0)
  })
})

describe('PCP Unsupported Version downgrade packet', () => {
  it('aceita somente Version=0, OP=0, Result=1 e 8 bytes exatos', () => {
    expect(decodePcpUnsupportedVersionResponse(buildPcpUnsupportedVersionResponse(77))).toEqual({
      version: 0,
      opcode: 0,
      resultCode: 1,
      epochTime: 77
    })
    for (const invalid of [
      Buffer.alloc(7),
      Buffer.alloc(9),
      Buffer.from([0, 128, 0, 1, 0, 0, 0, 1]),
      Buffer.from([0, 0, 0, 2, 0, 0, 0, 1]),
      Buffer.from([2, 0, 0, 1, 0, 0, 0, 1])
    ]) {
      expect(() => decodePcpUnsupportedVersionResponse(invalid)).toThrow(PcpError)
    }
  })

  it('packet perfeito de outra origem/porta não provoca fallback', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    const spoof = createSocket('udp4')
    await new Promise<void>((resolve) => spoof.bind(0, '127.0.0.2', resolve))
    try {
      const fix = await createLocalServerFixture('masq-spoof-pcp-')
      const handle = await startTestServer(fix)
      let natPackets = 0
      fakeGw.setResponseHandler((request, peer) => {
        if (request.readUInt8(0) === 0) natPackets += 1
        else spoof.send(buildPcpUnsupportedVersionResponse(), peer.port, peer.address)
        return null
      })
      await expect(createPcpFirstPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        timeoutMs: 30,
        maxRetransmissions: 1
      })).rejects.toThrow(expect.objectContaining({ code: 'PCP_TIMEOUT' }))
      expect(natPackets).toBe(0)
    } finally {
      await new Promise<void>((resolve) => spoof.close(() => resolve()))
      await fakeGw.close()
    }
  }, 10000)

  it('downgrade curto com opcode incorreto vindo do gateway falha sem NAT-PMP', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    try {
      const fix = await createLocalServerFixture('masq-invalid-down-')
      const handle = await startTestServer(fix)
      let natPackets = 0
      fakeGw.setResponseHandler((request) => {
        if (request.readUInt8(0) === 0) natPackets += 1
        const invalid = buildPcpUnsupportedVersionResponse()
        invalid.writeUInt8(128, 1)
        return invalid
      })
      await expect(createPcpFirstPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        timeoutMs: 30,
        maxRetransmissions: 1
      })).rejects.toThrow(expect.objectContaining({ code: 'PCP_RESPONSE_INVALID' }))
      expect(natPackets).toBe(0)
    } finally {
      await fakeGw.close()
    }
  }, 10000)
})

describe('NAT-PMP parsers estritos, epoch e fuzz-like', () => {
  it('rejeita trailing bytes em OP0 e OP2 responses', () => {
    expect(() => decodeNatPmpExternalAddressResponse(Buffer.alloc(13))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
    expect(() => decodeNatPmpTcpMappingResponse(Buffer.alloc(17))).toThrow(
      expect.objectContaining({ code: 'NAT_PMP_RESPONSE_INVALID' })
    )
  })

  it.each([
    [1, 'NAT_PMP_UNSUPPORTED_VERSION'],
    [2, 'NAT_PMP_NOT_AUTHORIZED'],
    [3, 'NAT_PMP_NETWORK_FAILURE'],
    [4, 'NAT_PMP_OUT_OF_RESOURCES'],
    [5, 'NAT_PMP_UNSUPPORTED_OPCODE'],
    [99, 'NAT_PMP_UNKNOWN_RESULT_CODE']
  ] as const)('result code %i falha semanticamente como %s sem retry', (resultCode, code) => {
    expect(() => decodeNatPmpExternalAddressResponse(
      buildFakeOp0Response({ resultCode: resultCode as NatPmpResultCode })
    )).toThrow(expect.objectContaining({ code, resultCode }))
  })

  it('aplica a fórmula NAT-PMP 7/8 e a tolerância exata de +2 segundos', () => {
    const baseline = validateNatPmpEpochTransition(null, 1000, 10)
    expect(baseline.result).toBe('VALID')
    expect(validateNatPmpEpochTransition(baseline.nextState, 1085, 110).result).toBe('VALID')
    expect(validateNatPmpEpochTransition(baseline.nextState, 1084, 110).result).toBe('STATE_LOSS_SUSPECTED')
  })

  it('falha fechado se o relógio monotônico retrocede', () => {
    const baseline = validateNatPmpEpochTransition(null, 100, 20)
    expect(validateNatPmpEpochTransition(baseline.nextState, 101, 19).result).toBe('STATE_LOSS_SUSPECTED')
  })

  it('buffers truncados e pseudoaleatórios não criam respostas válidas nem causam crash', () => {
    let accepted = 0
    for (let length = 0; length < 64; length += 1) {
      const input = Buffer.alloc(length)
      for (let index = 0; index < length; index += 1) input[index] = (length * 31 + index * 17) & 0xff
      for (const parser of [decodeNatPmpExternalAddressResponse, decodeNatPmpTcpMappingResponse]) {
        try {
          parser(input)
          accepted += 1
        } catch (error) {
          expect(error).toBeInstanceOf(NatPmpError)
        }
      }
    }
    expect(accepted).toBe(0)
  })
})

describe('NAT-PMP response source e cross-transaction correlation', () => {
  it('ignora OP0 perfeito de outro peer LAN', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    const spoof = createSocket('udp4')
    await new Promise<void>((resolve) => spoof.bind(0, '127.0.0.2', resolve))
    try {
      const fix = await createLocalServerFixture('masq-spoof-op0-')
      const handle = await startTestServer(fix)
      fakeGw.setResponseHandler((_request, peer) => {
        spoof.send(buildFakeOp0Response({ externalAddress: '8.8.4.4' }), peer.port, peer.address)
        return null
      })
      await expect(createNatPmpPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        initialTimeoutMs: 30,
        maxRetransmissions: 1
      })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_TIMEOUT' }))
    } finally {
      await new Promise<void>((resolve) => spoof.close(() => resolve()))
      await fakeGw.close()
    }
  }, 10000)

  it('ignora OP130 enquanto aguarda OP0 e OP128 enquanto aguarda OP2', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    try {
      const fix = await createLocalServerFixture('masq-cross-op-')
      const handle = await startTestServer(fix)
      fakeGw.setResponseHandler((request) => request.readUInt8(1) === 0
        ? buildFakeOp2Response({ internalPort: handle.endpoint.port })
        : buildFakeOp0Response({ externalAddress: '8.8.4.4' }))
      await expect(createNatPmpPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        initialTimeoutMs: 30,
        maxRetransmissions: 1
      })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_TIMEOUT' }))
    } finally {
      await fakeGw.close()
    }
  }, 10000)

  it('ignora OP2 perfeito de outro peer LAN depois de OP0 legítimo', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    const spoof = createSocket('udp4')
    await new Promise<void>((resolve) => spoof.bind(0, '127.0.0.2', resolve))
    try {
      const fix = await createLocalServerFixture('masq-spoof-op2-')
      const handle = await startTestServer(fix)
      fakeGw.setResponseHandler((request, peer) => {
        if (request.readUInt8(1) === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        spoof.send(buildFakeOp2Response({ internalPort: handle.endpoint.port }), peer.port, peer.address)
        return null
      })
      await expect(createNatPmpPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        initialTimeoutMs: 30,
        maxRetransmissions: 1
      })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_TIMEOUT' }))
    } finally {
      await new Promise<void>((resolve) => spoof.close(() => resolve()))
      await fakeGw.close()
    }
  }, 10000)

  it('ignora OP2 com internal port diferente da transaction', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    try {
      const fix = await createLocalServerFixture('masq-wrong-port-')
      const handle = await startTestServer(fix)
      fakeGw.setResponseHandler((request) => request.readUInt8(1) === 0
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4' })
        : buildFakeOp2Response({ internalPort: handle.endpoint.port === 65535 ? 1 : handle.endpoint.port + 1 }))
      await expect(createNatPmpPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        initialTimeoutMs: 30,
        maxRetransmissions: 1
      })).rejects.toThrow(expect.objectContaining({ code: 'NAT_PMP_TIMEOUT' }))
    } finally {
      await fakeGw.close()
    }
  }, 10000)
})

describe('NAT-PMP lifecycle, renewal, recovery, delete e serialização', () => {
  let fakeGw: Awaited<ReturnType<typeof startFakeNatPmpServer>> | null = null

  beforeEach(async () => { fakeGw = await startFakeNatPmpServer('127.0.0.1') })
  afterEach(async () => { if (fakeGw) { await fakeGw.close(); fakeGw = null } })

  it('agenda renewal automaticamente aproximadamente em 50% da lifetime', async () => {
    const fix = await createLocalServerFixture('masq-half-life-')
    const handle = await startTestServer(fix)
    let mapRequests = 0
    fakeGw!.setResponseHandler((request) => {
      if (request.readUInt8(1) === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 10 })
      const deletion = request.readUInt32BE(8) === 0
      if (!deletion) mapRequests += 1
      return buildFakeOp2Response({
        internalPort: handle.endpoint.port,
        assignedExternalPort: deletion ? 0 : 50001,
        assignedLifetimeSeconds: deletion ? 0 : 2,
        epochTime: 10 + mapRequests
      })
    })
    const mapping = await createNatPmpPortMapping({
      listener: handle,
      requestedLifetimeSeconds: 2,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      maxRetransmissions: 1
    })
    await new Promise((resolve) => setTimeout(resolve, 1150))
    expect(mapRequests).toBeGreaterThanOrEqual(2)
    await mapping.close()
  }, 10000)

  it('renewal em half-life pode trocar a porta externa sem estender sem SUCCESS', async () => {
    const fix = await createLocalServerFixture('masq-renew01-')
    const handle = await startTestServer(fix)
    let monotonic = 0
    let mapRequests = 0
    fakeGw!.setResponseHandler((request) => {
      if (request.readUInt8(1) === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 100 })
      const lifetime = request.readUInt32BE(8)
      if (lifetime === 0) return buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 0, assignedLifetimeSeconds: 0, epochTime: 145 })
      mapRequests += 1
      return buildFakeOp2Response({
        internalPort: handle.endpoint.port,
        assignedExternalPort: mapRequests === 1 ? 50000 : 51000,
        assignedLifetimeSeconds: 100,
        epochTime: mapRequests === 1 ? 100 : 144
      })
    })
    const mapping = await createNatPmpPortMapping({
      listener: handle,
      requestedLifetimeSeconds: 100,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      maxRetransmissions: 1,
      monotonicClock: () => monotonic
    })
    monotonic = 50
    await mapping.executeRenewalForTesting()
    expect(mapping.getExternalEndpoint().port).toBe(51000)
    expect(mapping.isActive()).toBe(true)
    await mapping.close()
  }, 10000)

  it('epoch state loss reexecuta OP0 antes de recuperar endereço e mapping', async () => {
    const fix = await createLocalServerFixture('masq-recover01-')
    const handle = await startTestServer(fix)
    let monotonic = 0
    let stage = 0
    const observedOpcodes: number[] = []
    fakeGw!.setResponseHandler((request) => {
      const opcode = request.readUInt8(1)
      observedOpcodes.push(opcode)
      if (stage === 0 && opcode === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 100 })
      if (stage === 0) {
        stage = 1
        return buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 50000, assignedLifetimeSeconds: 200, epochTime: 100 })
      }
      if (stage === 1) {
        stage = 2
        return buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 50000, assignedLifetimeSeconds: 200, epochTime: 1 })
      }
      if (stage === 2 && opcode === 0) {
        stage = 3
        return buildFakeOp0Response({ externalAddress: '9.9.9.9', epochTime: 2 })
      }
      stage = 4
      return buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 52000, assignedLifetimeSeconds: 200, epochTime: 2 })
    })
    const mapping = await createNatPmpPortMapping({
      listener: handle,
      requestedLifetimeSeconds: 200,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      maxRetransmissions: 1,
      monotonicClock: () => monotonic
    })
    monotonic = 100
    await mapping.executeRenewalForTesting()
    expect(observedOpcodes.slice(2, 5)).toEqual([2, 0, 2])
    expect(mapping.getExternalEndpoint()).toEqual({ family: 4, address: '9.9.9.9', port: 52000 })
    expect(mapping.isActive()).toBe(true)
    await mapping.close()
  }, 10000)

  it('close é idempotente, invalida imediatamente e envia delete OP2/port0/lifetime0', async () => {
    const fix = await createLocalServerFixture('masq-delete01-')
    const handle = await startTestServer(fix)
    const requests: Buffer[] = []
    fakeGw!.setResponseHandler((request) => {
      requests.push(Buffer.from(request))
      if (request.readUInt8(1) === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 50 })
      const deletion = request.readUInt32BE(8) === 0
      return buildFakeOp2Response({
        internalPort: handle.endpoint.port,
        assignedExternalPort: deletion ? 0 : 53000,
        assignedLifetimeSeconds: deletion ? 0 : 300,
        epochTime: 50
      })
    })
    const mapping = await createNatPmpPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      maxRetransmissions: 1
    })
    await Promise.all([mapping.close(), mapping.close()])
    expect(mapping.isActive()).toBe(false)
    const deletes = requests.filter((request) => request.length === 12 && request.readUInt32BE(8) === 0)
    expect(deletes).toHaveLength(1)
    expect(deletes[0]!.readUInt16BE(6)).toBe(0)
  }, 10000)

  it('delete timeout permanece bounded e não reativa a capability', async () => {
    const fix = await createLocalServerFixture('masq-delete-timeout-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((request) => request.readUInt8(1) === 0
      ? buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 20 })
      : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: 53001, assignedLifetimeSeconds: 300, epochTime: 20 }))
    const mapping = await createNatPmpPortMapping({
      listener: handle,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      initialTimeoutMs: 20,
      maxRetransmissions: 1
    })
    fakeGw!.setResponseHandler(null)
    await mapping.close()
    expect(mapping.isActive()).toBe(false)
  }, 10000)

  it('serializa fluxos completos OP0→OP2 no mesmo gateway', async () => {
    const fixA = await createLocalServerFixture('masq-serial-a-')
    const fixB = await createLocalServerFixture('masq-serial-b-')
    const handleA = await startTestServer(fixA)
    const handleB = await startTestServer(fixB)
    const opcodes: number[] = []
    fakeGw!.setResponseHandler((request) => {
      const opcode = request.readUInt8(1)
      opcodes.push(opcode)
      if (opcode === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 100 })
      return buildFakeOp2Response({
        internalPort: request.readUInt16BE(4),
        assignedExternalPort: 54000 + opcodes.length,
        assignedLifetimeSeconds: 300,
        epochTime: 100
      })
    })
    const [mappingA, mappingB] = await Promise.all([
      createNatPmpPortMapping({ listener: handleA, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1 }),
      createNatPmpPortMapping({ listener: handleB, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1 })
    ])
    expect(opcodes.slice(0, 4)).toEqual([0, 2, 0, 2])
    await mappingA.close()
    await mappingB.close()
  }, 10000)

  it('expiry monotônico e listener close tornam a capability não anunciável', async () => {
    const fix = await createLocalServerFixture('masq-expire01-')
    const handle = await startTestServer(fix)
    let monotonic = 0
    fakeGw!.setResponseHandler((request) => request.readUInt8(1) === 0
      ? buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 1 })
      : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: request.readUInt32BE(8) === 0 ? 0 : 55000, assignedLifetimeSeconds: request.readUInt32BE(8) === 0 ? 0 : 1, epochTime: 1 }))
    const mapping = await createNatPmpPortMapping({
      listener: handle,
      requestedLifetimeSeconds: 1,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: fakeGw!.port,
      maxRetransmissions: 1,
      monotonicClock: () => monotonic
    })
    monotonic = 1
    expect(mapping.isActive()).toBe(false)
    await handle.close()
    expect(mapping.isActive()).toBe(false)
  }, 10000)

  it('capability NAT-PMP concreta usa a implementação separada de PCP', async () => {
    const fix = await createLocalServerFixture('masq-type01-')
    const handle = await startTestServer(fix)
    fakeGw!.setResponseHandler((request) => request.readUInt8(1) === 0
      ? buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 1 })
      : buildFakeOp2Response({ internalPort: handle.endpoint.port, assignedExternalPort: request.readUInt32BE(8) === 0 ? 0 : 55000, assignedLifetimeSeconds: request.readUInt32BE(8) === 0 ? 0 : 300, epochTime: 1 }))
    const mapping = await createNatPmpPortMapping({ listener: handle, customGatewayAddress: '127.0.0.1', customGatewayPort: fakeGw!.port, maxRetransmissions: 1 })
    expect(mapping).toBeInstanceOf(NatPmpActivePortMapping)
    await mapping.close()
  }, 10000)
})

describe('ActivePortMapping protocol-agnostic e lease clamp', () => {
  it('PCP e NAT-PMP com o mesmo endpoint produzem o mesmo candidate wire sem metadata do roteador', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    try {
      const fix = await createLocalServerFixture('masq-agnostic-')
      const handle = await startTestServer(fix)
      fakeGw.setResponseHandler((request) => {
        if (request.readUInt8(0) === 2) return buildPcpMapResponse(request)
        if (request.readUInt8(1) === 0) return buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 5000 })
        const deletion = request.readUInt32BE(8) === 0
        return buildFakeOp2Response({
          internalPort: handle.endpoint.port,
          assignedExternalPort: deletion ? 0 : 55001,
          assignedLifetimeSeconds: deletion ? 0 : 3600,
          epochTime: 5000
        })
      })
      const pcp = await createPcpPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        timeoutMs: 30,
        maxRetransmissions: 1
      })
      const natPmp = await createNatPmpPortMapping({
        listener: handle,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        initialTimeoutMs: 30,
        maxRetransmissions: 1
      })
      const issueTime = Math.floor(Date.now() / 1000)
      const descriptorId = Buffer.alloc(32, 7)
      const create = (mapping: typeof pcp | typeof natPmp): Buffer => createSignedConnectivityDescriptor({
        serverId: fix.serverId,
        serverPublicKey: fix.publicKey,
        serverPrivateKey: fix.privateKey,
        candidates: [mapping],
        customIssuedAt: issueTime,
        customDescriptorId: descriptorId,
        lifetimeSeconds: 60
      })
      const pcpWire = create(pcp)
      const natWire = create(natPmp)
      expect(pcpWire.equals(natWire)).toBe(true)
      for (const forbidden of ['NAT-PMP', 'PCP', '127.0.0.1', '5000']) {
        expect(natWire.includes(Buffer.from(forbidden))).toBe(false)
      }
      await pcp.close()
      await natPmp.close()
    } finally {
      await fakeGw.close()
    }
  }, 10000)

  it('descriptor expiresAt nunca excede a lease NAT-PMP', async () => {
    const fakeGw = await startFakeNatPmpServer('127.0.0.1')
    try {
      const fix = await createLocalServerFixture('masq-clamp-')
      const handle = await startTestServer(fix)
      fakeGw.setResponseHandler((request) => request.readUInt8(1) === 0
        ? buildFakeOp0Response({ externalAddress: '8.8.4.4', epochTime: 10 })
        : buildFakeOp2Response({
            internalPort: handle.endpoint.port,
            assignedExternalPort: request.readUInt32BE(8) === 0 ? 0 : 55002,
            assignedLifetimeSeconds: request.readUInt32BE(8) === 0 ? 0 : 30,
            epochTime: 10
          }))
      const mapping = await createNatPmpPortMapping({
        listener: handle,
        requestedLifetimeSeconds: 30,
        customGatewayAddress: '127.0.0.1',
        customGatewayPort: fakeGw.port,
        maxRetransmissions: 1
      })
      const issuedAt = Math.floor(Date.now() / 1000)
      const descriptor = verifySignedConnectivityDescriptor({
        encodedDescriptor: createSignedConnectivityDescriptor({
          serverId: fix.serverId,
          serverPublicKey: fix.publicKey,
          serverPrivateKey: fix.privateKey,
          candidates: [mapping],
          customIssuedAt: issuedAt,
          lifetimeSeconds: 300
        })
      })
      expect(descriptor.expiresAt).toBeLessThanOrEqual(mapping.getExpiresAt())
      expect(descriptor.expiresAt - descriptor.issuedAt).toBeLessThanOrEqual(30)
      await mapping.close()
    } finally {
      await fakeGw.close()
    }
  }, 10000)
})
