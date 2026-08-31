import { afterEach, describe, expect, it } from 'vitest'
import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { createSocket, type Socket as DgramSocket } from 'node:dgram'
import { mkdtemp, readdir, rm } from 'node:fs/promises'
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createAuthenticatedCandidateDevice } from '../security/authenticated-candidate'
import { createLocalServerStorage } from '../servers/local-server-storage'
import { isLegitimateActivePortMapping } from './active-port-mapping'
import {
  createSignedConnectivityDescriptor,
  ConnectivityCandidateType,
  verifySignedConnectivityDescriptor
} from './connectivity-descriptor'
import { startLanTcpServer, type LanTcpServerHandle } from './lan-transport'
import { createNatPmpPortMapping } from './nat-pmp-client'
import { createPcpPortMapping } from './pcp-client'
import {
  createUpnpPortMapping,
  UpnpActivePortMapping,
  UPNP_MAX_EXTERNAL_PORT_ATTEMPTS
} from './upnp-client'
import {
  encodeAddPortMapping,
  encodeDeletePortMapping,
  encodeGetExternalIpAddress,
  encodeGetSpecificPortMappingEntry,
  encodeSsdpMSearch,
  MAX_SSDP_DATAGRAM_BYTES,
  MAX_UPNP_DEVICE_DESCRIPTION_BYTES,
  MAX_UPNP_XML_ATTRIBUTES_PER_ELEMENT,
  MAX_UPNP_XML_ELEMENTS,
  MAX_UPNP_XML_TEXT_BYTES,
  parseGetExternalIpAddressResponse,
  parseGetSpecificPortMappingEntryResponse,
  parseSsdpResponse,
  parseUpnpDeviceDescription,
  SSDP_IPV4_MULTICAST_ADDRESS,
  SSDP_PORT,
  SSDP_TTL,
  UPNP_IGD_V1_SEARCH_TARGET,
  UPNP_WAN_IP_CONNECTION_V1,
  UPNP_WAN_PPP_CONNECTION_V1,
  UpnpError,
  validateUpnpGatewayUrl
} from './upnp-protocol'
import { discoverUpnpLocation, getUpnpDeviceDescription } from './upnp-transport'

const roots: string[] = []
const listeners: LanTcpServerHandle[] = []
const udpServers: DgramSocket[] = []
const httpServers: HttpServer[] = []

afterEach(async () => {
  await Promise.all(listeners.splice(0).map((listener) => listener.close()))
  await Promise.all(udpServers.splice(0).map((socket) => new Promise<void>((resolve) => socket.close(() => resolve()))))
  await Promise.all(httpServers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function fakeSecureStorage() {
  const values = new Map<string, string>()
  let counter = 0
  let lastKey: KeyObject | undefined
  return {
    storage: {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => 'gnome_libsecret' as const,
      encryptString: (plaintext: string) => {
        const token = `upnp:${++counter}`
        values.set(token, plaintext)
        try { lastKey = createPrivateKey({ key: Buffer.from(plaintext, 'base64'), format: 'der', type: 'pkcs8' }) } catch { lastKey = undefined }
        return Buffer.from(token)
      },
      decryptString: (encrypted: Buffer) => {
        const value = values.get(encrypted.toString())
        if (!value) throw new Error('ciphertext invalid')
        return value
      }
    },
    get key(): KeyObject | undefined { return lastKey }
  }
}

async function createFixture() {
  const root = await mkdtemp(join(tmpdir(), 'masq-upnp-'))
  roots.push(root)
  const secure = fakeSecureStorage()
  const ownerPair = generateKeyPairSync('ed25519')
  const ownerKey = Buffer.from(ownerPair.publicKey.export({ format: 'der', type: 'spki' }))
  const owner = createAuthenticatedCandidateDevice(`sha256:${createHash('sha256').update(ownerKey).digest('hex')}`, ownerKey)
  let id = 1
  const storage = createLocalServerStorage(root, secure.storage, owner, {
    platform: 'win32',
    generateStorageId: () => (id++).toString(16).padStart(32, '0')
  })
  const server = await storage.createLocalServer('UPnP Test')
  if (!secure.key) throw new Error('missing server key')
  const listener = await startLanTcpServer({
    bindAddress: '127.0.0.1',
    port: 0,
    storage,
    localStorageId: server.localStorageId,
    serverId: server.serverId,
    serverPublicKey: server.identity.publicKey,
    serverPrivateKey: secure.key
  })
  listeners.push(listener)
  return { root, storage, server, listener, privateKey: secure.key }
}

function igdDescription(options: {
  serviceType?: string
  controlUrl?: string
  urlBase?: string
  duplicateIpService?: boolean
  serviceOutsideHierarchy?: boolean
} = {}): string {
  const type = options.serviceType ?? UPNP_WAN_IP_CONNECTION_V1
  const service = `<service><serviceType>${type}</serviceType><serviceId>urn:upnp-org:serviceId:WAN</serviceId><SCPDURL>/ignored.xml</SCPDURL><controlURL>${options.controlUrl ?? '/control'}</controlURL><eventSubURL>/events</eventSubURL></service>`
  const duplicate = options.duplicateIpService ? service : ''
  const nested = `<device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList>${service}${duplicate}</serviceList></device></deviceList></device>`
  const outside = options.serviceOutsideHierarchy ? `<serviceList>${service}</serviceList>` : ''
  return `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">${options.urlBase ? `<URLBase>${options.urlBase}</URLBase>` : ''}<device><deviceType>${UPNP_IGD_V1_SEARCH_TARGET}</deviceType>${outside}<deviceList>${options.serviceOutsideHierarchy ? '' : nested}</deviceList></device></root>`
}

function soapResponse(action: string, fields = ''): string {
  return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:${action}Response xmlns:u="${UPNP_WAN_IP_CONNECTION_V1}">${fields}</u:${action}Response></s:Body></s:Envelope>`
}

function soapFault(code: number): string {
  return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>${code}</errorCode><errorDescription>redacted</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`
}

async function startHttp(handler: (request: IncomingMessage, response: ServerResponse, body: Buffer) => void) {
  const server = createServer((request, response) => {
    const chunks: Buffer[] = []
    request.on('data', (chunk: Buffer) => chunks.push(chunk))
    request.on('end', () => handler(request, response, Buffer.concat(chunks)))
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve() })
  })
  httpServers.push(server)
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('http address')
  return { server, port: address.port }
}

async function startSsdp(location: string, responder?: (request: Buffer) => Buffer | null) {
  const socket = createSocket('udp4')
  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, '127.0.0.1', () => { socket.off('error', reject); resolve() })
  })
  udpServers.push(socket)
  const address = socket.address()
  socket.on('message', (request, remote) => {
    const custom = responder?.(request)
    const response = custom === undefined
      ? Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: ${location}\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`)
      : custom
    if (response) socket.send(response, remote.port, remote.address)
  })
  return { socket, port: address.port }
}

async function startPcpAndNatPmpGateway(externalPort: number) {
  const socket = createSocket('udp4')
  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, '127.0.0.1', () => { socket.off('error', reject); resolve() })
  })
  udpServers.push(socket)
  socket.on('message', (request, remote) => {
    let response: Buffer
    if (request[0] === 2) {
      response = Buffer.alloc(60)
      response[0] = 2
      response[1] = 0x81
      response.writeUInt32BE(request.readUInt32BE(4) === 0 ? 0 : 300, 4)
      response.writeUInt32BE(1000, 8)
      request.subarray(24, 36).copy(response, 24)
      response[36] = 6
      response.writeUInt16BE(request.readUInt16BE(40), 40)
      response.writeUInt16BE(externalPort, 42)
      response.writeUInt16BE(0xffff, 54)
      response.set([8, 8, 4, 4], 56)
    } else if (request[1] === 0) {
      response = Buffer.alloc(12)
      response[1] = 0x80
      response.writeUInt32BE(1000, 4)
      response.set([8, 8, 4, 4], 8)
    } else {
      response = Buffer.alloc(16)
      response[1] = 0x82
      response.writeUInt32BE(1000, 4)
      response.writeUInt16BE(request.readUInt16BE(4), 8)
      response.writeUInt16BE(request.readUInt32BE(8) === 0 ? 0 : externalPort, 10)
      response.writeUInt32BE(request.readUInt32BE(8) === 0 ? 0 : 300, 12)
    }
    socket.send(response, remote.port, remote.address)
  })
  return { port: socket.address().port }
}

interface FakeIgdState {
  externalIp: string
  internalClient: string
  internalPort: number
  lease: number
  enabled: string
  addFaults: number[]
  specificMismatchClient?: string
  redirectDescription?: boolean
  redirectLocation?: string
  contentEncoding?: string
  oversizedDescription?: boolean
  specificFaults?: number[]
  deleteFault?: number
  hangDelete?: boolean
  addHttp500Success?: boolean
  addDelayMs?: number
  hangDescription?: boolean
  requests: Array<{
    method?: string
    url?: string
    soapAction?: string
    host?: string
    contentType?: string
    acceptEncoding?: string
    body: string
  }>
}

async function startFakeIgd(state: FakeIgdState) {
  return startHttp((request, response, body) => {
    const soapActionHeader = request.headers.soapaction
    state.requests.push({
      method: request.method,
      url: request.url,
      soapAction: Array.isArray(soapActionHeader) ? soapActionHeader[0] : soapActionHeader,
      host: request.headers.host,
      contentType: request.headers['content-type'],
      acceptEncoding: request.headers['accept-encoding'],
      body: body.toString()
    })
    if (request.method === 'GET') {
      if (state.hangDescription) return
      if (state.redirectDescription) {
        response.writeHead(307, { Location: state.redirectLocation ?? '/other' }).end()
        return
      }
      const description = state.oversizedDescription
        ? 'x'.repeat(MAX_UPNP_DEVICE_DESCRIPTION_BYTES + 1)
        : igdDescription()
      response.writeHead(200, state.contentEncoding ? { 'Content-Encoding': state.contentEncoding } : {})
      response.end(description)
      return
    }
    const action = String(request.headers.soapaction ?? '')
    response.setHeader('Content-Type', 'text/xml')
    if (action.includes('#GetExternalIPAddress')) {
      response.end(soapResponse('GetExternalIPAddress', `<NewExternalIPAddress>${state.externalIp}</NewExternalIPAddress>`))
    } else if (action.includes('#AddPortMapping')) {
      const fault = state.addFaults.shift()
      if (fault !== undefined) response.writeHead(500).end(soapFault(fault))
      else if (state.addHttp500Success) response.writeHead(500).end(soapResponse('AddPortMapping'))
      else if (state.addDelayMs !== undefined) setTimeout(() => response.end(soapResponse('AddPortMapping')), state.addDelayMs)
      else response.end(soapResponse('AddPortMapping'))
    } else if (action.includes('#GetSpecificPortMappingEntry')) {
      const fault = state.specificFaults?.shift()
      if (fault !== undefined) response.writeHead(500).end(soapFault(fault))
      else response.end(soapResponse('GetSpecificPortMappingEntry', `<NewInternalPort>${state.internalPort}</NewInternalPort><NewInternalClient>${state.specificMismatchClient ?? state.internalClient}</NewInternalClient><NewEnabled>${state.enabled}</NewEnabled><NewPortMappingDescription>Masquerada</NewPortMappingDescription><NewLeaseDuration>${state.lease}</NewLeaseDuration>`))
    } else if (action.includes('#DeletePortMapping')) {
      if (state.hangDelete) return
      if (state.deleteFault !== undefined) response.writeHead(500).end(soapFault(state.deleteFault))
      else response.end(soapResponse('DeletePortMapping'))
    } else {
      response.writeHead(500).end(soapFault(401))
    }
  })
}

async function prepareIntegratedMapping(
  overrides: Partial<FakeIgdState> = {},
  createOptions: {
    readonly monotonicClock?: () => number
    readonly httpTimeoutMs?: number
    readonly randomExternalPort?: () => number
  } = {}
) {
  const fixture = await createFixture()
  const state: FakeIgdState = {
    externalIp: '8.8.4.4',
    internalClient: fixture.listener.endpoint.address,
    internalPort: fixture.listener.endpoint.port,
    lease: 300,
    enabled: '1',
    addFaults: [],
    requests: [],
    ...overrides
  }
  const http = await startFakeIgd(state)
  const ssdp = await startSsdp(`http://127.0.0.1:${http.port}/root.xml`)
  const create = () => createUpnpPortMapping({
      listener: fixture.listener,
      requestedLifetimeSeconds: 300,
      gatewayProvider: { resolveGatewayForLocalAddress: async () => '127.0.0.1' },
      testOnlyAllowLoopback: true,
      testOnlySsdpDestinationAddress: '127.0.0.1',
      testOnlySsdpDestinationPort: ssdp.port,
      testOnlySsdpTimeoutMs: 100,
      httpTimeoutMs: createOptions.httpTimeoutMs ?? 100,
      monotonicClock: createOptions.monotonicClock,
      randomExternalPort: createOptions.randomExternalPort
    })
  return { fixture, state, http, ssdp, create }
}

async function createIntegratedMapping(
  overrides: Partial<FakeIgdState> = {},
  createOptions: Parameters<typeof prepareIntegratedMapping>[1] = {}
) {
  const prepared = await prepareIntegratedMapping(overrides, createOptions)
  const mapping = await prepared.create()
  return { ...prepared, mapping }
}

describe('UPnP SSDP e URL security', () => {
  it('M-SEARCH é byte-exact, MX=1, TTL policy=2', () => {
    expect(encodeSsdpMSearch().toString('ascii')).toBe(
      `M-SEARCH * HTTP/1.1\r\nHOST: ${SSDP_IPV4_MULTICAST_ADDRESS}:${SSDP_PORT}\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`
    )
    expect(SSDP_TTL).toBe(2)
  })

  it('parser SSDP aceita headers case-insensitive e extrai LOCATION/ST', () => {
    expect(parseSsdpResponse(Buffer.from(`HTTP/1.1 200 OK\r\nlocation: http://192.168.1.1/root.xml\r\nst: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`))).toEqual({
      location: 'http://192.168.1.1/root.xml', searchTarget: UPNP_IGD_V1_SEARCH_TARGET
    })
  })

  it.each([
    Buffer.alloc(0),
    Buffer.from('HTTP/1.1 200 OK\r\n'),
    Buffer.from('HTTP/1.1 404 Nope\r\n\r\n'),
    Buffer.from('HTTP/1.1 200 OK\nLOCATION: x\n\n'),
    Buffer.from(`HTTP/1.1 200 OK\r\nBadHeader\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\n LOCATION: x\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: x\u0000y\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from('HTTP/1.1 200 OK\r\nLOCATION: x\r\n\r\n'),
    Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: a\r\nLOCATION: b\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: a\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: a\r\nST: ssdp:all\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: ${'x'.repeat(1025)}\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`),
    Buffer.from(`HTTP/1.1 200 OK\r\n${Array.from({ length: 33 }, (_, index) => `X-${index}: y`).join('\r\n')}\r\n\r\n`),
    Buffer.alloc(MAX_SSDP_DATAGRAM_BYTES + 1)
  ])('SSDP malformed/oversized é rejeitado', (input) => {
    expect(() => parseSsdpResponse(input)).toThrow(expect.objectContaining({ code: 'UPNP_SSDP_RESPONSE_INVALID' }))
  })

  it('SSDP válido de source port diferente é ignorado até timeout', async () => {
    const destination = await startSsdp('http://127.0.0.1:1234/root.xml', () => null)
    const spoof = createSocket('udp4')
    udpServers.push(spoof)
    await new Promise<void>((resolve) => spoof.bind(0, '127.0.0.1', resolve))
    destination.socket.once('message', (_request, remote) => {
      spoof.send(Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1234/root.xml\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`), remote.port, remote.address)
    })
    await expect(discoverUpnpLocation({
      localAddress: '127.0.0.1', gatewayAddress: '127.0.0.1', destinationAddress: '127.0.0.1', destinationPort: destination.port, timeoutMs: 30
    })).rejects.toThrow(expect.objectContaining({ code: 'UPNP_SSDP_TIMEOUT' }))
  })

  it('SSDP válido de outro IP é ignorado até timeout', async () => {
    const destination = await startSsdp('http://127.0.0.1:1234/root.xml', () => null)
    const spoof = createSocket('udp4')
    udpServers.push(spoof)
    await new Promise<void>((resolve, reject) => {
      spoof.once('error', reject)
      spoof.bind(destination.port, '127.0.0.2', () => { spoof.off('error', reject); resolve() })
    })
    destination.socket.once('message', (_request, remote) => {
      spoof.send(Buffer.from(`HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1234/root.xml\r\nST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`), remote.port, remote.address)
    })
    await expect(discoverUpnpLocation({
      localAddress: '127.0.0.1', gatewayAddress: '127.0.0.1', destinationAddress: '127.0.0.1', destinationPort: destination.port, timeoutMs: 30
    })).rejects.toThrow(expect.objectContaining({ code: 'UPNP_SSDP_TIMEOUT' }))
  })

  it('LOCATION válido aceita porta arbitrária e gateway literal', () => {
    expect(validateUpnpGatewayUrl('http://192.168.1.1:54321/root.xml', '192.168.1.1').port).toBe('54321')
  })

  it.each([
    'http://router.local/root.xml',
    'https://192.168.1.1/root.xml',
    'file:///etc/passwd',
    'ftp://192.168.1.1/a',
    'data:text/plain,x',
    'gopher://192.168.1.1/a',
    'javascript:alert(1)',
    'http://192.168.1.1/a\r\nInjected: x',
    'http://user:pass@192.168.1.1/a',
    'http://192.168.1.1/a#fragment',
    'http://192.168.1.99/a'
  ])('LOCATION SSRF rejeita %s', (url) => {
    expect(() => validateUpnpGatewayUrl(url, '192.168.1.1')).toThrow(UpnpError)
  })
})

describe('UPnP XML hardened e hierarquia IGD', () => {
  const location = new URL('http://192.168.1.1:1234/root.xml')

  it('extrai WANIPConnection:1 relativo', () => {
    const service = parseUpnpDeviceDescription(igdDescription(), location, '192.168.1.1')
    expect(service.serviceType).toBe(UPNP_WAN_IP_CONNECTION_V1)
    expect(service.controlUrl.href).toBe('http://192.168.1.1:1234/control')
  })

  it('aceita WANPPPConnection:1 quando não existe WANIP', () => {
    expect(parseUpnpDeviceDescription(igdDescription({ serviceType: UPNP_WAN_PPP_CONNECTION_V1 }), location, '192.168.1.1').serviceType).toBe(UPNP_WAN_PPP_CONNECTION_V1)
  })

  it('serviço fora da hierarquia é rejeitado', () => {
    expect(() => parseUpnpDeviceDescription(igdDescription({ serviceOutsideHierarchy: true }), location, '192.168.1.1')).toThrow(
      expect.objectContaining({ code: 'UPNP_IGD_SERVICE_NOT_FOUND' })
    )
  })

  it('múltiplos WANIP falham fechados', () => {
    expect(() => parseUpnpDeviceDescription(igdDescription({ duplicateIpService: true }), location, '192.168.1.1')).toThrow(
      expect.objectContaining({ code: 'UPNP_AMBIGUOUS_WAN_SERVICE' })
    )
  })

  it.each([
    igdDescription({ controlUrl: 'http://192.168.1.99/control' }),
    igdDescription({ urlBase: 'http://192.168.1.99/base/' }),
    igdDescription({ controlUrl: 'https://192.168.1.1/control' })
  ])('controlURL/URLBase SSRF é rejeitado', (xml) => {
    expect(() => parseUpnpDeviceDescription(xml, location, '192.168.1.1')).toThrow(UpnpError)
  })

  it.each([
    '<!DOCTYPE root><root/>',
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<!DOCTYPE root PUBLIC "x" "http://evil/"><root/>',
    '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>'
  ])('DOCTYPE/ENTITY/SYSTEM/PUBLIC/XInclude é rejeitado antes do parser', (xml) => {
    expect(() => parseUpnpDeviceDescription(xml, location, '192.168.1.1')).toThrow(
      expect.objectContaining({ code: 'UPNP_XML_UNSAFE' })
    )
  })

  it('nesting profundo e body excessivo são bounded', () => {
    const deep = `${'<x>'.repeat(40)}${'</x>'.repeat(40)}`
    expect(() => parseUpnpDeviceDescription(deep, location, '192.168.1.1')).toThrow(UpnpError)
    expect(() => parseUpnpDeviceDescription('x'.repeat(MAX_UPNP_DEVICE_DESCRIPTION_BYTES + 1), location, '192.168.1.1')).toThrow(
      expect.objectContaining({ code: 'UPNP_XML_LIMIT_EXCEEDED' })
    )
  })

  it('limites de texto, elementos, atributos e UTF-8 inválido são fail-closed', () => {
    const hugeText = igdDescription().replace(
      '<device><deviceType>',
      `<device><friendlyName>${'x'.repeat(MAX_UPNP_XML_TEXT_BYTES + 1)}</friendlyName><deviceType>`
    )
    const excessiveElements = igdDescription().replace(
      '<device><deviceType>',
      `<device>${'<x/>'.repeat(MAX_UPNP_XML_ELEMENTS + 1)}<deviceType>`
    )
    const attributes = Array.from(
      { length: MAX_UPNP_XML_ATTRIBUTES_PER_ELEMENT + 1 },
      (_, index) => ` a${index}="x"`
    ).join('')
    const excessiveAttributes = igdDescription().replace('<root ', `<root${attributes} `)
    for (const xml of [hugeText, excessiveElements, excessiveAttributes]) {
      expect(() => parseUpnpDeviceDescription(xml, location, '192.168.1.1')).toThrow(
        expect.objectContaining({ code: 'UPNP_XML_LIMIT_EXCEEDED' })
      )
    }
    expect(() => parseUpnpDeviceDescription(Buffer.from([0xc3, 0x28]), location, '192.168.1.1')).toThrow(
      expect.objectContaining({ code: 'UPNP_XML_INVALID' })
    )
  })

  it('resolve URLBase válido e controlURL absoluto no mesmo gateway', () => {
    const relative = parseUpnpDeviceDescription(
      igdDescription({ urlBase: 'http://192.168.1.1:4321/base/', controlUrl: 'control' }),
      location,
      '192.168.1.1'
    )
    expect(relative.controlUrl.href).toBe('http://192.168.1.1:4321/base/control')
    const absolute = parseUpnpDeviceDescription(
      igdDescription({ controlUrl: 'http://192.168.1.1:9876/control?x=1' }),
      location,
      '192.168.1.1'
    )
    expect(absolute.controlUrl.href).toBe('http://192.168.1.1:9876/control?x=1')
  })

  it('rejeita IGD v2 e prefere exatamente um WANIP sobre WANPPP', () => {
    expect(() => parseUpnpDeviceDescription(
      igdDescription({ serviceType: 'urn:schemas-upnp-org:service:WANIPConnection:2' }),
      location,
      '192.168.1.1'
    )).toThrow(expect.objectContaining({ code: 'UPNP_IGD_SERVICE_NOT_FOUND' }))
    const ppp = igdDescription({ serviceType: UPNP_WAN_PPP_CONNECTION_V1 })
      .match(/<service>.*<\/service>/)?.[0]
    if (!ppp) throw new Error('fixture PPP inválida')
    const both = igdDescription().replace('</serviceList>', `${ppp}</serviceList>`)
    expect(parseUpnpDeviceDescription(both, location, '192.168.1.1').serviceType).toBe(UPNP_WAN_IP_CONNECTION_V1)
  })
})

describe('UPnP SOAP allowlist e parsing', () => {
  it('GetExternalIPAddress possui action e envelope mínimos', () => {
    const body = encodeGetExternalIpAddress(UPNP_WAN_IP_CONNECTION_V1).toString()
    expect(body).toContain('<u:GetExternalIPAddress')
    expect(body).not.toContain('InternalClient')
  })

  it('AddPortMapping deriva todos os argumentos do mapping TCP finito', () => {
    const body = encodeAddPortMapping({ serviceType: UPNP_WAN_IP_CONNECTION_V1, externalPort: 50000, internalPort: 45000, internalClient: '192.168.1.20', leaseDurationSeconds: 3600 }).toString()
    for (const expected of ['<NewRemoteHost></NewRemoteHost>', '<NewExternalPort>50000</NewExternalPort>', '<NewProtocol>TCP</NewProtocol>', '<NewInternalPort>45000</NewInternalPort>', '<NewInternalClient>192.168.1.20</NewInternalClient>', '<NewEnabled>1</NewEnabled>', '<NewPortMappingDescription>Masquerada</NewPortMappingDescription>', '<NewLeaseDuration>3600</NewLeaseDuration>']) {
      expect(body).toContain(expected)
    }
  })

  it('GetSpecific e Delete só contêm remoteHost/port/TCP', () => {
    expect(encodeGetSpecificPortMappingEntry(UPNP_WAN_IP_CONNECTION_V1, 50000).toString()).toContain('<NewProtocol>TCP</NewProtocol>')
    expect(encodeDeletePortMapping(UPNP_WAN_IP_CONNECTION_V1, 50000).toString()).toContain('<NewExternalPort>50000</NewExternalPort>')
  })

  it('parsers SOAP extraem external IP e mapping específica', () => {
    expect(parseGetExternalIpAddressResponse(soapResponse('GetExternalIPAddress', '<NewExternalIPAddress>8.8.4.4</NewExternalIPAddress>'))).toBe('8.8.4.4')
    expect(parseGetSpecificPortMappingEntryResponse(soapResponse('GetSpecificPortMappingEntry', '<NewInternalPort>45000</NewInternalPort><NewInternalClient>192.168.1.20</NewInternalClient><NewEnabled>1</NewEnabled><NewLeaseDuration>3600</NewLeaseDuration>'))).toEqual({ internalClient: '192.168.1.20', internalPort: 45000, enabled: true, leaseDurationSeconds: 3600 })
  })

  it('SOAP exige Envelope/Body e service type runtime allowlisted', () => {
    const responseInHeader = `<?xml version="1.0"?><Envelope><Header><GetExternalIPAddressResponse><NewExternalIPAddress>8.8.8.8</NewExternalIPAddress></GetExternalIPAddressResponse></Header><Body/></Envelope>`
    expect(() => parseGetExternalIpAddressResponse(responseInHeader)).toThrow(
      expect.objectContaining({ code: 'UPNP_XML_INVALID' })
    )
    expect(() => encodeGetExternalIpAddress('urn:vendor:service:Injected\r\nX: y' as never)).toThrow(
      expect.objectContaining({ code: 'UPNP_REQUEST_INVALID' })
    )
    expect(() => encodeAddPortMapping({
      serviceType: UPNP_WAN_IP_CONNECTION_V1,
      externalPort: 50000,
      internalPort: 45000,
      internalClient: 'not-an-ip',
      leaseDurationSeconds: 3600
    })).toThrow(expect.objectContaining({ code: 'UPNP_REQUEST_INVALID' }))
  })
})

describe('UPnP HTTP hardening', () => {
  it.each([
    [{ redirectDescription: true, redirectLocation: '/same-host' }, 'UPNP_HTTP_REDIRECT_PROHIBITED'],
    [{ redirectDescription: true, redirectLocation: 'http://127.0.0.2/cross-host' }, 'UPNP_HTTP_REDIRECT_PROHIBITED'],
    [{ contentEncoding: 'gzip' }, 'UPNP_HTTP_RESPONSE_INVALID'],
    [{ contentEncoding: 'br' }, 'UPNP_HTTP_RESPONSE_INVALID'],
    [{ oversizedDescription: true }, 'UPNP_HTTP_RESPONSE_TOO_LARGE']
  ] as const)('description rejeita redirect/compression/body limit', async (state, code) => {
    const http = await startFakeIgd({ externalIp: '8.8.4.4', internalClient: '127.0.0.1', internalPort: 1, lease: 300, enabled: '1', addFaults: [], requests: [], ...state })
    await expect(getUpnpDeviceDescription(new URL(`http://127.0.0.1:${http.port}/root.xml`), '127.0.0.1', '127.0.0.1', 100)).rejects.toThrow(
      expect.objectContaining({ code })
    )
  })

  it('description timeout é curto, bounded e retorna código seguro', async () => {
    const http = await startFakeIgd({
      externalIp: '8.8.4.4', internalClient: '127.0.0.1', internalPort: 1,
      lease: 300, enabled: '1', addFaults: [], requests: [], hangDescription: true
    })
    const startedAt = Date.now()
    await expect(getUpnpDeviceDescription(
      new URL(`http://127.0.0.1:${http.port}/root.xml`), '127.0.0.1', '127.0.0.1', 30
    )).rejects.toThrow(expect.objectContaining({ code: 'UPNP_HTTP_TIMEOUT' }))
    expect(Date.now() - startedAt).toBeLessThan(500)
  })
})

describe('UPnP create, verification, lifecycle e descriptor', () => {
  it('rejeita listener forjado e production loopback antes de SSDP', async () => {
    await expect(createUpnpPortMapping({ listener: {} as LanTcpServerHandle })).rejects.toThrow(
      expect.objectContaining({ code: 'UPNP_LISTENER_INVALID' })
    )
    const fixture = await createFixture()
    await expect(createUpnpPortMapping({ listener: fixture.listener })).rejects.toThrow(
      expect.objectContaining({ code: 'UPNP_REQUEST_INVALID' })
    )
  })

  it('fluxo local completo só cria capability após GetSpecific e produz PORT_MAPPED_TCP', async () => {
    const { fixture, state, mapping } = await createIntegratedMapping()
    expect(isLegitimateActivePortMapping(mapping)).toBe(true)
    expect(mapping.isActive()).toBe(true)
    expect(state.requests.map((request) => request.soapAction).filter(Boolean)).toEqual([
      `"${UPNP_WAN_IP_CONNECTION_V1}#GetExternalIPAddress"`,
      `"${UPNP_WAN_IP_CONNECTION_V1}#AddPortMapping"`,
      `"${UPNP_WAN_IP_CONNECTION_V1}#GetSpecificPortMappingEntry"`
    ])
    const getDescription = state.requests[0]!
    expect(getDescription.method).toBe('GET')
    expect(getDescription.url).toBe('/root.xml')
    expect(getDescription.acceptEncoding).toBe('identity')
    const getExternal = state.requests[1]!
    expect(getExternal.method).toBe('POST')
    expect(getExternal.url).toBe('/control')
    expect(getExternal.host).toMatch(/^127\.0\.0\.1:\d+$/)
    expect(getExternal.contentType).toBe('text/xml; charset="utf-8"')
    expect(getExternal.acceptEncoding).toBe('identity')
    const verified = verifySignedConnectivityDescriptor({
      encodedDescriptor: createSignedConnectivityDescriptor({
        serverId: fixture.server.serverId,
        serverPublicKey: fixture.server.identity.publicKey,
        serverPrivateKey: fixture.privateKey,
        candidates: [mapping]
      })
    })
    expect(verified.candidates[0]!.candidateType).toBe(ConnectivityCandidateType.PORT_MAPPED_TCP)
    expect(verified.expiresAt).toBeLessThanOrEqual(mapping.getExpiresAt())
    await mapping.close()
  }, 10000)

  it('AddPortMapping usa internal client/port reais e descrição constante', async () => {
    const { fixture, state, mapping } = await createIntegratedMapping()
    const add = state.requests.find((request) => request.soapAction?.includes('#AddPortMapping'))!
    expect(add.body).toContain(`<NewInternalClient>${fixture.listener.endpoint.address}</NewInternalClient>`)
    expect(add.body).toContain(`<NewInternalPort>${fixture.listener.endpoint.port}</NewInternalPort>`)
    expect(add.body).not.toContain(fixture.server.serverId)
    await mapping.close()
  })

  it('PCP, NAT-PMP e UPnP com o mesmo endpoint produzem candidate wire idêntico', async () => {
    let externalPort = 65000
    const prepared = await prepareIntegratedMapping(
      { addFaults: [718], lease: 300 },
      { randomExternalPort: () => externalPort }
    )
    if (prepared.fixture.listener.endpoint.port === externalPort) externalPort += 1
    const gateway = await startPcpAndNatPmpGateway(externalPort)
    const pcp = await createPcpPortMapping({
      listener: prepared.fixture.listener,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: gateway.port,
      timeoutMs: 50,
      maxRetransmissions: 1
    })
    const natPmp = await createNatPmpPortMapping({
      listener: prepared.fixture.listener,
      customGatewayAddress: '127.0.0.1',
      customGatewayPort: gateway.port,
      initialTimeoutMs: 50,
      maxRetransmissions: 1
    })
    const upnp = await prepared.create()
    const issuedAt = Math.floor(Date.now() / 1000)
    const descriptorId = Buffer.alloc(32, 0x74)
    const wire = (mapping: typeof pcp | typeof natPmp | typeof upnp): Buffer => createSignedConnectivityDescriptor({
      serverId: prepared.fixture.server.serverId,
      serverPublicKey: prepared.fixture.server.identity.publicKey,
      serverPrivateKey: prepared.fixture.privateKey,
      candidates: [mapping],
      customIssuedAt: issuedAt,
      customDescriptorId: descriptorId,
      lifetimeSeconds: 60
    })
    const pcpWire = wire(pcp)
    expect(wire(natPmp).equals(pcpWire)).toBe(true)
    expect(wire(upnp).equals(pcpWire)).toBe(true)
    for (const forbidden of ['PCP', 'NAT-PMP', 'UPnP', '/control', '127.0.0.1']) {
      expect(pcpWire.includes(Buffer.from(forbidden))).toBe(false)
    }
    await Promise.all([pcp.close(), natPmp.close(), upnp.close()])
  }, 10000)

  it('718 tenta portas alternativas bounded; 725 nunca tenta lifetime zero', async () => {
    const conflict = await createIntegratedMapping({ addFaults: [718], lease: 300 })
    const addBodies = conflict.state.requests.filter((request) => request.soapAction?.includes('#AddPortMapping')).map((request) => request.body)
    expect(addBodies).toHaveLength(2)
    expect(addBodies[0]).toContain(`<NewExternalPort>${conflict.fixture.listener.endpoint.port}</NewExternalPort>`)
    expect(addBodies[1]).toMatch(/<NewExternalPort>\d+<\/NewExternalPort>/)
    expect(addBodies.length).toBeLessThanOrEqual(UPNP_MAX_EXTERNAL_PORT_ATTEMPTS)
    await conflict.mapping.close()

    const fixture = await createFixture()
    const state: FakeIgdState = { externalIp: '8.8.4.4', internalClient: '127.0.0.1', internalPort: fixture.listener.endpoint.port, lease: 300, enabled: '1', addFaults: [725], requests: [] }
    const http = await startFakeIgd(state)
    const ssdp = await startSsdp(`http://127.0.0.1:${http.port}/root.xml`)
    await expect(createUpnpPortMapping({ listener: fixture.listener, requestedLifetimeSeconds: 300, gatewayProvider: { resolveGatewayForLocalAddress: async () => '127.0.0.1' }, testOnlyAllowLoopback: true, testOnlySsdpDestinationAddress: '127.0.0.1', testOnlySsdpDestinationPort: ssdp.port, testOnlySsdpTimeoutMs: 100, httpTimeoutMs: 100 })).rejects.toThrow(
      expect.objectContaining({ code: 'UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED' })
    )
    expect(state.requests.every((request) => !request.body.includes('<NewLeaseDuration>0</NewLeaseDuration>'))).toBe(true)
  }, 10000)

  it('somente 718 recebe retry; quatro conflitos encerram sem loop', async () => {
    const other = await prepareIntegratedMapping({ addFaults: [501] })
    await expect(other.create()).rejects.toThrow(expect.objectContaining({ code: 'UPNP_SOAP_FAULT' }))
    expect(other.state.requests.filter((request) => request.soapAction?.includes('#AddPortMapping'))).toHaveLength(1)

    let nextPort = 50000
    const conflicts = await prepareIntegratedMapping(
      { addFaults: [718, 718, 718, 718] },
      { randomExternalPort: () => nextPort++ }
    )
    await expect(conflicts.create()).rejects.toThrow(expect.objectContaining({ code: 'UPNP_MAPPING_CONFLICT' }))
    expect(conflicts.state.requests.filter((request) => request.soapAction?.includes('#AddPortMapping'))).toHaveLength(4)
  })

  it('HTTP 500 sem SOAP Fault válido nunca é aceito como success', async () => {
    const prepared = await prepareIntegratedMapping({ addHttp500Success: true })
    await expect(prepared.create()).rejects.toThrow(expect.objectContaining({ code: 'UPNP_HTTP_RESPONSE_INVALID' }))
    expect(prepared.state.requests.filter((request) => request.soapAction?.includes('#AddPortMapping'))).toHaveLength(1)
  })

  it('falha de GetSpecific após Add executa Delete exatamente na porta criada', async () => {
    const mismatch = await prepareIntegratedMapping({ specificMismatchClient: '127.0.0.2' })
    await expect(mismatch.create()).rejects.toThrow(expect.objectContaining({ code: 'UPNP_MAPPING_VERIFICATION_FAILED' }))
    const add = mismatch.state.requests.find((request) => request.soapAction?.includes('#AddPortMapping'))!
    const deletion = mismatch.state.requests.find((request) => request.soapAction?.includes('#DeletePortMapping'))!
    const externalPort = add.body.match(/<NewExternalPort>(\d+)<\/NewExternalPort>/)?.[1]
    expect(externalPort).toBeTruthy()
    expect(deletion.body).toContain(`<NewExternalPort>${externalPort}</NewExternalPort>`)
    expect(deletion.body).toContain('<NewRemoteHost></NewRemoteHost>')
    expect(deletion.body).toContain('<NewProtocol>TCP</NewProtocol>')
  })

  it.each([
    [{ externalIp: '192.168.1.2' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ externalIp: '100.64.0.1' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ externalIp: '203.0.113.1' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ externalIp: '198.18.0.1' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ externalIp: '127.0.0.1' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ externalIp: '0.0.0.0' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ externalIp: '224.0.0.1' }, 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'],
    [{ specificMismatchClient: '127.0.0.2' }, 'UPNP_MAPPING_VERIFICATION_FAILED'],
    [{ internalPort: 1 }, 'UPNP_MAPPING_VERIFICATION_FAILED'],
    [{ enabled: '0' }, 'UPNP_MAPPING_VERIFICATION_FAILED'],
    [{ lease: 0 }, 'UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED']
  ] as const)('external address/mapping verification falha fechado', async (overrides, code) => {
    await expect(createIntegratedMapping(overrides)).rejects.toThrow(expect.objectContaining({ code }))
  })

  it('constructor sem token e object literal não forjam capability', () => {
    expect(() => new UpnpActivePortMapping({} as never)).toThrow(expect.objectContaining({ code: 'UPNP_REQUEST_INVALID' }))
    expect(isLegitimateActivePortMapping({ isActive: () => true })).toBe(false)
  })

  it('renewal revalida mapping e external IP, podendo atualizar A→B', async () => {
    const integrated = await createIntegratedMapping()
    integrated.state.externalIp = '9.9.9.9'
    await integrated.mapping.executeRenewalForTesting()
    expect(integrated.mapping.getExternalEndpoint().address).toBe('9.9.9.9')
    expect(integrated.mapping.isActive()).toBe(true)
    await integrated.mapping.close()
  })

  it('renew só estende deadline após Add + GetSpecific + GetExternal completos', async () => {
    let monotonic = 1000
    const integrated = await createIntegratedMapping({}, { monotonicClock: () => monotonic })
    const originalExpiry = integrated.mapping.getExpiresAt()
    monotonic += 100
    integrated.state.specificFaults = [501]
    await integrated.mapping.executeRenewalForTesting()
    const afterFailedVerification = integrated.mapping.getExpiresAt()
    expect(afterFailedVerification).toBeLessThan(originalExpiry)
    expect(integrated.mapping.isActive()).toBe(true)
    await integrated.mapping.executeRenewalForTesting()
    expect(integrated.mapping.getExpiresAt()).toBeGreaterThan(afterFailedVerification)
    await integrated.mapping.close()
  })

  it('mapping expirada não é aceita pelo signer', async () => {
    let monotonic = 500
    const integrated = await createIntegratedMapping({}, { monotonicClock: () => monotonic })
    monotonic += 301
    expect(integrated.mapping.isActive()).toBe(false)
    expect(() => createSignedConnectivityDescriptor({
      serverId: integrated.fixture.server.serverId,
      serverPublicKey: integrated.fixture.server.identity.publicKey,
      serverPrivateKey: integrated.fixture.privateKey,
      candidates: [integrated.mapping]
    })).toThrow(expect.objectContaining({ code: 'DESCRIPTOR_HANDLE_CLOSED' }))
    await integrated.mapping.close()
  })

  it('renew mismatch/private external invalidam; failure transitória não estende artificialmente', async () => {
    const integrated = await createIntegratedMapping()
    integrated.state.specificMismatchClient = '127.0.0.2'
    await integrated.mapping.executeRenewalForTesting()
    expect(integrated.mapping.isActive()).toBe(false)

    const privateIp = await createIntegratedMapping()
    privateIp.state.externalIp = '192.168.1.2'
    await privateIp.mapping.executeRenewalForTesting()
    expect(privateIp.mapping.isActive()).toBe(false)
  })

  it('close é idempotente, delete correto e listener close faz cascade', async () => {
    const first = await createIntegratedMapping()
    await Promise.all([first.mapping.close(), first.mapping.close()])
    expect(first.mapping.isActive()).toBe(false)
    const deletes = first.state.requests.filter((request) => request.soapAction?.includes('#DeletePortMapping'))
    expect(deletes).toHaveLength(1)
    expect(deletes[0]!.body).toContain('<NewProtocol>TCP</NewProtocol>')

    const cascade = await createIntegratedMapping()
    await cascade.fixture.listener.close()
    await new Promise((resolve) => setTimeout(resolve, 30))
    expect(cascade.mapping.isActive()).toBe(false)
    expect(cascade.state.requests.some((request) => request.soapAction?.includes('#DeletePortMapping'))).toBe(true)
  })

  it('Delete 714 é semanticamente idempotente e timeout não reativa nem trava close', async () => {
    const absent = await createIntegratedMapping()
    absent.state.deleteFault = 714
    await expect(absent.mapping.close()).resolves.toBeUndefined()
    expect(absent.mapping.isActive()).toBe(false)

    const offline = await createIntegratedMapping({}, { httpTimeoutMs: 30 })
    offline.state.hangDelete = true
    const startedAt = Date.now()
    await expect(offline.mapping.close()).resolves.toBeUndefined()
    expect(Date.now() - startedAt).toBeLessThan(500)
    expect(offline.mapping.isActive()).toBe(false)
  })

  it('close aguarda renewal em voo e envia Delete depois dela', async () => {
    const integrated = await createIntegratedMapping({}, { httpTimeoutMs: 200 })
    integrated.state.addDelayMs = 30
    const renewal = integrated.mapping.executeRenewalForTesting()
    while (integrated.state.requests.filter((request) => request.soapAction?.includes('#AddPortMapping')).length < 2) {
      await new Promise((resolve) => setTimeout(resolve, 1))
    }
    const closing = integrated.mapping.close()
    expect(integrated.mapping.isActive()).toBe(false)
    await Promise.all([renewal, closing])
    const actions = integrated.state.requests.map((request) => request.soapAction ?? '')
    const lastMatchingIndex = (needle: string): number => actions.reduce(
      (found, action, index) => action.includes(needle) ? index : found,
      -1
    )
    const lastAdd = lastMatchingIndex('#AddPortMapping')
    const deletion = lastMatchingIndex('#DeletePortMapping')
    expect(deletion).toBeGreaterThan(lastAdd)
  })

  it('não persiste discovery/mapping state nem altera schema', async () => {
    const integrated = await createIntegratedMapping()
    const before = (await readdir(integrated.fixture.root, { recursive: true })).sort()
    await integrated.mapping.close()
    const after = (await readdir(integrated.fixture.root, { recursive: true })).sort()
    expect(after).toEqual(before)
  })
})

describe('UPnP fuzz-like bounded', () => {
  it('SSDP/XML/SOAP pseudoaleatórios nunca produzem mapping válida', () => {
    let accepted = 0
    for (let length = 0; length < 96; length += 1) {
      const input = Buffer.alloc(length)
      for (let index = 0; index < length; index += 1) input[index] = (length * 17 + index * 29) & 0xff
      for (const parser of [
        () => parseSsdpResponse(input),
        () => parseGetExternalIpAddressResponse(input),
        () => parseGetSpecificPortMappingEntryResponse(input)
      ]) {
        try { parser(); accepted += 1 } catch (error) { expect(error).toBeInstanceOf(UpnpError) }
      }
    }
    expect(accepted).toBe(0)
  })
})
