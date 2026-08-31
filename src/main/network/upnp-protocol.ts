import { isIP } from 'node:net'

import { XMLParser, XMLValidator } from 'fast-xml-parser'

export const SSDP_IPV4_MULTICAST_ADDRESS = '239.255.255.250'
export const SSDP_PORT = 1900
export const SSDP_TTL = 2
export const UPNP_IGD_V1_SEARCH_TARGET = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'
export const UPNP_WAN_DEVICE_V1 = 'urn:schemas-upnp-org:device:WANDevice:1'
export const UPNP_WAN_CONNECTION_DEVICE_V1 = 'urn:schemas-upnp-org:device:WANConnectionDevice:1'
export const UPNP_WAN_IP_CONNECTION_V1 = 'urn:schemas-upnp-org:service:WANIPConnection:1'
export const UPNP_WAN_PPP_CONNECTION_V1 = 'urn:schemas-upnp-org:service:WANPPPConnection:1'

export const MAX_SSDP_DATAGRAM_BYTES = 8192
export const MAX_SSDP_HEADERS = 32
export const MAX_SSDP_HEADER_LINE_BYTES = 1024
export const MAX_UPNP_URL_BYTES = 2048
export const MAX_UPNP_URL_PATH_BYTES = 1024
export const MAX_UPNP_URL_QUERY_BYTES = 512
export const MAX_UPNP_DEVICE_DESCRIPTION_BYTES = 128 * 1024
export const MAX_UPNP_SOAP_RESPONSE_BYTES = 64 * 1024
export const MAX_UPNP_XML_DEPTH = 32
export const MAX_UPNP_XML_ELEMENTS = 512
export const MAX_UPNP_XML_ATTRIBUTES_PER_ELEMENT = 16
export const MAX_UPNP_XML_TEXT_BYTES = 64 * 1024

export type UpnpErrorCode =
  | 'UPNP_LISTENER_INVALID'
  | 'UPNP_LISTENER_CLOSED'
  | 'UPNP_GATEWAY_NOT_FOUND'
  | 'UPNP_GATEWAY_INVALID'
  | 'UPNP_SSDP_TIMEOUT'
  | 'UPNP_SSDP_RESPONSE_INVALID'
  | 'UPNP_SSDP_SOURCE_INVALID'
  | 'UPNP_LOCATION_INVALID'
  | 'UPNP_LOCATION_CROSS_HOST'
  | 'UPNP_HTTP_TIMEOUT'
  | 'UPNP_HTTP_RESPONSE_TOO_LARGE'
  | 'UPNP_HTTP_REDIRECT_PROHIBITED'
  | 'UPNP_HTTP_RESPONSE_INVALID'
  | 'UPNP_XML_INVALID'
  | 'UPNP_XML_UNSAFE'
  | 'UPNP_XML_LIMIT_EXCEEDED'
  | 'UPNP_IGD_SERVICE_NOT_FOUND'
  | 'UPNP_AMBIGUOUS_WAN_SERVICE'
  | 'UPNP_CONTROL_URL_INVALID'
  | 'UPNP_SOAP_FAULT'
  | 'UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL'
  | 'UPNP_MAPPING_CONFLICT'
  | 'UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED'
  | 'UPNP_MAPPING_VERIFICATION_FAILED'
  | 'UPNP_MAPPING_EXPIRED'
  | 'UPNP_MAPPING_CLOSED'
  | 'UPNP_REQUEST_INVALID'

const ERROR_MESSAGES: Record<UpnpErrorCode, string> = {
  UPNP_LISTENER_INVALID: 'O listener fornecido para UPnP é inválido ou ilegítimo.',
  UPNP_LISTENER_CLOSED: 'O listener associado ao UPnP foi encerrado.',
  UPNP_GATEWAY_NOT_FOUND: 'Nenhum default gateway válido foi encontrado.',
  UPNP_GATEWAY_INVALID: 'O default gateway UPnP é inválido.',
  UPNP_SSDP_TIMEOUT: 'Tempo limite esgotado aguardando SSDP do gateway.',
  UPNP_SSDP_RESPONSE_INVALID: 'A resposta SSDP é inválida.',
  UPNP_SSDP_SOURCE_INVALID: 'A resposta SSDP não veio do gateway esperado.',
  UPNP_LOCATION_INVALID: 'O LOCATION SSDP é inválido.',
  UPNP_LOCATION_CROSS_HOST: 'O LOCATION aponta para host diferente do gateway.',
  UPNP_HTTP_TIMEOUT: 'A request HTTP UPnP excedeu o timeout.',
  UPNP_HTTP_RESPONSE_TOO_LARGE: 'A resposta HTTP UPnP excedeu o limite.',
  UPNP_HTTP_REDIRECT_PROHIBITED: 'Redirect HTTP UPnP é proibido.',
  UPNP_HTTP_RESPONSE_INVALID: 'A resposta HTTP UPnP é inválida.',
  UPNP_XML_INVALID: 'O XML UPnP é inválido.',
  UPNP_XML_UNSAFE: 'O XML UPnP contém construção proibida.',
  UPNP_XML_LIMIT_EXCEEDED: 'O XML UPnP excedeu limites estruturais.',
  UPNP_IGD_SERVICE_NOT_FOUND: 'Nenhum serviço IGD v1 permitido foi encontrado.',
  UPNP_AMBIGUOUS_WAN_SERVICE: 'A descrição contém serviços WAN ambíguos.',
  UPNP_CONTROL_URL_INVALID: 'O controlURL UPnP é inválido.',
  UPNP_SOAP_FAULT: 'O gateway retornou SOAP Fault.',
  UPNP_EXTERNAL_ADDRESS_NOT_GLOBAL: 'O endereço externo UPnP não é globalmente roteável.',
  UPNP_MAPPING_CONFLICT: 'A porta externa UPnP está em conflito.',
  UPNP_PERMANENT_LEASE_REQUIRED_UNSUPPORTED: 'O gateway exige mapping permanente, não suportada.',
  UPNP_MAPPING_VERIFICATION_FAILED: 'A mapping UPnP não pôde ser comprovada.',
  UPNP_MAPPING_EXPIRED: 'A lease UPnP expirou.',
  UPNP_MAPPING_CLOSED: 'A mapping UPnP foi encerrada.',
  UPNP_REQUEST_INVALID: 'Os parâmetros UPnP são inválidos.'
}

export class UpnpError extends Error {
  readonly code: UpnpErrorCode
  readonly soapErrorCode?: number

  constructor(code: UpnpErrorCode, soapErrorCode?: number) {
    super(ERROR_MESSAGES[code])
    this.name = 'UpnpError'
    this.code = code
    this.soapErrorCode = soapErrorCode
  }
}

export function encodeSsdpMSearch(): Buffer {
  return Buffer.from(
    'M-SEARCH * HTTP/1.1\r\n' +
    `HOST: ${SSDP_IPV4_MULTICAST_ADDRESS}:${SSDP_PORT}\r\n` +
    'MAN: "ssdp:discover"\r\n' +
    'MX: 1\r\n' +
    `ST: ${UPNP_IGD_V1_SEARCH_TARGET}\r\n\r\n`,
    'ascii'
  )
}

export interface ParsedSsdpResponse {
  readonly location: string
  readonly searchTarget: typeof UPNP_IGD_V1_SEARCH_TARGET
}

function containsAsciiControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.charCodeAt(0)
    if (codePoint <= 0x1f || codePoint === 0x7f) return true
  }
  return false
}

export function parseSsdpResponse(datagram: Buffer): ParsedSsdpResponse {
  if (!Buffer.isBuffer(datagram) || datagram.length === 0 || datagram.length > MAX_SSDP_DATAGRAM_BYTES) {
    throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
  }
  const text = datagram.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(datagram) || text.includes('\0')) {
    throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
  }
  if (!text.endsWith('\r\n\r\n') || /(^|[^\r])\n/.test(text) || /\r(?!\n)/.test(text)) {
    throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
  }
  const lines = text.slice(0, -4).split('\r\n')
  if (lines.shift() !== 'HTTP/1.1 200 OK' || lines.length > MAX_SSDP_HEADERS) {
    throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
  }
  const headers = new Map<string, string>()
  for (const line of lines) {
    if (
      Buffer.byteLength(line, 'utf8') > MAX_SSDP_HEADER_LINE_BYTES ||
      /^[ \t]/.test(line) ||
      containsAsciiControl(line)
    ) {
      throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
    }
    const separator = line.indexOf(':')
    if (separator <= 0) throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
    const name = line.slice(0, separator).trim().toLowerCase()
    const value = line.slice(separator + 1).trim()
    if (!/^[a-z0-9-]+$/.test(name) || value.length === 0) {
      throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
    }
    if ((name === 'location' || name === 'st') && headers.has(name)) {
      throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
    }
    headers.set(name, value)
  }
  const location = headers.get('location')
  const searchTarget = headers.get('st')
  if (!location || searchTarget !== UPNP_IGD_V1_SEARCH_TARGET) {
    throw new UpnpError('UPNP_SSDP_RESPONSE_INVALID')
  }
  return { location, searchTarget: UPNP_IGD_V1_SEARCH_TARGET }
}

export function validateUpnpGatewayUrl(
  rawUrl: string,
  expectedGatewayIp: string,
  errorCode: 'UPNP_LOCATION_INVALID' | 'UPNP_CONTROL_URL_INVALID' = 'UPNP_LOCATION_INVALID'
): URL {
  if (
    typeof rawUrl !== 'string' ||
    Buffer.byteLength(rawUrl, 'utf8') > MAX_UPNP_URL_BYTES ||
    containsAsciiControl(rawUrl)
  ) {
    throw new UpnpError(errorCode)
  }
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new UpnpError(errorCode)
  }
  if (parsed.protocol !== 'http:' || parsed.username || parsed.password || parsed.hash) {
    throw new UpnpError(errorCode)
  }
  if (isIP(parsed.hostname) !== 4) throw new UpnpError(errorCode)
  if (parsed.hostname !== expectedGatewayIp) {
    throw new UpnpError(errorCode === 'UPNP_LOCATION_INVALID' ? 'UPNP_LOCATION_CROSS_HOST' : errorCode)
  }
  const authorityMatch = /^http:\/\/([^/?#]+)(?:[/?#]|$)/.exec(rawUrl)
  if (!authorityMatch || !authorityMatch[1] || !new RegExp(`^${escapeRegex(expectedGatewayIp)}(?::\\d{1,5})?$`).test(authorityMatch[1])) {
    throw new UpnpError(errorCode)
  }
  const port = parsed.port === '' ? 80 : Number(parsed.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UpnpError(errorCode)
  if (
    Buffer.byteLength(parsed.pathname, 'utf8') > MAX_UPNP_URL_PATH_BYTES ||
    Buffer.byteLength(parsed.search, 'utf8') > MAX_UPNP_URL_QUERY_BYTES
  ) throw new UpnpError(errorCode)
  return parsed
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

type XmlRecord = Record<string, unknown>

function asRecord(value: unknown): XmlRecord | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as XmlRecord : null
}

function asArray(value: unknown): readonly unknown[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value]
}

function scalarText(value: unknown): string | null {
  if (typeof value === 'string') return value.trim()
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  const record = asRecord(value)
  if (record && typeof record['#text'] === 'string') return record['#text'].trim()
  return null
}

function parseBoundedXml(xml: Buffer | string, maxBytes: number): XmlRecord {
  const text = Buffer.isBuffer(xml) ? xml.toString('utf8') : xml
  if (Buffer.isBuffer(xml) && !Buffer.from(text, 'utf8').equals(xml)) {
    throw new UpnpError('UPNP_XML_INVALID')
  }
  if (Buffer.byteLength(text, 'utf8') === 0 || Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new UpnpError('UPNP_XML_LIMIT_EXCEEDED')
  }
  if (/<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)\b/i.test(text) || /<(?:[A-Za-z_][\w.-]*:)?include\b/i.test(text)) {
    throw new UpnpError('UPNP_XML_UNSAFE')
  }
  if (XMLValidator.validate(text, { allowBooleanAttributes: false }) !== true) {
    throw new UpnpError('UPNP_XML_INVALID')
  }
  let parsed: unknown
  try {
    parsed = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      parseTagValue: false,
      parseAttributeValue: false,
      processEntities: false,
      removeNSPrefix: true,
      trimValues: true,
      allowBooleanAttributes: false
    }).parse(text)
  } catch {
    throw new UpnpError('UPNP_XML_INVALID')
  }
  const root = asRecord(parsed)
  if (!root) throw new UpnpError('UPNP_XML_INVALID')
  validateXmlLimits(root, 0, { elements: 0, textBytes: 0 })
  return root
}

function validateXmlLimits(
  value: unknown,
  depth: number,
  counters: { elements: number; textBytes: number }
): void {
  if (depth > MAX_UPNP_XML_DEPTH) throw new UpnpError('UPNP_XML_LIMIT_EXCEEDED')
  if (typeof value === 'string') {
    counters.textBytes += Buffer.byteLength(value, 'utf8')
    if (counters.textBytes > MAX_UPNP_XML_TEXT_BYTES) throw new UpnpError('UPNP_XML_LIMIT_EXCEEDED')
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) validateXmlLimits(item, depth, counters)
    return
  }
  const record = asRecord(value)
  if (!record) return
  let attributes = 0
  for (const [key, child] of Object.entries(record)) {
    if (key.startsWith('@_')) {
      attributes += 1
      if (attributes > MAX_UPNP_XML_ATTRIBUTES_PER_ELEMENT) throw new UpnpError('UPNP_XML_LIMIT_EXCEEDED')
      continue
    }
    if (key !== '#text') {
      counters.elements += Array.isArray(child) ? child.length : 1
      if (counters.elements > MAX_UPNP_XML_ELEMENTS) throw new UpnpError('UPNP_XML_LIMIT_EXCEEDED')
    }
    validateXmlLimits(child, depth + (key === '#text' ? 0 : 1), counters)
  }
}

export interface UpnpWanService {
  readonly serviceType: typeof UPNP_WAN_IP_CONNECTION_V1 | typeof UPNP_WAN_PPP_CONNECTION_V1
  readonly serviceId: string
  readonly controlUrl: URL
}

export function parseUpnpDeviceDescription(
  xml: Buffer | string,
  locationUrl: URL,
  gatewayIp: string
): UpnpWanService {
  const document = parseBoundedXml(xml, MAX_UPNP_DEVICE_DESCRIPTION_BYTES)
  const root = asRecord(document.root)
  const igd = asRecord(root?.device)
  if (!root || !igd || scalarText(igd.deviceType) !== UPNP_IGD_V1_SEARCH_TARGET) {
    throw new UpnpError('UPNP_IGD_SERVICE_NOT_FOUND')
  }
  let base = locationUrl
  if (root.URLBase !== undefined) {
    const urlBase = scalarText(root.URLBase)
    if (!urlBase) throw new UpnpError('UPNP_CONTROL_URL_INVALID')
    base = validateUpnpGatewayUrl(urlBase, gatewayIp, 'UPNP_CONTROL_URL_INVALID')
  }
  const ipServices: UpnpWanService[] = []
  const pppServices: UpnpWanService[] = []
  for (const wanValue of asArray(asRecord(igd.deviceList)?.device)) {
    const wan = asRecord(wanValue)
    if (!wan || scalarText(wan.deviceType) !== UPNP_WAN_DEVICE_V1) continue
    for (const connectionValue of asArray(asRecord(wan.deviceList)?.device)) {
      const connection = asRecord(connectionValue)
      if (!connection || scalarText(connection.deviceType) !== UPNP_WAN_CONNECTION_DEVICE_V1) continue
      for (const serviceValue of asArray(asRecord(connection.serviceList)?.service)) {
        const service = asRecord(serviceValue)
        if (!service) continue
        const serviceType = scalarText(service.serviceType)
        if (serviceType !== UPNP_WAN_IP_CONNECTION_V1 && serviceType !== UPNP_WAN_PPP_CONNECTION_V1) continue
        const serviceId = scalarText(service.serviceId)
        const rawControlUrl = scalarText(service.controlURL)
        if (!serviceId || !rawControlUrl) throw new UpnpError('UPNP_CONTROL_URL_INVALID')
        let resolved: URL
        try {
          resolved = new URL(rawControlUrl, base)
        } catch {
          throw new UpnpError('UPNP_CONTROL_URL_INVALID')
        }
        const candidate: UpnpWanService = {
          serviceType,
          serviceId,
          controlUrl: validateUpnpGatewayUrl(resolved.href, gatewayIp, 'UPNP_CONTROL_URL_INVALID')
        }
        if (serviceType === UPNP_WAN_IP_CONNECTION_V1) ipServices.push(candidate)
        else pppServices.push(candidate)
      }
    }
  }
  if (ipServices.length > 1 || (ipServices.length === 0 && pppServices.length > 1)) {
    throw new UpnpError('UPNP_AMBIGUOUS_WAN_SERVICE')
  }
  if (ipServices.length === 1) return ipServices[0]!
  if (pppServices.length === 1) return pppServices[0]!
  throw new UpnpError('UPNP_IGD_SERVICE_NOT_FOUND')
}

function escapeXml(value: string | number): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function assertAllowedServiceType(serviceType: string): asserts serviceType is UpnpWanService['serviceType'] {
  if (serviceType !== UPNP_WAN_IP_CONNECTION_V1 && serviceType !== UPNP_WAN_PPP_CONNECTION_V1) {
    throw new UpnpError('UPNP_REQUEST_INVALID')
  }
}

function assertSoapPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UpnpError('UPNP_REQUEST_INVALID')
}

function soapEnvelope(serviceType: string, action: string, fields: readonly [string, string | number][]): Buffer {
  const body = fields.map(([name, value]) => `<${name}>${escapeXml(value)}</${name}>`).join('')
  return Buffer.from(
    '<?xml version="1.0" encoding="utf-8"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:${action} xmlns:u="${serviceType}">${body}</u:${action}></s:Body></s:Envelope>`,
    'utf8'
  )
}

export function encodeGetExternalIpAddress(serviceType: UpnpWanService['serviceType']): Buffer {
  assertAllowedServiceType(serviceType)
  return soapEnvelope(serviceType, 'GetExternalIPAddress', [])
}

export interface AddPortMappingSoapOptions {
  readonly serviceType: UpnpWanService['serviceType']
  readonly externalPort: number
  readonly internalPort: number
  readonly internalClient: string
  readonly leaseDurationSeconds: number
}

export function encodeAddPortMapping(options: AddPortMappingSoapOptions): Buffer {
  assertAllowedServiceType(options.serviceType)
  assertSoapPort(options.externalPort)
  assertSoapPort(options.internalPort)
  if (isIP(options.internalClient) !== 4) throw new UpnpError('UPNP_REQUEST_INVALID')
  if (
    !Number.isInteger(options.leaseDurationSeconds) ||
    options.leaseDurationSeconds < 1 ||
    options.leaseDurationSeconds > 0xffffffff
  ) throw new UpnpError('UPNP_REQUEST_INVALID')
  return soapEnvelope(options.serviceType, 'AddPortMapping', [
    ['NewRemoteHost', ''],
    ['NewExternalPort', options.externalPort],
    ['NewProtocol', 'TCP'],
    ['NewInternalPort', options.internalPort],
    ['NewInternalClient', options.internalClient],
    ['NewEnabled', 1],
    ['NewPortMappingDescription', 'Masquerada'],
    ['NewLeaseDuration', options.leaseDurationSeconds]
  ])
}

export function encodeGetSpecificPortMappingEntry(
  serviceType: UpnpWanService['serviceType'], externalPort: number
): Buffer {
  assertAllowedServiceType(serviceType)
  assertSoapPort(externalPort)
  return soapEnvelope(serviceType, 'GetSpecificPortMappingEntry', [
    ['NewRemoteHost', ''], ['NewExternalPort', externalPort], ['NewProtocol', 'TCP']
  ])
}

export function encodeDeletePortMapping(
  serviceType: UpnpWanService['serviceType'], externalPort: number
): Buffer {
  assertAllowedServiceType(serviceType)
  assertSoapPort(externalPort)
  return soapEnvelope(serviceType, 'DeletePortMapping', [
    ['NewRemoteHost', ''], ['NewExternalPort', externalPort], ['NewProtocol', 'TCP']
  ])
}

function findElement(root: unknown, name: string): unknown {
  const record = asRecord(root)
  if (!record) return undefined
  if (record[name] !== undefined) return record[name]
  for (const [key, child] of Object.entries(record)) {
    if (key.startsWith('@_') || key === '#text') continue
    for (const item of asArray(child)) {
      const found = findElement(item, name)
      if (found !== undefined) return found
    }
  }
  return undefined
}

function parseSoapBody(xml: Buffer | string): XmlRecord {
  const document = parseBoundedXml(xml, MAX_UPNP_SOAP_RESPONSE_BYTES)
  const envelope = asRecord(document.Envelope)
  const body = asRecord(envelope?.Body)
  if (!envelope || !body) throw new UpnpError('UPNP_XML_INVALID')
  const fault = body.Fault
  if (fault !== undefined) {
    const rawCode = scalarText(findElement(fault, 'errorCode'))
    const code = rawCode && /^\d{1,5}$/.test(rawCode) ? Number(rawCode) : undefined
    throw new UpnpError('UPNP_SOAP_FAULT', code)
  }
  return body
}

export function throwSoapFaultResponse(xml: Buffer | string): never {
  try {
    parseSoapBody(xml)
  } catch (error) {
    if (error instanceof UpnpError && error.code === 'UPNP_SOAP_FAULT') throw error
    throw new UpnpError('UPNP_HTTP_RESPONSE_INVALID')
  }
  throw new UpnpError('UPNP_HTTP_RESPONSE_INVALID')
}

export function parseGetExternalIpAddressResponse(xml: Buffer | string): string {
  const body = parseSoapBody(xml)
  const response = asRecord(body.GetExternalIPAddressResponse)
  const address = scalarText(response?.NewExternalIPAddress)
  if (!address) throw new UpnpError('UPNP_XML_INVALID')
  return address
}

export interface VerifiedSpecificMappingEntry {
  readonly internalClient: string
  readonly internalPort: number
  readonly enabled: boolean
  readonly leaseDurationSeconds: number
}

export function parseGetSpecificPortMappingEntryResponse(xml: Buffer | string): VerifiedSpecificMappingEntry {
  const body = parseSoapBody(xml)
  const response = asRecord(body.GetSpecificPortMappingEntryResponse)
  const client = scalarText(response?.NewInternalClient)
  const port = scalarText(response?.NewInternalPort)
  const enabled = scalarText(response?.NewEnabled)
  const lease = scalarText(response?.NewLeaseDuration)
  if (!client || !port || !lease || !/^\d{1,5}$/.test(port) || !/^\d{1,10}$/.test(lease)) {
    throw new UpnpError('UPNP_MAPPING_VERIFICATION_FAILED')
  }
  const internalPort = Number(port)
  const leaseDurationSeconds = Number(lease)
  if (internalPort < 1 || internalPort > 65535 || leaseDurationSeconds > 0xffffffff || enabled !== '1') {
    throw new UpnpError('UPNP_MAPPING_VERIFICATION_FAILED')
  }
  return { internalClient: client, internalPort, enabled: true, leaseDurationSeconds }
}

export function assertSoapActionSuccess(xml: Buffer | string, action: 'AddPortMapping' | 'DeletePortMapping'): void {
  const body = parseSoapBody(xml)
  if (!Object.prototype.hasOwnProperty.call(body, `${action}Response`)) {
    throw new UpnpError('UPNP_XML_INVALID')
  }
}
