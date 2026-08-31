import { createSocket, type RemoteInfo, type Socket as DgramSocket } from 'node:dgram'
import { request as httpRequest, type IncomingMessage } from 'node:http'

import {
  encodeAddPortMapping,
  encodeDeletePortMapping,
  encodeGetExternalIpAddress,
  encodeGetSpecificPortMappingEntry,
  encodeSsdpMSearch,
  MAX_SSDP_DATAGRAM_BYTES,
  MAX_UPNP_DEVICE_DESCRIPTION_BYTES,
  MAX_UPNP_SOAP_RESPONSE_BYTES,
  parseSsdpResponse,
  SSDP_IPV4_MULTICAST_ADDRESS,
  SSDP_PORT,
  SSDP_TTL,
  throwSoapFaultResponse,
  UPNP_WAN_IP_CONNECTION_V1,
  UPNP_WAN_PPP_CONNECTION_V1,
  UpnpError,
  validateUpnpGatewayUrl,
  type UpnpWanService
} from './upnp-protocol'

export const UPNP_SSDP_TIMEOUT_MS = 1500
export const UPNP_HTTP_TIMEOUT_MS = 3000

export interface DiscoverUpnpLocationOptions {
  readonly localAddress: string
  readonly gatewayAddress: string
  readonly destinationAddress?: string
  readonly destinationPort?: number
  readonly timeoutMs?: number
}

/** Transient SSDP search. destination overrides exist only for deterministic local tests. */
export async function discoverUpnpLocation(options: DiscoverUpnpLocationOptions): Promise<URL> {
  const destinationAddress = options.destinationAddress ?? SSDP_IPV4_MULTICAST_ADDRESS
  const destinationPort = options.destinationPort ?? SSDP_PORT
  const timeoutMs = options.timeoutMs ?? UPNP_SSDP_TIMEOUT_MS
  const socket: DgramSocket = createSocket('udp4')
  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (): void => reject(new UpnpError('UPNP_SSDP_RESPONSE_INVALID'))
      socket.once('error', onError)
      socket.bind(0, options.localAddress, () => {
        socket.off('error', onError)
        const bound = socket.address()
        if (bound.address === '0.0.0.0' || bound.address !== options.localAddress) {
          reject(new UpnpError('UPNP_REQUEST_INVALID'))
          return
        }
        try {
          if (destinationAddress === SSDP_IPV4_MULTICAST_ADDRESS) {
            socket.setMulticastInterface(options.localAddress)
            socket.setMulticastTTL(SSDP_TTL)
          }
        } catch {
          reject(new UpnpError('UPNP_REQUEST_INVALID'))
          return
        }
        resolve()
      })
    })
    return await new Promise<URL>((resolve, reject) => {
      let done = false
      const timer = setTimeout(() => finish(() => reject(new UpnpError('UPNP_SSDP_TIMEOUT'))), timeoutMs)
      const finish = (callback: () => void): void => {
        if (done) return
        done = true
        clearTimeout(timer)
        socket.removeAllListeners()
        callback()
      }
      socket.on('error', () => finish(() => reject(new UpnpError('UPNP_SSDP_RESPONSE_INVALID'))))
      socket.on('message', (message: Buffer, remote: RemoteInfo) => {
        if (done) return
        if (remote.address !== options.gatewayAddress || remote.port !== destinationPort) return
        if (message.length > MAX_SSDP_DATAGRAM_BYTES) return
        try {
          const parsed = parseSsdpResponse(message)
          const location = validateUpnpGatewayUrl(parsed.location, options.gatewayAddress)
          finish(() => resolve(location))
        } catch {
          // Malformed packets do not terminate the bounded discovery window.
        }
      })
      socket.send(encodeSsdpMSearch(), destinationPort, destinationAddress, (error) => {
        if (error) finish(() => reject(new UpnpError('UPNP_SSDP_RESPONSE_INVALID')))
      })
    })
  } finally {
    try { socket.close() } catch { /* already closed */ }
  }
}

export interface UpnpHttpResponse {
  readonly statusCode: number
  readonly body: Buffer
}

function countRawHeader(response: IncomingMessage, expectedName: string): number {
  let count = 0
  for (let index = 0; index < response.rawHeaders.length; index += 2) {
    if (response.rawHeaders[index]?.toLowerCase() === expectedName) count += 1
  }
  return count
}

async function boundedHttpRequest(options: {
  readonly url: URL
  readonly localAddress: string
  readonly method: 'GET' | 'POST'
  readonly headers: Readonly<Record<string, string>>
  readonly body?: Buffer
  readonly maxBodyBytes: number
  readonly allowSoapFaultStatus?: boolean
  readonly timeoutMs?: number
}): Promise<UpnpHttpResponse> {
  return new Promise<UpnpHttpResponse>((resolve, reject) => {
    let settled = false
    const finish = (callback: () => void): void => {
      if (settled) return
      settled = true
      callback()
    }
    const request = httpRequest({
      protocol: 'http:',
      hostname: options.url.hostname,
      port: options.url.port === '' ? 80 : Number(options.url.port),
      path: `${options.url.pathname}${options.url.search}`,
      method: options.method,
      localAddress: options.localAddress,
      agent: false,
      headers: {
        Host: options.url.host,
        Connection: 'close',
        'Accept-Encoding': 'identity',
        ...options.headers
      }
    }, (response) => {
      const status = response.statusCode ?? 0
      if (status >= 300 && status < 400) {
        response.resume()
        finish(() => reject(new UpnpError('UPNP_HTTP_REDIRECT_PROHIBITED')))
        return
      }
      const validStatus = status === 200 || (options.allowSoapFaultStatus === true && status === 500)
      if (!validStatus) {
        response.resume()
        finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_INVALID')))
        return
      }
      if (
        countRawHeader(response, 'content-length') > 1 ||
        countRawHeader(response, 'content-encoding') > 1
      ) {
        response.resume()
        finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_INVALID')))
        return
      }
      const encoding = response.headers['content-encoding']
      if (encoding !== undefined && String(encoding).trim().toLowerCase() !== 'identity') {
        response.resume()
        finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_INVALID')))
        return
      }
      const contentLength = response.headers['content-length']
      if (contentLength !== undefined) {
        if (!/^\d+$/.test(String(contentLength))) {
          response.resume()
          finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_INVALID')))
          return
        }
        const declared = Number(contentLength)
        if (!Number.isSafeInteger(declared) || declared > options.maxBodyBytes) {
          response.resume()
          finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_TOO_LARGE')))
          return
        }
      }
      const chunks: Buffer[] = []
      let total = 0
      response.on('error', () => finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_INVALID'))))
      response.on('data', (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        total += buffer.length
        if (total > options.maxBodyBytes) {
          response.destroy()
          finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_TOO_LARGE')))
          return
        }
        chunks.push(buffer)
      })
      response.on('end', () => finish(() => resolve({ statusCode: status, body: Buffer.concat(chunks) })))
    })
    request.on('error', () => finish(() => reject(new UpnpError('UPNP_HTTP_RESPONSE_INVALID'))))
    request.setTimeout(options.timeoutMs ?? UPNP_HTTP_TIMEOUT_MS, () => {
      request.destroy()
      finish(() => reject(new UpnpError('UPNP_HTTP_TIMEOUT')))
    })
    if (options.body) request.write(options.body)
    request.end()
  })
}

export async function getUpnpDeviceDescription(
  location: URL,
  gatewayAddress: string,
  localAddress: string,
  timeoutMs?: number
): Promise<Buffer> {
  const validated = validateUpnpGatewayUrl(location.href, gatewayAddress)
  const response = await boundedHttpRequest({
    url: validated,
    localAddress,
    method: 'GET',
    headers: { Accept: 'text/xml, application/xml' },
    maxBodyBytes: MAX_UPNP_DEVICE_DESCRIPTION_BYTES,
    timeoutMs
  })
  return response.body
}

type UpnpSoapAction =
  | 'GetExternalIPAddress'
  | 'AddPortMapping'
  | 'GetSpecificPortMappingEntry'
  | 'DeletePortMapping'

interface UpnpSoapRequestContext {
  readonly controlUrl: URL
  readonly gatewayAddress: string
  readonly localAddress: string
  readonly serviceType: UpnpWanService['serviceType']
  readonly timeoutMs?: number
}

async function postUpnpSoap(options: UpnpSoapRequestContext & {
  readonly action: UpnpSoapAction
  readonly body: Buffer
}): Promise<UpnpHttpResponse> {
  const allowedActions: readonly UpnpSoapAction[] = [
    'GetExternalIPAddress', 'AddPortMapping', 'GetSpecificPortMappingEntry', 'DeletePortMapping'
  ]
  if (
    !allowedActions.includes(options.action) ||
    (options.serviceType !== UPNP_WAN_IP_CONNECTION_V1 && options.serviceType !== UPNP_WAN_PPP_CONNECTION_V1)
  ) throw new UpnpError('UPNP_REQUEST_INVALID')
  const validated = validateUpnpGatewayUrl(options.controlUrl.href, options.gatewayAddress, 'UPNP_CONTROL_URL_INVALID')
  const response = await boundedHttpRequest({
    url: validated,
    localAddress: options.localAddress,
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset="utf-8"',
      SOAPAction: `"${options.serviceType}#${options.action}"`,
      'Content-Length': String(options.body.length)
    },
    body: options.body,
    maxBodyBytes: MAX_UPNP_SOAP_RESPONSE_BYTES,
    allowSoapFaultStatus: true,
    timeoutMs: options.timeoutMs
  })
  if (response.statusCode === 500) throwSoapFaultResponse(response.body)
  return response
}

export async function requestUpnpExternalIpAddress(
  context: UpnpSoapRequestContext
): Promise<Buffer> {
  return (await postUpnpSoap({
    ...context,
    action: 'GetExternalIPAddress',
    body: encodeGetExternalIpAddress(context.serviceType)
  })).body
}

export async function requestUpnpAddPortMapping(
  context: UpnpSoapRequestContext,
  options: {
    readonly externalPort: number
    readonly internalPort: number
    readonly internalClient: string
    readonly leaseDurationSeconds: number
  }
): Promise<Buffer> {
  return (await postUpnpSoap({
    ...context,
    action: 'AddPortMapping',
    body: encodeAddPortMapping({ serviceType: context.serviceType, ...options })
  })).body
}

export async function requestUpnpSpecificPortMapping(
  context: UpnpSoapRequestContext,
  externalPort: number
): Promise<Buffer> {
  return (await postUpnpSoap({
    ...context,
    action: 'GetSpecificPortMappingEntry',
    body: encodeGetSpecificPortMappingEntry(context.serviceType, externalPort)
  })).body
}

export async function requestUpnpDeletePortMapping(
  context: UpnpSoapRequestContext,
  externalPort: number
): Promise<Buffer> {
  return (await postUpnpSoap({
    ...context,
    action: 'DeletePortMapping',
    body: encodeDeletePortMapping(context.serviceType, externalPort)
  })).body
}
