import { afterEach, describe, expect, it } from 'vitest'
import { createServer, type Server, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'

import { MAX_UPNP_DEVICE_DESCRIPTION_BYTES } from './upnp-protocol'
import { getUpnpDeviceDescription } from './upnp-transport'

const servers: Server[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
    server.closeAllConnections()
  })))
})

async function startHttp(handler: (response: ServerResponse) => void) {
  const sockets = new Set<Socket>()
  const server = createServer((_request, response) => handler(response))
  servers.push(server)
  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('HTTP address unavailable')
  return {
    sockets,
    get: (timeoutMs = 2000) => getUpnpDeviceDescription(
      new URL(`http://127.0.0.1:${address.port}/root.xml`), '127.0.0.1', '127.0.0.1', timeoutMs
    )
  }
}

describe('UPnP HTTP deadline and cleanup', () => {
  it('enforces the total deadline despite continuous body activity and closes the socket', async () => {
    let writes = 0
    const http = await startHttp((response) => {
      response.writeHead(200)
      response.write('x')
      const drip = setInterval(() => {
        writes += 1
        response.write('x')
      }, 10)
      // Bound the fixture too, so an inactivity-only implementation fails without hanging.
      const end = setTimeout(() => response.end(), 1000)
      response.once('close', () => {
        clearInterval(drip)
        clearTimeout(end)
      })
    })
    const startedAt = performance.now()
    await expect(http.get(200)).rejects.toMatchObject({ code: 'UPNP_HTTP_TIMEOUT' })
    expect(performance.now() - startedAt).toBeLessThan(800)
    expect(writes).toBeGreaterThan(1)
    await expect.poll(() => http.sockets.size, { timeout: 500 }).toBe(0)
  })

  it('closes a request that never receives response headers', async () => {
    const http = await startHttp(() => {})
    await expect(http.get(100)).rejects.toMatchObject({ code: 'UPNP_HTTP_TIMEOUT' })
    await expect.poll(() => http.sockets.size, { timeout: 500 }).toBe(0)
  })

  it.each([
    { name: 'redirect', status: 307, headers: { Location: '/other' }, code: 'UPNP_HTTP_REDIRECT_PROHIBITED' },
    { name: 'invalid status', status: 503, headers: {}, code: 'UPNP_HTTP_RESPONSE_INVALID' },
    { name: 'compression', status: 200, headers: { 'Content-Encoding': 'gzip' }, code: 'UPNP_HTTP_RESPONSE_INVALID' },
    { name: 'duplicate encoding', status: 200, headers: { 'Content-Encoding': ['identity', 'identity'] }, code: 'UPNP_HTTP_RESPONSE_INVALID' },
    { name: 'invalid length', status: 200, headers: { 'Content-Length': 'invalid' }, code: 'UPNP_HTTP_RESPONSE_INVALID' },
    { name: 'declared oversized body', status: 200, headers: { 'Content-Length': String(MAX_UPNP_DEVICE_DESCRIPTION_BYTES + 1) }, code: 'UPNP_HTTP_RESPONSE_TOO_LARGE' }
  ])('closes a rejected $name response without waiting for body end', async ({ status, headers, code }) => {
    const http = await startHttp((response) => {
      response.writeHead(status, headers)
      response.flushHeaders()
      // Deliberately never end the response: draining it cannot release the socket.
    })
    await expect(http.get()).rejects.toMatchObject({ code })
    await expect.poll(() => http.sockets.size, { timeout: 500 }).toBe(0)
  })

  it('preserves the size error when destroying an oversized streaming response', async () => {
    const http = await startHttp((response) => {
      response.writeHead(200)
      response.write(Buffer.alloc(MAX_UPNP_DEVICE_DESCRIPTION_BYTES + 1))
    })
    await expect(http.get()).rejects.toMatchObject({ code: 'UPNP_HTTP_RESPONSE_TOO_LARGE' })
    await expect.poll(() => http.sockets.size, { timeout: 500 }).toBe(0)
  })

  it.each(['before headers', 'during body'])('handles a peer disconnect %s without unhandled errors', async (phase) => {
    const http = await startHttp((response) => {
      if (phase === 'before headers') {
        response.socket?.destroy()
        return
      }
      response.writeHead(200, { 'Content-Length': '100' })
      response.write('partial')
      const abort = setTimeout(() => response.socket?.destroy(), 30)
      response.once('close', () => clearTimeout(abort))
    })
    await expect(http.get()).rejects.toMatchObject({ code: 'UPNP_HTTP_RESPONSE_INVALID' })
    await expect.poll(() => http.sockets.size, { timeout: 500 }).toBe(0)
  })

  it.each(['content-length', 'chunked'])('preserves a complete %s body at the size limit and releases the socket', async (framing) => {
    const body = Buffer.alloc(MAX_UPNP_DEVICE_DESCRIPTION_BYTES, 'x')
    const http = await startHttp((response) => {
      response.writeHead(200, {
        'Content-Encoding': 'identity',
        ...(framing === 'content-length' ? { 'Content-Length': String(body.length) } : {})
      })
      response.write(body.subarray(0, 100))
      response.end(body.subarray(100))
    })
    await expect(http.get()).resolves.toEqual(body)
    await expect.poll(() => http.sockets.size, { timeout: 500 }).toBe(0)
  })
})
