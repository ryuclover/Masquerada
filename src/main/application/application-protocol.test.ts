import { describe, expect, it, vi } from 'vitest'

import {
  APPLICATION_MESSAGE_TYPE,
  APPLICATION_VERSION,
  ApplicationProtocolError,
  createApplicationMessageId,
  decodeApplicationEnvelope,
  encodeApplicationEnvelope,
  MAX_APPLICATION_BODY_BYTES,
  MAX_APPLICATION_PAYLOAD_BYTES,
  type ApplicationEnvelope,
  type ServerState,
  type ServerStateResponsePayload
} from './application-protocol'

const messageId = '01'.repeat(16)
const serverId = `sha256:${'ab'.repeat(32)}`
const channelId = '02'.repeat(16)

function request(): ApplicationEnvelope {
  return {
    messageId, serverId, channelId: null, kind: 'request',
    messageType: 'server-state.request', correlationId: null, sequence: null, payload: {}
  }
}

function response(payload?: ServerStateResponsePayload): ApplicationEnvelope {
  const state: ServerState = { displayName: 'Server', channels: [{ channelId, name: 'General' }] }
  return {
    messageId, serverId, channelId: null, kind: 'response',
    messageType: 'server-state.response', correlationId: '03'.repeat(16), sequence: 1,
    payload: payload ?? { status: 'ok', server: { displayName: state.displayName }, channels: state.channels }
  }
}

function frame(body: string | Buffer): Buffer {
  const content = typeof body === 'string' ? Buffer.from(body, 'utf8') : body
  const header = Buffer.alloc(6)
  header[0] = APPLICATION_VERSION
  header[1] = APPLICATION_MESSAGE_TYPE
  header.writeUInt32BE(content.length, 2)
  return Buffer.concat([header, content])
}

function encode(value: unknown): Buffer {
  return encodeApplicationEnvelope(value as ApplicationEnvelope)
}

function rejectBoth(value: unknown): void {
  expect(() => encode(value)).toThrow(ApplicationProtocolError)
  expect(() => decodeApplicationEnvelope(frame(JSON.stringify(value)))).toThrow(ApplicationProtocolError)
}

function okPayload(displayName = 'Server', name = 'General'): ServerStateResponsePayload {
  return { status: 'ok', server: { displayName }, channels: [{ channelId, name }] }
}

describe('application protocol contract and canonical framing', () => {
  it('exports the agreed constants and error code', () => {
    expect(APPLICATION_VERSION).toBe(1)
    expect(APPLICATION_MESSAGE_TYPE).toBe(0x70)
    expect(MAX_APPLICATION_BODY_BYTES).toBe(40 * 1024)
    expect(MAX_APPLICATION_PAYLOAD_BYTES).toBe(32 * 1024)
    const error = new ApplicationProtocolError('TEST_CODE')
    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe('ApplicationProtocolError')
    expect(error.code).toBe('TEST_CODE')
  })

  it('creates fresh 16-byte lowercase hexadecimal message IDs', () => {
    const ids = Array.from({ length: 256 }, createApplicationMessageId)
    expect(new Set(ids).size).toBe(ids.length)
    for (const id of ids) expect(id).toMatch(/^[0-9a-f]{32}$/)
  })

  it.each([
    request(), response(), response({ status: 'error', code: 'UNAVAILABLE' }),
    response({ status: 'ok', server: { displayName: 'Empty' }, channels: [] }),
    { ...response(), sequence: Number.MAX_SAFE_INTEGER },
    response(okPayload('\u00e9\ud83d\ude00', '\u6f22\ud83d\ude00'))
  ])('roundtrips all supported envelopes: %#', (envelope) => {
    const bytes = encode(envelope)
    expect(bytes[0]).toBe(1)
    expect(bytes[1]).toBe(0x70)
    expect(bytes.readUInt32BE(2)).toBe(bytes.length - 6)
    expect(decodeApplicationEnvelope(bytes)).toEqual(envelope)
    expect(encodeApplicationEnvelope(decodeApplicationEnvelope(bytes))).toEqual(bytes)
  })

  it('sorts every object lexicographically regardless of insertion order', () => {
    const expected = `{"channelId":null,"correlationId":null,"kind":"request","messageId":"${messageId}","messageType":"server-state.request","payload":{},"sequence":null,"serverId":"${serverId}"}`
    expect(encode(request())).toEqual(frame(expected))
    const payload = okPayload()
    const envelope = response(payload)
    const reversed = Object.fromEntries(Object.entries(envelope).reverse())
    reversed.payload = { channels: [{ name: 'General', channelId }], server: { displayName: 'Server' }, status: 'ok' }
    expect(encode(reversed)).toEqual(encode(envelope))
    expect(encode(envelope).subarray(6).toString()).toContain(`"channels":[{"channelId":"${channelId}","name":"General"}]`)
  })

  it('accepts frozen and null-prototype data without retaining caller references', () => {
    const envelope = Object.freeze({ ...request(), payload: Object.freeze(Object.create(null)) })
    const decoded = decodeApplicationEnvelope(encode(envelope))
    expect(decoded).toEqual(request())
    expect(decoded).not.toBe(envelope)
    expect(decoded.payload).not.toBe(envelope.payload)
  })
})

describe('strict envelope and nested schemas', () => {
  it.each(Object.keys(request()))('requires property %s', (key) => {
    const value: Record<string, unknown> = { ...request() }
    delete value[key]
    rejectBoth(value)
  })

  it.each([
    null, [], true, 1, 'request', {},
    { ...request(), extra: 1 },
    { ...request(), kind: 'event' },
    { ...request(), kind: 'response' },
    { ...response(), kind: 'request' },
    { ...request(), messageType: 'server-state.event' },
    { ...request(), messageType: 'server-state.response' },
    { ...request(), correlationId: messageId },
    { ...request(), sequence: 1 },
    { ...request(), channelId },
    { ...request(), payload: { ignored: true } },
    { ...request(), payload: [] },
    { ...request(), payload: null },
    { ...response(), correlationId: null },
    { ...response(), payload: {} },
    { ...response(), payload: { status: 'error', code: 'UNKNOWN' } },
    { ...response(), payload: { status: 'error', code: 'UNAVAILABLE', server: {} } },
    { ...response(), payload: { status: 'ok', server: {}, channels: [] } },
    { ...response(), payload: { status: 'ok', server: { displayName: 'S', extra: 1 }, channels: [] } },
    { ...response(), payload: { status: 'ok', server: { displayName: 'S' }, channels: [], extra: 1 } },
    { ...response(), payload: { status: 'ok', server: { displayName: 'S' }, channels: {} } },
    { ...response(), payload: { status: 'ok', server: { displayName: 'S' }, channels: [{ channelId }] } },
    { ...response(), payload: { status: 'ok', server: { displayName: 'S' }, channels: [{ channelId, name: 'N', extra: 1 }] } }
  ])('rejects unsupported or inexact schema: %#', rejectBoth)

  it.each(['', 'a'.repeat(31), 'a'.repeat(33), 'A'.repeat(32), 'g'.repeat(32), 'a'.repeat(32) + '\n', 123, null])(
    'rejects malformed message, correlation and channel IDs: %#', (id) => {
      rejectBoth({ ...request(), messageId: id })
      rejectBoth({ ...response(), correlationId: id })
      rejectBoth({ ...response(), payload: { status: 'ok', server: { displayName: 'S' }, channels: [{ channelId: id, name: 'N' }] } })
    }
  )

  it.each(['', 'ab'.repeat(32), `sha256:${'A'.repeat(64)}`, `sha256:${'a'.repeat(63)}`, `sha256:${'a'.repeat(65)}`, serverId + '\n', null])(
    'rejects malformed server IDs: %#', (id) => rejectBoth({ ...request(), serverId: id })
  )

  it.each([null, '1', 0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1])('rejects invalid response sequence: %s', (sequence) => {
    rejectBoth({ ...response(), sequence })
  })

  it.each(['', '\u0000', '\n', '\t', '\u001f', '\u007f', '\u0085', '\u009f', '\ud800', '\udc00', '\ud800a', '\ud800\ud800'])('rejects invalid names: %#', (name) => {
    rejectBoth(response(okPayload(name)))
    rejectBoth(response(okPayload('Server', name)))
  })

  it.each([255, 256, 257])('bounds displayName at 256 UTF-8 bytes: %i', (size) => {
    const value = response(okPayload('a'.repeat(size)))
    if (size <= 256) expect(decodeApplicationEnvelope(encode(value))).toEqual(value)
    else rejectBoth(value)
  })

  it.each([127, 128, 129])('bounds channel names at 128 UTF-8 bytes: %i', (size) => {
    const value = response(okPayload('S', 'a'.repeat(size)))
    if (size <= 128) expect(decodeApplicationEnvelope(encode(value))).toEqual(value)
    else rejectBoth(value)
  })

  it('measures Unicode names in bytes, not code units', () => {
    const value = response(okPayload('\ud83d\ude00'.repeat(64), '\u00e9'.repeat(64)))
    expect(decodeApplicationEnvelope(encode(value))).toEqual(value)
    rejectBoth(response(okPayload('\ud83d\ude00'.repeat(64) + 'x')))
    rejectBoth(response(okPayload('S', '\u00e9'.repeat(64) + 'x')))
  })

  it.each([127, 128, 129])('bounds the sorted channel list at 128 entries: %i', (count) => {
    const channels = Array.from({ length: count }, (_, index) => ({ channelId: index.toString(16).padStart(32, '0'), name: 'N' }))
    const value = response({ status: 'ok', server: { displayName: 'S' }, channels })
    if (count <= 128) expect(decodeApplicationEnvelope(encode(value))).toEqual(value)
    else rejectBoth(value)
  })

  it('rejects duplicate or unsorted channels rather than silently sorting', () => {
    const first = { channelId: '00'.repeat(16), name: 'First' }
    const second = { channelId: 'ff'.repeat(16), name: 'Second' }
    for (const channels of [[first, first], [second, first]]) {
      rejectBoth(response({ status: 'ok', server: { displayName: 'S' }, channels }))
    }
  })
})

describe('malformed framing, UTF-8 and non-canonical JSON', () => {
  it.each([0, 1, 2, 3, 4, 5])('rejects truncated headers of %i bytes', (length) => {
    expect(() => decodeApplicationEnvelope(Buffer.alloc(length))).toThrow(ApplicationProtocolError)
  })

  it.each([-1, 1])('requires the exact declared length: delta %i', (delta) => {
    const bytes = encode(request())
    bytes.writeUInt32BE(bytes.readUInt32BE(2) + delta, 2)
    expect(() => decodeApplicationEnvelope(bytes)).toThrow(ApplicationProtocolError)
  })

  it('rejects wrong version, wrong type, truncation and appended frames', () => {
    const bytes = encode(request())
    for (const offset of [0, 1]) {
      const changed = Buffer.from(bytes)
      changed[offset] = 0
      expect(() => decodeApplicationEnvelope(changed)).toThrow(ApplicationProtocolError)
    }
    for (const changed of [bytes.subarray(0, -1), Buffer.concat([bytes, Buffer.from([0])]), Buffer.concat([bytes, bytes])]) {
      expect(() => decodeApplicationEnvelope(changed)).toThrow(ApplicationProtocolError)
    }
  })

  it.each([MAX_APPLICATION_BODY_BYTES - 1, MAX_APPLICATION_BODY_BYTES, MAX_APPLICATION_BODY_BYTES + 1])(
    'checks body byte limits before JSON parsing: %i', (size) => {
      const parse = vi.spyOn(JSON, 'parse')
      try {
        expect(() => decodeApplicationEnvelope(frame(Buffer.alloc(size, 0x20)))).toThrow(ApplicationProtocolError)
        expect(parse.mock.calls.length).toBe(size > MAX_APPLICATION_BODY_BYTES ? 0 : 1)
      } finally {
        parse.mockRestore()
      }
    }
  )

  it('rejects oversized declarations and actual buffers before parsing', () => {
    const bytes = encode(request())
    bytes.writeUInt32BE(0xffffffff, 2)
    const oversized = Buffer.alloc(MAX_APPLICATION_BODY_BYTES + 7)
    const parse = vi.spyOn(JSON, 'parse')
    try {
      expect(() => decodeApplicationEnvelope(bytes)).toThrow(ApplicationProtocolError)
      expect(() => decodeApplicationEnvelope(oversized)).toThrow(ApplicationProtocolError)
      expect(parse).not.toHaveBeenCalled()
    } finally {
      parse.mockRestore()
    }
  })

  it.each([
    [[0xc0, 0xaf]], [[0xc2]], [[0x80]], [[0xed, 0xa0, 0x80]], [[0xf4, 0x90, 0x80, 0x80]], [[0xff]]
  ])('rejects invalid UTF-8 even inside JSON strings: %#', (invalid: number[]) => {
    const body = encode(response()).subarray(6)
    const offset = body.indexOf('General')
    const corrupted = Buffer.concat([body.subarray(0, offset), Buffer.from(invalid), body.subarray(offset + 7)])
    expect(() => decodeApplicationEnvelope(frame(corrupted))).toThrow(ApplicationProtocolError)
  })

  it('rejects BOM instead of silently stripping it', () => {
    expect(() => decodeApplicationEnvelope(frame(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), encode(request()).subarray(6)])))).toThrow(ApplicationProtocolError)
  })

  it.each(['', '{', 'null', '[]', '{}', '{"x":undefined}', '{"x":NaN}'])('rejects malformed JSON or body: %s', (body) => {
    expect(() => decodeApplicationEnvelope(frame(body))).toThrow(ApplicationProtocolError)
  })

  it('rejects duplicate keys, alternate escapes, key order, whitespace and trailing JSON', () => {
    const body = encode(response()).subarray(6).toString('utf8')
    const variants = [
      body.replace('"channelId":null', '"channelId":null,"channelId":null'),
      body.replace('"displayName":"Server"', '"displayName":"Other","displayName":"Server"'),
      body.replace('"status":"ok"', '"status":"ok","status":"ok"'),
      body.replace('"name":"General"', '"name":"General","name":"General"'),
      body.replace('Server', '\\u0053erver'),
      body.replace('"kind"', '"\\u006bind"'),
      body.replace('"sequence":1', '"sequence":1.0'),
      body.replace('"sequence":1', '"sequence":1e0'),
      JSON.stringify(response()),
      ` ${body}`, `${body}\n`, `${body}{}`, body.replace(':null', ': null')
    ]
    for (const variant of variants) expect(() => decodeApplicationEnvelope(frame(variant))).toThrow(ApplicationProtocolError)
    const slash = encode(response(okPayload('a/b'))).subarray(6).toString()
    expect(() => decodeApplicationEnvelope(frame(slash.replace('a/b', 'a\\/b')))).toThrow(ApplicationProtocolError)
  })
})

describe('hostile encoder inputs and bounded traversal', () => {
  it.each([undefined, () => 1, Symbol('x'), 1n, NaN, Infinity, -Infinity, -0, Number.MAX_SAFE_INTEGER + 1])(
    'rejects non-JSON or unsafe values before serialization: %#', (value) => {
      expect(() => encode({ ...request(), payload: { value } })).toThrow(ApplicationProtocolError)
    }
  )

  it('never invokes getters, including toJSON and array element accessors', () => {
    const getter = vi.fn(() => { throw new Error('Getter invoked') })
    const top = Object.defineProperty(request(), 'messageId', { get: getter })
    const payload = Object.defineProperty({}, 'toJSON', { get: getter, enumerable: true })
    const channels = Object.defineProperty([], '0', { get: getter, enumerable: true })
    const server = Object.defineProperty({}, 'displayName', { get: getter, enumerable: true })
    for (const value of [top, { ...request(), payload }, { ...response(), payload: { status: 'ok', server, channels: [] } }, { ...response(), payload: { status: 'ok', server: { displayName: 'S' }, channels } }]) {
      expect(() => encode(value)).toThrow(ApplicationProtocolError)
    }
    expect(getter).not.toHaveBeenCalled()
  })

  it('never invokes toJSON methods or proxy traps', () => {
    const toJSON = vi.fn(() => ({}))
    const trap = vi.fn(() => { throw new Error('Proxy trap invoked') })
    const proxy = new Proxy({}, { get: trap, getPrototypeOf: trap, ownKeys: trap, getOwnPropertyDescriptor: trap })
    const revoked = Proxy.revocable({}, {})
    revoked.revoke()
    for (const payload of [{ toJSON }, proxy, revoked.proxy, Object.create({ toJSON })]) {
      expect(() => encode({ ...request(), payload })).toThrow(ApplicationProtocolError)
    }
    expect(toJSON).not.toHaveBeenCalled()
    expect(trap).not.toHaveBeenCalled()
  })

  it.each([new Date(), new Map(), new Set(), Buffer.alloc(0), new Number(1), /x/, Object.create({ inherited: true })])(
    'rejects exotic prototypes: %#', (payload) => {
      expect(() => encode({ ...request(), payload })).toThrow(ApplicationProtocolError)
    }
  )

  it('rejects hidden and symbol properties, sparse arrays and array extras', () => {
    const hidden = Object.defineProperty({}, 'hidden', { value: 1 })
    const symbol = { [Symbol('hidden')]: 1 }
    const sparse = new Array(2)
    const extra = Object.assign([], { extra: 1 })
    const exotic = Object.setPrototypeOf([], null)
    for (const payload of [hidden, symbol, sparse, extra, exotic]) {
      expect(() => encode({ ...request(), payload })).toThrow(ApplicationProtocolError)
    }
  })

  it('rejects prototype-pollution keys at every object level without pollution', () => {
    const body = encode(response()).subarray(6).toString()
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      for (const target of ['"channelId":null', '"status":"ok"', '"displayName":"Server"', '"name":"General"']) {
        const polluted = body.replace(target, `${target},"${key}":{"polluted":true}`)
        expect(() => decodeApplicationEnvelope(frame(polluted))).toThrow(ApplicationProtocolError)
        expect(() => encode(JSON.parse(polluted))).toThrow(ApplicationProtocolError)
      }
    }
    expect(Object.hasOwn(Object.prototype, 'polluted')).toBe(false)
  })

  it('rejects cycles without overflowing the stack', () => {
    const payload: Record<string, unknown> = {}
    payload.self = payload
    expect(() => encode({ ...request(), payload })).toThrow(ApplicationProtocolError)
    const array: unknown[] = []
    array.push(array)
    expect(() => encode({ ...request(), payload: array })).toThrow(ApplicationProtocolError)
  })

  it('bounds traversal before reaching deeper accessors or recursive serialization', () => {
    const getter = vi.fn(() => { throw new Error('Deep getter invoked') })
    let deep: unknown = Object.defineProperty({}, 'value', { get: getter, enumerable: true })
    for (let index = 0; index < 20000; index++) deep = { child: deep }
    expect(() => encode({ ...request(), payload: deep })).toThrow(ApplicationProtocolError)
    expect(getter).not.toHaveBeenCalled()
    const body = '['.repeat(10000) + '0' + ']'.repeat(10000)
    expect(() => decodeApplicationEnvelope(frame(body))).toThrow(ApplicationProtocolError)
  })

  it('enforces depth 8 before inspecting the ninth level', () => {
    const trap = vi.fn(() => { throw new Error('Visited beyond depth limit') })
    let value: unknown = new Proxy({}, { ownKeys: trap })
    for (let depth = 0; depth < 8; depth++) value = [value]
    expect(() => encode(value)).toThrow(ApplicationProtocolError)
    expect(trap).not.toHaveBeenCalled()
  })

  it('bounds wide objects and sparse lengths before inspecting child descriptors', () => {
    const getter = vi.fn(() => { throw new Error('Wide getter invoked') })
    const wide = Object.defineProperty({}, 'first', { get: getter, enumerable: true })
    for (let index = 0; index < 2048; index++) Object.defineProperty(wide, String(index), { value: null, enumerable: true })
    expect(() => encode({ ...request(), payload: wide })).toThrow(ApplicationProtocolError)
    expect(getter).not.toHaveBeenCalled()
    expect(() => encode({ ...request(), payload: new Array(0xffffffff) })).toThrow(ApplicationProtocolError)
    expect(() => decodeApplicationEnvelope(frame(`[${Array.from({ length: 2049 }, () => '0').join(',')}]`))).toThrow(ApplicationProtocolError)
  })

  it('limits total nodes even when each individual object is small', () => {
    const tree = Array.from({ length: 64 }, () => Array.from({ length: 32 }, () => 0))
    expect(() => encode({ ...request(), payload: tree })).toThrow(ApplicationProtocolError)
    expect(() => decodeApplicationEnvelope(frame(JSON.stringify({ ...request(), payload: tree })))).toThrow(ApplicationProtocolError)
  })

  it('counts escaped canonical payload bytes at limit minus one, limit and limit plus one', () => {
    const channels = Array.from({ length: 128 }, (_, index) => ({ channelId: index.toString(16).padStart(32, '0'), name: '"'.repeat(128) }))
    const payload = { status: 'ok' as const, server: { displayName: 'S' }, channels }
    const excess = Buffer.byteLength(JSON.stringify(payload)) - MAX_APPLICATION_PAYLOAD_BYTES
    // Replacing a quote with ASCII saves one canonical byte without changing name length.
    for (let index = 0; index < excess; index++) {
      const channel = channels[Math.floor(index / 128)]!
      channel.name = channel.name.replace('"', 'a')
    }
    for (const delta of [-1, 0, 1]) {
      const adjusted = channels.map((channel) => ({ ...channel }))
      if (delta === -1) adjusted[127]!.name = adjusted[127]!.name.replace('"', 'a')
      if (delta === 1) adjusted[0]!.name = adjusted[0]!.name.replace('a', '"')
      const value = response({ ...payload, channels: adjusted })
      expect(Buffer.byteLength(JSON.stringify(value.payload))).toBe(MAX_APPLICATION_PAYLOAD_BYTES + delta)
      if (delta <= 0) expect(decodeApplicationEnvelope(encode(value))).toEqual(value)
      else rejectBoth(value)
    }
  })
})
