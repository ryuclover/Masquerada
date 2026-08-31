import { describe, expect, it } from 'vitest'

import {
  createStunBindingRequest,
  MAX_STUN_DATAGRAM_BYTES,
  parseStunBindingResponse,
  STUN_ATTRIBUTE_FINGERPRINT,
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
  STUN_BINDING_ERROR_RESPONSE,
  STUN_BINDING_REQUEST,
  STUN_BINDING_SUCCESS_RESPONSE,
  STUN_FINGERPRINT_XOR,
  STUN_HEADER_BYTES,
  STUN_MAGIC_COOKIE,
  stunProtocolTestOnly
} from './stun-protocol'

const TX = Buffer.from('00112233445566778899aabb', 'hex')

function attribute(type: number, value: Buffer, paddingByte = 0): Buffer {
  const padded = (value.length + 3) & ~3
  const encoded = Buffer.alloc(4 + padded, paddingByte)
  encoded.writeUInt16BE(type, 0)
  encoded.writeUInt16BE(value.length, 2)
  value.copy(encoded, 4)
  return encoded
}

function xorMappedIpv4(address: string, port: number): Buffer {
  const value = Buffer.alloc(8)
  value[1] = 0x01
  value.writeUInt16BE(port ^ (STUN_MAGIC_COOKIE >>> 16), 2)
  const cookie = Buffer.alloc(4)
  cookie.writeUInt32BE(STUN_MAGIC_COOKIE)
  address.split('.').map(Number).forEach((octet, index) => {
    value[index + 4] = octet ^ cookie[index]!
  })
  return attribute(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, value)
}

function ipv6Bytes(words: readonly number[]): Buffer {
  const result = Buffer.alloc(16)
  words.forEach((word, index) => result.writeUInt16BE(word, index * 2))
  return result
}

function xorMappedIpv6(words: readonly number[], port: number, transactionId = TX): Buffer {
  const value = Buffer.alloc(20)
  value[1] = 0x02
  value.writeUInt16BE(port ^ (STUN_MAGIC_COOKIE >>> 16), 2)
  const mask = Buffer.alloc(16)
  mask.writeUInt32BE(STUN_MAGIC_COOKIE)
  transactionId.copy(mask, 4)
  const address = ipv6Bytes(words)
  for (let index = 0; index < 16; index += 1) value[index + 4] = address[index]! ^ mask[index]!
  return attribute(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, value)
}

function response(
  attributes: readonly Buffer[],
  options: { type?: number; transactionId?: Buffer; fingerprint?: boolean } = {}
): Buffer {
  const type = options.type ?? STUN_BINDING_SUCCESS_RESPONSE
  const baseBody = Buffer.concat(attributes)
  const includeFingerprint = options.fingerprint === true
  const bodyLength = baseBody.length + (includeFingerprint ? 8 : 0)
  const header = Buffer.alloc(STUN_HEADER_BYTES)
  header.writeUInt16BE(type, 0)
  header.writeUInt16BE(bodyLength, 2)
  header.writeUInt32BE(STUN_MAGIC_COOKIE, 4)
  ;(options.transactionId ?? TX).copy(header, 8)
  const beforeFingerprint = Buffer.concat([header, baseBody])
  if (!includeFingerprint) return beforeFingerprint
  const value = Buffer.alloc(4)
  value.writeUInt32BE(
    (stunProtocolTestOnly.crc32(beforeFingerprint) ^ STUN_FINGERPRINT_XOR) >>> 0
  )
  return Buffer.concat([beforeFingerprint, attribute(STUN_ATTRIBUTE_FINGERPRINT, value)])
}

describe('STUN RFC 8489 codec bounded', () => {
  it('gera Binding Request byte-exact com cookie, transaction ID e FINGERPRINT final', () => {
    const request = createStunBindingRequest(TX)
    expect(request).toHaveLength(28)
    expect(request.readUInt16BE(0)).toBe(STUN_BINDING_REQUEST)
    expect(request.readUInt16BE(2)).toBe(8)
    expect(request.readUInt32BE(4)).toBe(STUN_MAGIC_COOKIE)
    expect(request.subarray(8, 20)).toEqual(TX)
    expect(request.readUInt16BE(20)).toBe(STUN_ATTRIBUTE_FINGERPRINT)
    expect(request.readUInt16BE(22)).toBe(4)
    expect(request.readUInt32BE(24)).toBe(
      (stunProtocolTestOnly.crc32(request.subarray(0, 20)) ^ STUN_FINGERPRINT_XOR) >>> 0
    )
  })

  it('reutiliza deterministicamente bytes para o mesmo transaction ID', () => {
    expect(createStunBindingRequest(TX)).toEqual(createStunBindingRequest(TX))
    expect(createStunBindingRequest(Buffer.alloc(12, 1))).not.toEqual(createStunBindingRequest(TX))
  })

  it('decodifica XOR-MAPPED-ADDRESS IPv4 e classifica endereço observado', () => {
    const decoded = parseStunBindingResponse(response([xorMappedIpv4('203.0.114.9', 55000)]), TX)
    expect(decoded).toEqual({
      kind: 'success', observedAddress: '203.0.114.9', observedPort: 55000,
      family: 4, observedScope: 'GLOBAL', hasFingerprint: false
    })
  })

  it('decodifica XOR-MAPPED-ADDRESS IPv6 com cookie || transaction ID', () => {
    const decoded = parseStunBindingResponse(response([
      xorMappedIpv6([0x2600, 0, 0, 0, 0, 0, 0, 0x1234], 49152)
    ], { fingerprint: true }), TX)
    expect(decoded).toMatchObject({
      observedAddress: '2600::1234', observedPort: 49152,
      family: 6, observedScope: 'GLOBAL', hasFingerprint: true
    })
  })

  it('representa observações CGNAT e privadas sem promovê-las', () => {
    expect(parseStunBindingResponse(response([xorMappedIpv4('100.64.1.2', 5000)]), TX).observedScope)
      .toBe('CGNAT')
    expect(parseStunBindingResponse(response([xorMappedIpv4('192.168.1.2', 5000)]), TX).observedScope)
      .toBe('LAN_PRIVATE')
  })

  it('rejeita cookie, transaction ID e message type incorretos', () => {
    const valid = response([xorMappedIpv4('203.0.114.9', 55000)])
    const badCookie = Buffer.from(valid)
    badCookie.writeUInt32BE(0, 4)
    expect(() => parseStunBindingResponse(badCookie, TX)).toThrowError(expect.objectContaining({ code: 'STUN_RESPONSE_INVALID' }))
    expect(() => parseStunBindingResponse(valid, Buffer.alloc(12, 9))).toThrowError(expect.objectContaining({ code: 'STUN_TRANSACTION_MISMATCH' }))
    const wrongType = Buffer.from(valid)
    wrongType.writeUInt16BE(0x0102, 0)
    expect(() => parseStunBindingResponse(wrongType, TX)).toThrowError(expect.objectContaining({ code: 'STUN_RESPONSE_INVALID' }))
  })

  it.each([
    Buffer.alloc(19),
    Buffer.alloc(MAX_STUN_DATAGRAM_BYTES + 1),
    (() => { const b = response([xorMappedIpv4('203.0.114.9', 5000)]); b.writeUInt16BE(b.length, 2); return b })(),
    (() => { const b = response([xorMappedIpv4('203.0.114.9', 5000)]); b.writeUInt16BE(0, 2); return b })(),
    (() => { const b = response([xorMappedIpv4('203.0.114.9', 5000)]); b.writeUInt16BE(1, 2); return b })()
  ])('rejeita datagram length inválido/oversized', (datagram) => {
    expect(() => parseStunBindingResponse(datagram, TX)).toThrow()
  })

  it('exige exatamente um XOR-MAPPED-ADDRESS e não aceita MAPPED-ADDRESS legado', () => {
    expect(() => parseStunBindingResponse(response([]), TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_XOR_MAPPED_ADDRESS_INVALID' })
    )
    const mappedLegacy = attribute(0x0001, Buffer.alloc(8))
    expect(() => parseStunBindingResponse(response([mappedLegacy]), TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_XOR_MAPPED_ADDRESS_INVALID' })
    )
    const xor = xorMappedIpv4('203.0.114.9', 5000)
    expect(() => parseStunBindingResponse(response([xor, xor]), TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_XOR_MAPPED_ADDRESS_INVALID' })
    )
  })

  it('rejeita family desconhecida e observed port zero', () => {
    const badFamily = Buffer.alloc(8)
    badFamily[1] = 3
    badFamily.writeUInt16BE(5000 ^ (STUN_MAGIC_COOKIE >>> 16), 2)
    expect(() => parseStunBindingResponse(response([
      attribute(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, badFamily)
    ]), TX)).toThrowError(expect.objectContaining({ code: 'STUN_XOR_MAPPED_ADDRESS_INVALID' }))

    expect(() => parseStunBindingResponse(response([xorMappedIpv4('203.0.114.9', 0)]), TX))
      .toThrowError(expect.objectContaining({ code: 'STUN_XOR_MAPPED_ADDRESS_INVALID' }))
  })

  it('respeita padding de TLV e rejeita padding truncado', () => {
    const optionalWithPadding = attribute(0x8001, Buffer.from([1, 2, 3]), 0xaa)
    expect(parseStunBindingResponse(response([
      optionalWithPadding, xorMappedIpv4('203.0.114.9', 5000)
    ]), TX).observedAddress).toBe('203.0.114.9')

    const truncated = response([optionalWithPadding, xorMappedIpv4('203.0.114.9', 5000)]).subarray(0, -1)
    truncated.writeUInt16BE(truncated.length - 20, 2)
    expect(() => parseStunBindingResponse(truncated, TX)).toThrow()
  })

  it('falha em unknown comprehension-required e ignora optional bounded', () => {
    expect(() => parseStunBindingResponse(response([
      attribute(0x1234, Buffer.alloc(0)), xorMappedIpv4('203.0.114.9', 5000)
    ]), TX)).toThrowError(expect.objectContaining({ code: 'STUN_UNSUPPORTED_ATTRIBUTE' }))
    expect(parseStunBindingResponse(response([
      attribute(0x9234, Buffer.from('optional')), xorMappedIpv4('203.0.114.9', 5000)
    ]), TX).observedPort).toBe(5000)
  })

  it('aceita FINGERPRINT válido, rejeita inválido, duplicado ou não-final', () => {
    const valid = response([xorMappedIpv4('203.0.114.9', 5000)], { fingerprint: true })
    expect(parseStunBindingResponse(valid, TX).hasFingerprint).toBe(true)
    const corrupted = Buffer.from(valid)
    corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1
    expect(() => parseStunBindingResponse(corrupted, TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_FINGERPRINT_INVALID' })
    )
    const fp = valid.subarray(-8)
    expect(() => parseStunBindingResponse(response([
      xorMappedIpv4('203.0.114.9', 5000), fp, fp
    ]), TX)).toThrowError(expect.objectContaining({ code: 'STUN_FINGERPRINT_INVALID' }))
    expect(() => parseStunBindingResponse(response([
      fp, xorMappedIpv4('203.0.114.9', 5000)
    ]), TX)).toThrowError(expect.objectContaining({ code: 'STUN_FINGERPRINT_INVALID' }))
  })

  it('aceita response sem FINGERPRINT quando restante é válido', () => {
    expect(parseStunBindingResponse(response([xorMappedIpv4('203.0.114.9', 5000)]), TX).hasFingerprint)
      .toBe(false)
  })

  it('produz erro bounded para error response e não inicia credential flow', () => {
    const errorValue = (code: number, reason = 'error') => {
      const value = Buffer.alloc(4 + Buffer.byteLength(reason))
      value[2] = Math.floor(code / 100)
      value[3] = code % 100
      value.write(reason, 4)
      return value
    }
    expect(() => parseStunBindingResponse(response([
      attribute(0x0009, errorValue(401, 'Unauthorized'))
    ], { type: STUN_BINDING_ERROR_RESPONSE }), TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_AUTH_REQUIRED', responseCode: 401 })
    )
    expect(() => parseStunBindingResponse(response([
      attribute(0x0009, errorValue(300, 'Try Alternate')),
      attribute(0x8023, Buffer.alloc(8))
    ], { type: STUN_BINDING_ERROR_RESPONSE }), TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_SERVER_ERROR', responseCode: 300 })
    )
  })

  it('limita quantidade de attributes', () => {
    const optional = Array.from({ length: 33 }, () => attribute(0x8001, Buffer.alloc(0)))
    expect(() => parseStunBindingResponse(response(optional), TX)).toThrowError(
      expect.objectContaining({ code: 'STUN_RESPONSE_INVALID' })
    )
  })

  it('fuzz-like: truncamentos e bytes pseudoaleatórios nunca produzem observation', () => {
    const valid = response([xorMappedIpv4('203.0.114.9', 5000)])
    for (let length = 0; length < valid.length; length += 1) {
      expect(() => parseStunBindingResponse(valid.subarray(0, length), TX)).toThrow()
    }
    for (let length = 0; length < 128; length += 7) {
      const bytes = Buffer.alloc(length)
      for (let index = 0; index < length; index += 1) bytes[index] = (index * 73 + length) & 0xff
      expect(() => parseStunBindingResponse(bytes, TX)).toThrow()
    }
  })
})
