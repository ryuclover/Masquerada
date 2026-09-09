import { describe, expect, it } from 'vitest'

import {
  encodeProtocolFrame,
  HEADER_LENGTH,
  MAX_DECODER_BUFFER_BYTES,
  MAX_FRAME_PAYLOAD_BYTES,
  ProtocolError,
  type ProtocolErrorCode,
  type ProtocolFrame,
  ProtocolFrameDecoder,
  ProtocolFrameType,
  PROTOCOL_MAGIC,
  PROTOCOL_VERSION
} from './protocol-frame'

const FRAME_TYPES = [
  ProtocolFrameType.HANDSHAKE,
  ProtocolFrameType.SESSION,
  ProtocolFrameType.HEARTBEAT,
  ProtocolFrameType.KEY_EXCHANGE
]
const SEEDS = Array.from({ length: 256 }, (_, index) => index + 1)
const BYTE_VALUES = Array.from({ length: 256 }, (_, index) => index)

function seededRandom(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state
  }
}

function* chunks(buffer: Buffer, seed: number, maximum: number): Generator<Buffer> {
  const next = seededRandom(seed)
  for (let offset = 0; offset < buffer.length; ) {
    const end = Math.min(buffer.length, offset + 1 + (next() % maximum))
    yield buffer.subarray(offset, end)
    offset = end
  }
}

function expectProtocolError(operation: () => unknown, code: ProtocolErrorCode): void {
  try {
    operation()
  } catch (error) {
    expect(error).toBeInstanceOf(ProtocolError)
    expect((error as ProtocolError).code).toBe(code)
    return
  }
  expect.unreachable(`Expected ${code}`)
}

describe('ProtocolFrameDecoder deterministic properties', () => {
  it.each(SEEDS)('delivers ordered, byte-identical frames exactly once (seed %i)', (seed) => {
    const next = seededRandom(seed)
    const lengths = [0, 1, 11, 12, 13, 255, 256, 1023]
    for (let index = 0; index < 8; index++) lengths.push(next() % 2049)
    if (seed % 32 === 0) lengths.push(MAX_FRAME_PAYLOAD_BYTES - 1, MAX_FRAME_PAYLOAD_BYTES)

    const expected = lengths.map((length, index) => {
      const payload = Buffer.alloc(length)
      for (let byte = 0; byte < length; byte++) payload[byte] = next() >>> 24
      return { type: FRAME_TYPES[index % FRAME_TYPES.length]!, payload }
    })
    const encoded = expected.map((frame) => encodeProtocolFrame(frame))
    const stream = Buffer.concat(encoded)
    let frameEnd = 0
    const frameEnds = encoded.map((frame) => (frameEnd += frame.length))
    const decoder = new ProtocolFrameDecoder()
    const delivered: ProtocolFrame[] = []
    let received = 0

    for (const chunk of chunks(stream, seed ^ 0x712cafe, 17 + (seed % 4096))) {
      delivered.push(...decoder.push(chunk))
      received += chunk.length
      expect(delivered.length, `seed=${seed}, received=${received}`).toBe(
        frameEnds.filter((end) => end <= received).length
      )
      if (next() % 7 === 0) expect(decoder.push(Buffer.alloc(0))).toEqual([])
    }

    expect(delivered).toHaveLength(expected.length)
    delivered.forEach((frame, index) => {
      expect(frame.version).toBe(PROTOCOL_VERSION)
      expect(frame.flags).toBe(0)
      expect(frame.type).toBe(expected[index]!.type)
      expect(frame.payload.equals(expected[index]!.payload), `seed=${seed}, frame=${index}`).toBe(true)
    })
    expect(decoder.push(Buffer.alloc(0))).toEqual([])
    expect(() => decoder.finish()).not.toThrow()
    expect(decoder.isInvalidated()).toBe(false)
  })

  it.each(FRAME_TYPES)('rejects every incomplete prefix after a valid frame (type %i)', (type) => {
    const prefixPayload = Buffer.from([0x00, 0xff, type])
    const prefix = encodeProtocolFrame({ type, payload: prefixPayload })

    for (const length of [0, 1, 13, 257]) {
      const encoded = encodeProtocolFrame({ type, payload: Buffer.alloc(length, type) })
      // Empty input and cuts at frame boundaries are valid, not truncations.
      for (let cut = 1; cut < encoded.length; cut++) {
        const decoder = new ProtocolFrameDecoder()
        const delivered: ProtocolFrame[] = []
        const stream = Buffer.concat([prefix, encoded.subarray(0, cut)])
        for (const chunk of chunks(stream, type * 65536 + length * 512 + cut, 64)) {
          delivered.push(...decoder.push(chunk))
        }

        expect(delivered, `type=${type}, length=${length}, cut=${cut}`).toHaveLength(1)
        expect(delivered[0]!.payload.equals(prefixPayload)).toBe(true)
        expect(decoder.isInvalidated()).toBe(false)
        expectProtocolError(() => decoder.finish(), 'PROTOCOL_FRAME_TRUNCATED')
        expect(decoder.isInvalidated()).toBe(true)
        expectProtocolError(() => decoder.push(encoded.subarray(cut)), 'PROTOCOL_DECODER_FAILED')
        expectProtocolError(() => decoder.finish(), 'PROTOCOL_DECODER_FAILED')
      }
    }
  })

  const nextLength = seededRandom(0x712bad)
  const malformedFields = [
    ...Array.from(PROTOCOL_MAGIC, (byte, offset) => ({
      name: `magic[${offset}]`,
      offset,
      width: 1,
      values: BYTE_VALUES.filter((value) => value !== byte),
      code: 'PROTOCOL_INVALID_MAGIC' as const
    })),
    {
      name: 'version',
      offset: 4,
      width: 1,
      values: BYTE_VALUES.filter((value) => value !== PROTOCOL_VERSION),
      code: 'PROTOCOL_VERSION_UNSUPPORTED'
    },
    {
      name: 'type',
      offset: 5,
      width: 1,
      values: BYTE_VALUES.filter((value) => !FRAME_TYPES.includes(value)),
      code: 'PROTOCOL_FRAME_TYPE_UNSUPPORTED'
    },
    {
      name: 'flags',
      offset: 6,
      width: 2,
      values: [...Array.from({ length: 16 }, (_, bit) => 2 ** bit), 0xffff],
      code: 'PROTOCOL_FLAGS_UNSUPPORTED'
    },
    {
      name: 'length',
      offset: 8,
      width: 4,
      values: [
        MAX_FRAME_PAYLOAD_BYTES + 1,
        MAX_FRAME_PAYLOAD_BYTES + 2,
        MAX_DECODER_BUFFER_BYTES,
        0x7fffffff,
        0x80000000,
        0xffffffff,
        ...Array.from({ length: 64 }, () => MAX_FRAME_PAYLOAD_BYTES + 1 +
          (nextLength() % (0xffffffff - MAX_FRAME_PAYLOAD_BYTES)))
      ],
      code: 'PROTOCOL_FRAME_TOO_LARGE'
    }
  ] satisfies Array<{
    name: string
    offset: number
    width: number
    values: number[]
    code: ProtocolErrorCode
  }>

  it.each(malformedFields)('never accepts malformed $name across header splits', (field) => {
    const valid = encodeProtocolFrame({ type: ProtocolFrameType.HEARTBEAT })
    for (const value of field.values) {
      const header = Buffer.from(valid)
      header.writeUIntBE(value, field.offset, field.width)
      const next = seededRandom(value ^ field.offset)
      for (const split of [0, 1 + (next() % (HEADER_LENGTH - 2)), HEADER_LENGTH - 1]) {
        const decoder = new ProtocolFrameDecoder()
        expect(decoder.push(header.subarray(0, split))).toEqual([])
        expect(decoder.isInvalidated()).toBe(false)
        // A complete invalid header must fail even without its advertised payload.
        // Alternating a valid suffix also checks that it cannot resynchronize.
        const tail = split === 0
          ? header
          : Buffer.concat([header.subarray(split), valid])
        expectProtocolError(() => decoder.push(tail), field.code)
        expect(decoder.isInvalidated()).toBe(true)
        expectProtocolError(() => decoder.push(Buffer.alloc(0)), 'PROTOCOL_DECODER_FAILED')
        expectProtocolError(() => decoder.push(valid), 'PROTOCOL_DECODER_FAILED')
        expectProtocolError(() => decoder.finish(), 'PROTOCOL_DECODER_FAILED')
      }
    }
  })

  it.each([-1, 0, 1])('enforces buffered bytes plus chunk at limit offset %i', (delta) => {
    const expected = FRAME_TYPES.slice(0, 3).map((type) => ({
      type,
      payload: Buffer.alloc(MAX_FRAME_PAYLOAD_BYTES, type)
    }))
    const encoded = expected.map((frame) => encodeProtocolFrame(frame))
    const stream = Buffer.concat(encoded)
    const frameLength = HEADER_LENGTH + MAX_FRAME_PAYLOAD_BYTES
    const next = seededRandom(0x712b0ff)
    const pendingLengths = [
      0, 1, HEADER_LENGTH - 1, HEADER_LENGTH, frameLength - 1,
      ...Array.from({ length: 16 }, () => 1 + (next() % (frameLength - 1)))
    ]

    for (const pending of pendingLengths) {
      const decoder = new ProtocolFrameDecoder()
      expect(decoder.push(stream.subarray(0, pending))).toEqual([])
      const end = MAX_DECODER_BUFFER_BYTES + delta
      const chunk = stream.subarray(pending, end)
      if (delta > 0) {
        // Complete frames in the chunk do not bypass the pre-extraction limit.
        expectProtocolError(() => decoder.push(chunk), 'PROTOCOL_FRAME_TOO_LARGE')
        expect(decoder.isInvalidated()).toBe(true)
        expectProtocolError(() => decoder.push(encoded[0]!), 'PROTOCOL_DECODER_FAILED')
        expectProtocolError(() => decoder.finish(), 'PROTOCOL_DECODER_FAILED')
      } else {
        const delivered = decoder.push(chunk)
        expect(delivered).toHaveLength(Math.floor(end / frameLength))
        delivered.push(...decoder.push(stream.subarray(end)))
        expect(delivered).toHaveLength(expected.length)
        delivered.forEach((frame, index) => {
          expect(frame.type).toBe(expected[index]!.type)
          expect(frame.payload.equals(expected[index]!.payload)).toBe(true)
        })
        expect(() => decoder.finish()).not.toThrow()
        expect(decoder.isInvalidated()).toBe(false)
      }
    }
  })
})
