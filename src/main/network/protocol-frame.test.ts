import { randomBytes } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
  decodeSingleProtocolFrame,
  encodeProtocolFrame,
  HEADER_LENGTH,
  MAX_FRAME_PAYLOAD_BYTES,
  ProtocolError,
  type ProtocolErrorCode,
  ProtocolFrameDecoder,
  ProtocolFrameType,
  PROTOCOL_MAGIC,
  PROTOCOL_VERSION
} from './protocol-frame'

describe('protocolo binário e framing seguro P2P', () => {
  describe('encoder e decoder de frame único', () => {
    it('codifica e decodifica frame com payload pequeno', () => {
      const payload = Buffer.from('hello world masquerada', 'utf8')
      const encoded = encodeProtocolFrame({
        type: ProtocolFrameType.HANDSHAKE,
        payload
      })

      expect(encoded.length).toBe(HEADER_LENGTH + payload.length)
      expect(encoded.subarray(0, 4)).toEqual(PROTOCOL_MAGIC)
      expect(encoded.readUInt8(4)).toBe(PROTOCOL_VERSION)
      expect(encoded.readUInt8(5)).toBe(ProtocolFrameType.HANDSHAKE)
      expect(encoded.readUInt16BE(6)).toBe(0)
      expect(encoded.readUInt32BE(8)).toBe(payload.length)

      const decoded = decodeSingleProtocolFrame(encoded)
      expect(decoded.version).toBe(PROTOCOL_VERSION)
      expect(decoded.type).toBe(ProtocolFrameType.HANDSHAKE)
      expect(decoded.flags).toBe(0)
      expect(decoded.payload).toEqual(payload)
    })

    it('codifica e decodifica frame com payload vazio (zero-length payload)', () => {
      const encoded = encodeProtocolFrame({
        type: ProtocolFrameType.HEARTBEAT
      })

      expect(encoded.length).toBe(HEADER_LENGTH)
      expect(encoded.readUInt32BE(8)).toBe(0)

      const decoded = decodeSingleProtocolFrame(encoded)
      expect(decoded.version).toBe(PROTOCOL_VERSION)
      expect(decoded.type).toBe(ProtocolFrameType.HEARTBEAT)
      expect(decoded.payload.length).toBe(0)
    })

    it('codifica e decodifica frame com payload no limite máximo (64 KB)', () => {
      const maxPayload = Buffer.alloc(MAX_FRAME_PAYLOAD_BYTES, 0xab)
      const encoded = encodeProtocolFrame({
        type: ProtocolFrameType.SESSION,
        payload: maxPayload
      })

      expect(encoded.length).toBe(HEADER_LENGTH + MAX_FRAME_PAYLOAD_BYTES)
      const decoded = decodeSingleProtocolFrame(encoded)
      expect(decoded.payload).toEqual(maxPayload)
    })

    it('codifica e decodifica frame de KEY_EXCHANGE', () => {
      const payload = Buffer.from('key exchange payload', 'utf8')
      const encoded = encodeProtocolFrame({
        type: ProtocolFrameType.KEY_EXCHANGE,
        payload
      })

      expect(encoded.readUInt8(5)).toBe(ProtocolFrameType.KEY_EXCHANGE)
      const decoded = decodeSingleProtocolFrame(encoded)
      expect(decoded.type).toBe(ProtocolFrameType.KEY_EXCHANGE)
      expect(decoded.payload).toEqual(payload)
    })

    it('produz encoding determinístico e canônico', () => {
      const payload = Buffer.from('deterministic test', 'utf8')
      const first = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload })
      const second = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload })

      expect(first).toEqual(second)
    })

    it('garante imutabilidade do payload retornado', () => {
      const payload = Buffer.from('immutable payload', 'utf8')
      const encoded = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload })
      const decoded = decodeSingleProtocolFrame(encoded)

      // Mutação externa da cópia
      decoded.payload[0] = 0xff

      // Uma nova leitura deve retornar o payload original intacto
      expect(decoded.payload).toEqual(payload)
    })
  })

  describe('decoder incremental e fragmentação', () => {
    it('processa frame completo entregue em um único chunk', () => {
      const decoder = new ProtocolFrameDecoder()
      const payload = Buffer.from('full chunk', 'utf8')
      const frame = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload })

      const frames = decoder.push(frame)
      decoder.finish()

      expect(frames).toHaveLength(1)
      expect(frames[0]?.type).toBe(ProtocolFrameType.SESSION)
      expect(frames[0]?.payload).toEqual(payload)
    })

    it('processa frame fragmentado entregue byte por byte', () => {
      const decoder = new ProtocolFrameDecoder()
      const payload = Buffer.from('byte by byte fragment test', 'utf8')
      const encoded = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload })

      const allFrames = []
      for (let i = 0; i < encoded.length; i++) {
        const singleByte = encoded.subarray(i, i + 1)
        const parsed = decoder.push(singleByte)
        allFrames.push(...parsed)
      }
      decoder.finish()

      expect(allFrames).toHaveLength(1)
      expect(allFrames[0]?.payload).toEqual(payload)
    })

    it('processa header fragmentado em pedaços arbitrários', () => {
      const decoder = new ProtocolFrameDecoder()
      const payload = Buffer.from('header split test', 'utf8')
      const encoded = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload })

      // Divide o header (12 bytes) em pedaços de 3 bytes
      const chunk1 = encoded.subarray(0, 3)
      const chunk2 = encoded.subarray(3, 8)
      const chunk3 = encoded.subarray(8, 12)
      const chunk4 = encoded.subarray(12)

      expect(decoder.push(chunk1)).toHaveLength(0)
      expect(decoder.push(chunk2)).toHaveLength(0)
      expect(decoder.push(chunk3)).toHaveLength(0)

      const finalFrames = decoder.push(chunk4)
      decoder.finish()

      expect(finalFrames).toHaveLength(1)
      expect(finalFrames[0]?.payload).toEqual(payload)
    })

    it('processa payload fragmentado em múltiplos chunks', () => {
      const decoder = new ProtocolFrameDecoder()
      const payload = Buffer.alloc(1000, 0x42)
      const encoded = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload })

      const headerAndHalf = encoded.subarray(0, HEADER_LENGTH + 500)
      const secondHalf = encoded.subarray(HEADER_LENGTH + 500)

      expect(decoder.push(headerAndHalf)).toHaveLength(0)
      const frames = decoder.push(secondHalf)
      decoder.finish()

      expect(frames).toHaveLength(1)
      expect(frames[0]?.payload).toEqual(payload)
    })
  })

  describe('decoder incremental e coalescing (múltiplos frames)', () => {
    it('processa múltiplos frames contidos em um único chunk', () => {
      const decoder = new ProtocolFrameDecoder()
      const frame1 = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: Buffer.from('F1') })
      const frame2 = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload: Buffer.from('F2') })
      const frame3 = encodeProtocolFrame({ type: ProtocolFrameType.HEARTBEAT, payload: Buffer.from('F3') })

      const coalesced = Buffer.concat([frame1, frame2, frame3])
      const frames = decoder.push(coalesced)
      decoder.finish()

      expect(frames).toHaveLength(3)
      expect(frames[0]?.payload.toString('utf8')).toBe('F1')
      expect(frames[1]?.payload.toString('utf8')).toBe('F2')
      expect(frames[2]?.payload.toString('utf8')).toBe('F3')
    })

    it('processa coalescing com frame subsequente parcialmente entregue', () => {
      const decoder = new ProtocolFrameDecoder()
      const frame1 = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: Buffer.from('First') })
      const frame2 = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload: Buffer.from('Second') })
      const frame3 = encodeProtocolFrame({ type: ProtocolFrameType.HEARTBEAT, payload: Buffer.from('Third') })

      // Chunk 1: frame1 + frame2 + metade do frame3
      const partialFrame3 = frame3.subarray(0, 5)
      const chunk1 = Buffer.concat([frame1, frame2, partialFrame3])

      const parsed1 = decoder.push(chunk1)
      expect(parsed1).toHaveLength(2)
      expect(parsed1[0]?.payload.toString('utf8')).toBe('First')
      expect(parsed1[1]?.payload.toString('utf8')).toBe('Second')

      // Chunk 2: restante do frame3
      const restFrame3 = frame3.subarray(5)
      const parsed2 = decoder.push(restFrame3)
      decoder.finish()

      expect(parsed2).toHaveLength(1)
      expect(parsed2[0]?.payload.toString('utf8')).toBe('Third')
    })
  })

  describe('testes negativos e rejeição estrita', () => {
    it('rejeita magic bytes incorretos', () => {
      const buffer = Buffer.alloc(HEADER_LENGTH)
      buffer.write('XXXX', 0, 'ascii') // Magic inválido
      buffer.writeUInt8(PROTOCOL_VERSION, 4)
      buffer.writeUInt8(ProtocolFrameType.HANDSHAKE, 5)
      buffer.writeUInt16BE(0, 6)
      buffer.writeUInt32BE(0, 8)

      expectProtocolError(() => decodeSingleProtocolFrame(buffer), 'PROTOCOL_INVALID_MAGIC')
    })

    it('rejeita versão de protocolo não suportada (v0, v2, v255)', () => {
      for (const invalidVersion of [0, 2, 255]) {
        const buffer = Buffer.alloc(HEADER_LENGTH)
        PROTOCOL_MAGIC.copy(buffer, 0)
        buffer.writeUInt8(invalidVersion, 4)
        buffer.writeUInt8(ProtocolFrameType.HANDSHAKE, 5)
        buffer.writeUInt16BE(0, 6)
        buffer.writeUInt32BE(0, 8)

        expectProtocolError(() => decodeSingleProtocolFrame(buffer), 'PROTOCOL_VERSION_UNSUPPORTED')
      }
    })

    it('rejeita frame type desconhecido', () => {
      const buffer = Buffer.alloc(HEADER_LENGTH)
      PROTOCOL_MAGIC.copy(buffer, 0)
      buffer.writeUInt8(PROTOCOL_VERSION, 4)
      buffer.writeUInt8(0x99, 5) // Tipo desconhecido
      buffer.writeUInt16BE(0, 6)
      buffer.writeUInt32BE(0, 8)

      expectProtocolError(() => decodeSingleProtocolFrame(buffer), 'PROTOCOL_FRAME_TYPE_UNSUPPORTED')
    })

    it('rejeita flags com bits definidos na versão 1', () => {
      const buffer = Buffer.alloc(HEADER_LENGTH)
      PROTOCOL_MAGIC.copy(buffer, 0)
      buffer.writeUInt8(PROTOCOL_VERSION, 4)
      buffer.writeUInt8(ProtocolFrameType.HANDSHAKE, 5)
      buffer.writeUInt16BE(0x0001, 6) // Flag desconhecida
      buffer.writeUInt32BE(0, 8)

      expectProtocolError(() => decodeSingleProtocolFrame(buffer), 'PROTOCOL_FLAGS_UNSUPPORTED')
    })

    it('rejeita payloadLength que excede MAX_FRAME_PAYLOAD_BYTES antes de alocar', () => {
      // 64 KB + 1
      const oversizeBuffer = Buffer.alloc(HEADER_LENGTH)
      PROTOCOL_MAGIC.copy(oversizeBuffer, 0)
      oversizeBuffer.writeUInt8(PROTOCOL_VERSION, 4)
      oversizeBuffer.writeUInt8(ProtocolFrameType.HANDSHAKE, 5)
      oversizeBuffer.writeUInt16BE(0, 6)
      oversizeBuffer.writeUInt32BE(MAX_FRAME_PAYLOAD_BYTES + 1, 8)

      expectProtocolError(() => decodeSingleProtocolFrame(oversizeBuffer), 'PROTOCOL_FRAME_TOO_LARGE')

      // 0xFFFFFFFF (4 GB)
      oversizeBuffer.writeUInt32BE(0xffffffff, 8)
      expectProtocolError(() => decodeSingleProtocolFrame(oversizeBuffer), 'PROTOCOL_FRAME_TOO_LARGE')
    })

    it('rejeita frame com trailing bytes em decodeSingleProtocolFrame', () => {
      const frame = encodeProtocolFrame({ type: ProtocolFrameType.HEARTBEAT })
      const withTrailing = Buffer.concat([frame, Buffer.from([0x00])])

      expectProtocolError(() => decodeSingleProtocolFrame(withTrailing), 'PROTOCOL_FRAME_INVALID')
    })

    it('rejeita frame truncado em decodeSingleProtocolFrame', () => {
      const frame = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: Buffer.from('12345') })
      const truncated = frame.subarray(0, frame.length - 1)

      expectProtocolError(() => decodeSingleProtocolFrame(truncated), 'PROTOCOL_FRAME_TRUNCATED')
    })

    it('rejeita finalização com bytes parciais restantes no decoder', () => {
      const decoder = new ProtocolFrameDecoder()
      const frame = encodeProtocolFrame({ type: ProtocolFrameType.SESSION, payload: Buffer.from('incomplete') })

      decoder.push(frame.subarray(0, 5)) // Apenas 5 bytes entregues
      expectProtocolError(() => decoder.finish(), 'PROTOCOL_FRAME_TRUNCATED')
    })

    it('não ressincroniza silenciosamente após erro de magic (desynchronization protection)', () => {
      const decoder = new ProtocolFrameDecoder()
      const invalidHeader = Buffer.from('BADM\x01\x01\x00\x00\x00\x00\x00\x00', 'binary')
      const validFrame = encodeProtocolFrame({ type: ProtocolFrameType.HANDSHAKE, payload: Buffer.from('valid') })

      // Envia lixo corrompido seguido de frame válido
      const stream = Buffer.concat([invalidHeader, validFrame])

      expectProtocolError(() => decoder.push(stream), 'PROTOCOL_INVALID_MAGIC')
      expect(decoder.isInvalidated()).toBe(true)

      // Tentativa de novo push após o erro deve falhar closed imediatamente
      expectProtocolError(() => decoder.push(validFrame), 'PROTOCOL_DECODER_FAILED')
    })

    it('invalida o decoder permanentemente após violação estrutural', () => {
      const decoder = new ProtocolFrameDecoder()
      const invalidVersionBuffer = Buffer.alloc(HEADER_LENGTH)
      PROTOCOL_MAGIC.copy(invalidVersionBuffer, 0)
      invalidVersionBuffer.writeUInt8(99, 4) // Versão inválida

      expectProtocolError(() => decoder.push(invalidVersionBuffer), 'PROTOCOL_VERSION_UNSUPPORTED')
      expect(decoder.isInvalidated()).toBe(true)

      const validFrame = encodeProtocolFrame({ type: ProtocolFrameType.HEARTBEAT })
      expectProtocolError(() => decoder.push(validFrame), 'PROTOCOL_DECODER_FAILED')
      expectProtocolError(() => decoder.finish(), 'PROTOCOL_DECODER_FAILED')
    })
  })

  describe('fuzz-like e robustez contra inputs aleatórios', () => {
    it('resiste a entradas aleatórias sem crashar nem entrar em loop infinito', () => {
      for (let i = 0; i < 50; i++) {
        const decoder = new ProtocolFrameDecoder()
        const randomChunk = randomBytes(Math.floor(Math.random() * 200) + 1)

        try {
          decoder.push(randomChunk)
        } catch (error) {
          expect(error).toBeInstanceOf(ProtocolError)
          expect(decoder.isInvalidated()).toBe(true)
        }
      }
    })
  })
})

function expectProtocolError(
  operation: () => unknown,
  code: ProtocolErrorCode
): void {
  expect(operation).toThrowError(
    expect.objectContaining({
      name: 'ProtocolError',
      code
    })
  )
}
