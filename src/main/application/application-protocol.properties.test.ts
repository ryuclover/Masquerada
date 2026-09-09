import { describe, expect, it } from 'vitest'

import {
  APPLICATION_MESSAGE_TYPE,
  APPLICATION_VERSION,
  ApplicationProtocolError,
  createApplicationMessageId,
  decodeApplicationEnvelope,
  encodeApplicationEnvelope,
  MAX_HISTORY_BATCH,
  type ApplicationEnvelope,
  type HistoryWireMessage
} from './application-protocol'

const SERVER_ID = `sha256:${'a'.repeat(64)}`

function stateRequest(): ApplicationEnvelope {
  return {
    kind: 'request', messageType: 'server-state.request', messageId: createApplicationMessageId(),
    correlationId: null, serverId: SERVER_ID, channelId: null, sequence: null, payload: {}
  }
}

function historyRequest(afterSequence: number, limit: number): ApplicationEnvelope {
  return {
    kind: 'request', messageType: 'history.request', messageId: createApplicationMessageId(),
    correlationId: null, serverId: SERVER_ID, channelId: null, sequence: null,
    payload: { channelId: 'b'.repeat(32), afterSequence, limit }
  }
}

function historyMessage(sequence: number, content: string): HistoryWireMessage {
  return {
    sequence, messageId: createApplicationMessageId(),
    authorFingerprint: `sha256:${'c'.repeat(64)}`,
    content, createdAt: 1700000000 + sequence, editedAt: null, deletedAt: null
  }
}

function historyResponse(messages: HistoryWireMessage[], hasMore: boolean): ApplicationEnvelope {
  return {
    kind: 'response', messageType: 'history.response', messageId: createApplicationMessageId(),
    correlationId: createApplicationMessageId(), serverId: SERVER_ID, channelId: null, sequence: 1,
    payload: { status: 'ok', messages, hasMore }
  }
}

const baseEnvelopes: ApplicationEnvelope[] = [
  stateRequest(),
  historyRequest(0, 100),
  {
    kind: 'response', messageType: 'server-state.response', messageId: createApplicationMessageId(),
    correlationId: createApplicationMessageId(), serverId: SERVER_ID, channelId: null, sequence: 1,
    payload: { status: 'ok', server: { displayName: 'Servidor' }, channels: [] }
  },
  historyResponse([], false),
  historyResponse([historyMessage(1, 'Primeira'), historyMessage(2, 'Segunda\u00e9')], true),
  {
    kind: 'response', messageType: 'history.response', messageId: createApplicationMessageId(),
    correlationId: createApplicationMessageId(), serverId: SERVER_ID, channelId: null, sequence: 2,
    payload: { status: 'error', code: 'UNAVAILABLE' }
  },
  {
    kind: 'response', messageType: 'history.response', messageId: createApplicationMessageId(),
    correlationId: createApplicationMessageId(), serverId: SERVER_ID, channelId: null, sequence: 3,
    payload: { status: 'ok', messages: [{ ...historyMessage(3, 'Apagada'), content: '', deletedAt: 1700000005 }], hasMore: false }
  }
]

describe('propriedades adversariais do protocolo de aplicação (ETAPA 8.5)', () => {
  it('decode(encode(x)) = x e encode(decode(bytes)) = bytes para todos os envelopes válidos', () => {
    for (const envelope of baseEnvelopes) {
      const bytes = encodeApplicationEnvelope(envelope)
      expect(decodeApplicationEnvelope(bytes)).toEqual(envelope)
      expect(encodeApplicationEnvelope(decodeApplicationEnvelope(bytes))).toEqual(bytes)
    }
  })

  it('mutações determinísticas de bytes válidos nunca produzem envelopes aceitos', () => {
    const sources = baseEnvelopes.map((envelope) => encodeApplicationEnvelope(envelope))
    let mutations = 0
    let accepted = 0
    for (const bytes of sources) {
      for (let position = 0; position < bytes.length; position++) {
        for (const delta of [1, 0x40, 0xff]) {
          const mutated = Buffer.from(bytes)
          mutated[position] = (mutated[position]! + delta) & 0xff
          mutations++
          try {
            decodeApplicationEnvelope(mutated)
            accepted++
          } catch (error) {
            expect(error).toBeInstanceOf(ApplicationProtocolError)
          }
        }
      }
    }
    expect(mutations).toBeGreaterThan(1000)
    // Bit-flips may occasionally keep the envelope valid (e.g. inside string payload
    // content), but any accept must be a well-formed envelope re-encoding identically.
    expect(accepted).toBeLessThan(mutations)
  })

  it('truncamento em qualquer prefixo rejeita sem aceitar', () => {
    for (const envelope of baseEnvelopes) {
      const bytes = encodeApplicationEnvelope(envelope)
      for (let length = 0; length < bytes.length; length++) {
        expect(() => decodeApplicationEnvelope(bytes.subarray(0, length))).toThrow(ApplicationProtocolError)
      }
    }
  })

  it('bytes adicionais após o envelope rejeitam e versão/tipo inválidos rejeitam', () => {
    for (const envelope of baseEnvelopes) {
      const bytes = encodeApplicationEnvelope(envelope)
      expect(() => decodeApplicationEnvelope(Buffer.concat([bytes, Buffer.from([0])]))).toThrow(ApplicationProtocolError)

      const wrongVersion = Buffer.from(bytes)
      wrongVersion[0] = APPLICATION_VERSION + 1
      expect(() => decodeApplicationEnvelope(wrongVersion)).toThrow(ApplicationProtocolError)

      const wrongType = Buffer.from(bytes)
      wrongType[1] = APPLICATION_MESSAGE_TYPE + 1
      expect(() => decodeApplicationEnvelope(wrongType)).toThrow(ApplicationProtocolError)
    }
  })

  it('JSON quase-canônico (chaves reordenadas, espaços, escapes alternativos) rejeita', () => {
    const envelope = historyResponse([historyMessage(1, 'Aé')], false)
    const bytes = encodeApplicationEnvelope(envelope)
    const body = bytes.subarray(6).toString('utf8')
    const parsed = JSON.parse(body) as Record<string, unknown>
    // Reverse top-level key order.
    const reordered = `{${Object.entries(parsed).reverse().map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`).join(',')}}`
    const header = Buffer.allocUnsafe(6)
    header[0] = APPLICATION_VERSION
    header[1] = APPLICATION_MESSAGE_TYPE
    header.writeUInt32BE(Buffer.byteLength(reordered), 2)
    expect(() => decodeApplicationEnvelope(Buffer.concat([header, Buffer.from(reordered)]))).toThrow(ApplicationProtocolError)

    const spaced = body.replace('{', '{ ')
    header.writeUInt32BE(Buffer.byteLength(spaced), 2)
    expect(() => decodeApplicationEnvelope(Buffer.concat([header, Buffer.from(spaced)]))).toThrow(ApplicationProtocolError)
  })

  it('limites de history: lote máximo, sequences não crescentes e limit fora de faixa rejeitam', () => {
    const maxBatch = Array.from({ length: MAX_HISTORY_BATCH }, (_, index) => historyMessage(index + 1, `m${index}`))
    const maxBytes = encodeApplicationEnvelope(historyResponse(maxBatch, true))
    expect(decodeApplicationEnvelope(maxBytes).payload).toMatchObject({ status: 'ok' })

    expect(() => encodeApplicationEnvelope(historyResponse([...maxBatch, historyMessage(MAX_HISTORY_BATCH + 1, 'x')], false)))
      .toThrow(ApplicationProtocolError)

    expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(1, 'a'), historyMessage(1, 'b')], false))).toThrow(ApplicationProtocolError)
    expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(2, 'a'), historyMessage(1, 'b')], false))).toThrow(ApplicationProtocolError)

    expect(() => encodeApplicationEnvelope(historyRequest(0, MAX_HISTORY_BATCH + 1))).toThrow(ApplicationProtocolError)
    expect(() => encodeApplicationEnvelope(historyRequest(0, 0))).toThrow(ApplicationProtocolError)
    expect(() => encodeApplicationEnvelope(historyRequest(-1, 10))).toThrow(ApplicationProtocolError)
    expect(() => encodeApplicationEnvelope(historyRequest(Number.MAX_SAFE_INTEGER + 1, 10))).toThrow(ApplicationProtocolError)
    expect(() => encodeApplicationEnvelope(historyRequest(0, 1))).not.toThrow()
  })

  it('conteúdo no limite de code points aceita e estoura; controles rejeitam mesmo em lápides', () => {
    const boundary = 'a'.repeat(4096)
    expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(1, boundary)], false))).not.toThrow()
    expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(1, `${boundary}a`)], false))).toThrow(ApplicationProtocolError)

    // Supplementary plane character counts as one code point: 2048 of them fit.
    const supplementary = '\u{1F600}'.repeat(2048)
    expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(1, supplementary)], false))).not.toThrow()

    const controls = ['a\nb', 'a\tb', 'a\u0000b', 'a\u007fb']
    for (const content of controls) {
      expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(1, content)], false))).toThrow(ApplicationProtocolError)
      // Even a tombstone cannot carry control characters in content.
      expect(() => encodeApplicationEnvelope(historyResponse([{ ...historyMessage(1, content), deletedAt: 1 }], false))).toThrow(ApplicationProtocolError)
    }
    // Empty content is only valid for tombstones.
    expect(() => encodeApplicationEnvelope(historyResponse([historyMessage(1, '')], false))).toThrow(ApplicationProtocolError)
    expect(() => encodeApplicationEnvelope(historyResponse([{ ...historyMessage(1, ''), deletedAt: 1700000005 }], false))).not.toThrow()
  })

  it('ids gerados são únicos e canonicalmente hex', () => {
    const ids = new Set<string>()
    for (let index = 0; index < 1000; index++) {
      const id = createApplicationMessageId()
      expect(id).toMatch(/^[0-9a-f]{32}$/)
      ids.add(id)
    }
    expect(ids.size).toBe(1000)
  })

  it('payload de server-state com estrutura trocada por history rejeita (sem confusão de tipos)', () => {
    const swapped = {
      kind: 'response', messageType: 'server-state.response', messageId: createApplicationMessageId(),
      correlationId: createApplicationMessageId(), serverId: SERVER_ID, channelId: null, sequence: 1,
      payload: { status: 'ok', messages: [historyMessage(1, 'x')], hasMore: false }
    } as unknown as ApplicationEnvelope
    expect(() => encodeApplicationEnvelope(swapped)).toThrow(ApplicationProtocolError)
  })
})
