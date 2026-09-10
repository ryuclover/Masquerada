import { describe, expect, it } from 'vitest'

import { ApplicationEndpointError } from './application-endpoint'
import type { MessageSendAccepted } from './application-protocol'
import { MessageOutbox, type OutboxDraft } from './message-outbox'

function draft(index: number): OutboxDraft {
  return { channelId: 'a'.repeat(32), clientMessageId: index.toString(16).padStart(32, '0'), content: `m${index}` }
}

function accepted(draft: OutboxDraft): MessageSendAccepted {
  return { sequence: Number.parseInt(draft.clientMessageId, 16) + 1, messageId: draft.clientMessageId, createdAt: 1, dedup: false }
}

describe('message outbox offline queue (ETAPA 9.3)', () => {
  it('entrega em ordem FIFO e remove itens confirmados', async () => {
    const outbox = new MessageOutbox()
    outbox.enqueue(draft(0))
    outbox.enqueue(draft(1))
    outbox.enqueue(draft(2))
    expect(outbox.size).toBe(3)

    const sent: OutboxDraft[] = []
    const result = await outbox.flush(async (item) => {
      sent.push(item)
      return accepted(item)
    })
    expect(sent.map((item) => item.clientMessageId)).toEqual([
      draft(0).clientMessageId, draft(1).clientMessageId, draft(2).clientMessageId
    ])
    expect(result.delivered).toHaveLength(3)
    expect(result.remaining).toBe(0)
    expect(outbox.size).toBe(0)
  })

  it('falha de rede mantém a item na frente e interrompe o flush', async () => {
    const outbox = new MessageOutbox()
    outbox.enqueue(draft(0))
    outbox.enqueue(draft(1))
    let attempts = 0
    const result = await outbox.flush(async (item) => {
      attempts++
      if (attempts === 1) throw new ApplicationEndpointError('UNAVAILABLE')
      return accepted(item)
    })
    expect(result.delivered).toHaveLength(0)
    expect(result.remaining).toBe(2)
    expect(outbox.size).toBe(2)

    const retry = await outbox.flush(async (item) => accepted(item))
    expect(retry.delivered).toHaveLength(2)
    expect(outbox.size).toBe(0)
  })

  it('dedup por clientMessageId e limite de capacidade', async () => {
    const outbox = new MessageOutbox()
    outbox.enqueue(draft(5))
    outbox.enqueue(draft(5))
    expect(outbox.size).toBe(1)

    expect(() => {
      for (let index = 0; index < 64; index++) outbox.enqueue(draft(100 + index))
    }).toThrow('OUTBOX_FULL')
    expect(outbox.size).toBe(64)
  })
})
