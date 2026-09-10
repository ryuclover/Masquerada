import { ApplicationEndpointError } from './application-endpoint'
import type { MessageSendAccepted } from './application-protocol'

export interface OutboxDraft {
  readonly channelId: string
  readonly clientMessageId: string
  readonly content: string
}

const MAX_OUTBOX_ITEMS = 64

/**
 * Client-side durable delivery queue. Items are processed in insertion order;
 * a failed send keeps its position and stops the flush (safe to retry later).
 * Dedup is enforced by the host via clientMessageId, so retries never duplicate.
 */
export class MessageOutbox {
  private readonly queue: OutboxDraft[] = []

  get size(): number {
    return this.queue.length
  }

  pending(): readonly OutboxDraft[] {
    return this.queue
  }

  enqueue(draft: OutboxDraft): void {
    if (this.queue.some((item) => item.clientMessageId === draft.clientMessageId)) return
    if (this.queue.length >= MAX_OUTBOX_ITEMS) {
      throw new ApplicationEndpointError('OUTBOX_FULL')
    }
    this.queue.push(draft)
  }

  /** Sends until the queue drains or the first failure; resolves per-item results. */
  async flush(
    send: (draft: OutboxDraft) => Promise<MessageSendAccepted>
  ): Promise<{ delivered: MessageSendAccepted[]; remaining: number }> {
    const delivered: MessageSendAccepted[] = []
    while (this.queue.length > 0) {
      const draft = this.queue[0]!
      try {
        const accepted = await send(draft)
        this.queue.shift()
        delivered.push(accepted)
      } catch {
        // Keep the item and stop: the connection is likely unavailable.
        break
      }
    }
    return { delivered, remaining: this.queue.length }
  }
}
