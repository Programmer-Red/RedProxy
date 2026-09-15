import type { AuditEvent } from './types';

export class AuditLog {
  private nextId = 1;
  private events: AuditEvent[] = [];
  private readonly limit: number;

  constructor(limit = 2000) {
    this.limit = limit;
  }

  record(type: string, data: Omit<AuditEvent, 'id' | 'at' | 'type'> = {}): AuditEvent {
    const event: AuditEvent = {
      id: this.nextId++,
      at: Date.now(),
      type,
      ...data,
    };
    this.events.push(event);
    if (this.events.length > this.limit) {
      this.events.splice(0, this.events.length - this.limit);
    }
    // Keep an operator-visible stream without ever logging node passwords.
    console.log(JSON.stringify({ audit: event }));
    return event;
  }

  list(limit = 200): AuditEvent[] {
    return this.events.slice(-limit).reverse();
  }
}
