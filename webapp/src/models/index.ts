export interface Repository {
    name: string;
    binaries: Binary[];
}

export interface Binary {
    name: string;
}

export interface Func {
    name: string;
    addr: number;
    signature: string;
}

export interface Asm {
    line: string;
    addr: number;
}

export type WsMessage = ProgressWsMessage;

export interface ProgressWsMessage {
    kind: 'progress';
    taskId: string;
    event: Event;
}

export type Event = IndeterminateEvent | ProgressEvent | MessageEvent | CompletedEvent;

export interface IndeterminateEvent {
    kind: 'indeterminate';
}

export interface ProgressEvent {
    kind: 'progress';
    current: number;
    max: number;
}

export interface MessageEvent {
    kind: 'message';
    msg: string;
}

export interface CompletedEvent {
    kind: 'completed';
    value: any;
}
