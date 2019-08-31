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

enum OpPartType {
    Char = 1,
    Register = 2,
    Label = 3,
    Variable = 4,
    Scalar = 5,
    Unknown = 6,
}

export interface OpPart {
    value: number|string;
    type: OpPartType;
}

export type Operand = OpPart[]

export interface Instruction {
    addr: number;
    mnemonic: string;
    operands: Operand[];
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
