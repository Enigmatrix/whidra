export interface UserInfo {
  name: string;
}

export interface Project {
  name: string;
  binaries: Binary[];
}

export interface Binary {
  name: String;
}

export interface Function {
  name: string;
  signature: string;
  addr: number;
  inline: boolean;
  thunk: boolean;
  global: boolean;
}

export namespace Task {
  export interface Message {
    kind: "message";
    msg: string;
  }
  export interface Completed {
    kind: "completed";
    value: any;
  }
  export interface Progress {
    kind: "progress";
    current: number;
    max: number;
  }
  export interface Progress {
    kind: "progress";
    current: number;
    max: number;
  }
  export interface Indeterminate {
    kind: "indeterminate";
  }
  export type Event = Indeterminate | Progress | Message | Completed;
}

export interface TaskProgress {
  kind: "progress";
  taskId: string;
  event: Task.Event;
}

export type WsOut = TaskProgress;
