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
