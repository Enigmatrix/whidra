export interface Repository {
    name: string;
    binaries: Binary[];
}

export interface Binary {
    name: string;
}

export interface Function {
    name: string;
    address: number;
    prototype: string;
}
