/// <reference types="node" />
export declare class Writer {
    private buffer;
    private offset;
    private headerPosition;
    private readonly encoding;
    constructor(size?: number);
    private _ensure;
    addInt32(num: number): Writer;
    addInt16(num: number): Writer;
    addCString(string: string): Writer;
    addChar(c: string): Writer;
    addString(string?: string): Writer;
    getByteLength(): number;
    add(otherBuffer: Buffer): Writer;
    clear(): void;
    addHeader(code: number, last?: boolean): void;
    join(code?: number): Buffer;
    flush(code?: number): Buffer;
}
