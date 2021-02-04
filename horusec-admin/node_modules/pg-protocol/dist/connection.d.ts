/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */
/// <reference types="node" />
declare var net: any;
declare var EventEmitter: any;
declare var util: any;
declare var Writer: any;
declare const parse: any;
declare var warnDeprecation: any;
declare var TEXT_MODE: number;
declare class Connection extends EventEmitter {
    constructor(config: any);
}
declare var emptyBuffer: Buffer;
declare const flushBuffer: Buffer;
declare const syncBuffer: Buffer;
declare const END_BUFFER: Buffer;
