"use strict";
//binary data writer tuned for creating
//postgres message packets as effeciently as possible by reusing the
//same buffer to avoid memcpy and limit memory allocations
Object.defineProperty(exports, "__esModule", { value: true });
class Writer {
    constructor(size = 1024) {
        this.offset = 5;
        this.headerPosition = 0;
        this.encoding = 'utf-8';
        this.buffer = Buffer.alloc(size + 5);
    }
    _ensure(size) {
        var remaining = this.buffer.length - this.offset;
        if (remaining < size) {
            var oldBuffer = this.buffer;
            // exponential growth factor of around ~ 1.5
            // https://stackoverflow.com/questions/2269063/buffer-growth-strategy
            var newSize = oldBuffer.length + (oldBuffer.length >> 1) + size;
            this.buffer = Buffer.alloc(newSize);
            oldBuffer.copy(this.buffer);
        }
    }
    addInt32(num) {
        this._ensure(4);
        this.buffer[this.offset++] = (num >>> 24 & 0xFF);
        this.buffer[this.offset++] = (num >>> 16 & 0xFF);
        this.buffer[this.offset++] = (num >>> 8 & 0xFF);
        this.buffer[this.offset++] = (num >>> 0 & 0xFF);
        return this;
    }
    addInt16(num) {
        this._ensure(2);
        this.buffer[this.offset++] = (num >>> 8 & 0xFF);
        this.buffer[this.offset++] = (num >>> 0 & 0xFF);
        return this;
    }
    addCString(string) {
        //just write a 0 for empty or null strings
        if (!string) {
            this._ensure(1);
        }
        else {
            var len = Buffer.byteLength(string);
            this._ensure(len + 1); //+1 for null terminator
            this.buffer.write(string, this.offset, this.encoding);
            this.offset += len;
        }
        this.buffer[this.offset++] = 0; // null terminator
        return this;
    }
    // note: this assumes character is 1 byte - used for writing protocol charcodes
    addChar(c) {
        this._ensure(1);
        this.buffer.write(c, this.offset);
        this.offset++;
        return this;
    }
    addString(string = "") {
        var len = Buffer.byteLength(string);
        this._ensure(len);
        this.buffer.write(string, this.offset);
        this.offset += len;
        return this;
    }
    getByteLength() {
        return this.offset - 5;
    }
    add(otherBuffer) {
        this._ensure(otherBuffer.length);
        otherBuffer.copy(this.buffer, this.offset);
        this.offset += otherBuffer.length;
        return this;
    }
    clear() {
        this.offset = 5;
        this.headerPosition = 0;
    }
    //appends a header block to all the written data since the last
    //subsequent header or to the beginning if there is only one data block
    addHeader(code, last = false) {
        var origOffset = this.offset;
        this.offset = this.headerPosition;
        this.buffer[this.offset++] = code;
        //length is everything in this packet minus the code
        this.addInt32(origOffset - (this.headerPosition + 1));
        //set next header position
        this.headerPosition = origOffset;
        //make space for next header
        this.offset = origOffset;
        if (!last) {
            this._ensure(5);
            this.offset += 5;
        }
    }
    join(code) {
        if (code) {
            this.addHeader(code, true);
        }
        return this.buffer.slice(code ? 0 : 5, this.offset);
    }
    flush(code) {
        var result = this.join(code);
        this.clear();
        return result;
    }
}
exports.Writer = Writer;
//# sourceMappingURL=BufferWriter.js.map