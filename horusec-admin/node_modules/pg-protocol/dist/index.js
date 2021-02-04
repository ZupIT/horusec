"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const messages_1 = require("./messages");
exports.DatabaseError = messages_1.DatabaseError;
const serializer_1 = require("./serializer");
exports.serialize = serializer_1.serialize;
const parser_1 = require("./parser");
function parse(stream, callback) {
    const parser = new parser_1.Parser();
    stream.on('data', (buffer) => parser.parse(buffer, callback));
    return new Promise((resolve) => stream.on('end', () => resolve()));
}
exports.parse = parse;
//# sourceMappingURL=index.js.map