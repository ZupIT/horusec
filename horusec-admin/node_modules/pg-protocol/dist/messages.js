"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseComplete = {
    name: "parseComplete" /* parseComplete */,
    length: 5,
};
exports.bindComplete = {
    name: "bindComplete" /* bindComplete */,
    length: 5,
};
exports.closeComplete = {
    name: "closeComplete" /* closeComplete */,
    length: 5,
};
exports.noData = {
    name: "noData" /* noData */,
    length: 5,
};
exports.portalSuspended = {
    name: "portalSuspended" /* portalSuspended */,
    length: 5,
};
exports.replicationStart = {
    name: "replicationStart" /* replicationStart */,
    length: 4,
};
exports.emptyQuery = {
    name: "emptyQuery" /* emptyQuery */,
    length: 4,
};
exports.copyDone = {
    name: "copyDone" /* copyDone */,
    length: 4,
};
class DatabaseError extends Error {
    constructor(message, length, name) {
        super(message);
        this.length = length;
        this.name = name;
    }
}
exports.DatabaseError = DatabaseError;
class CopyDataMessage {
    constructor(length, chunk) {
        this.length = length;
        this.chunk = chunk;
        this.name = "copyData" /* copyData */;
    }
}
exports.CopyDataMessage = CopyDataMessage;
class CopyResponse {
    constructor(length, name, binary, columnCount) {
        this.length = length;
        this.name = name;
        this.binary = binary;
        this.columnTypes = new Array(columnCount);
    }
}
exports.CopyResponse = CopyResponse;
class Field {
    constructor(name, tableID, columnID, dataTypeID, dataTypeSize, dataTypeModifier, format) {
        this.name = name;
        this.tableID = tableID;
        this.columnID = columnID;
        this.dataTypeID = dataTypeID;
        this.dataTypeSize = dataTypeSize;
        this.dataTypeModifier = dataTypeModifier;
        this.format = format;
    }
}
exports.Field = Field;
class RowDescriptionMessage {
    constructor(length, fieldCount) {
        this.length = length;
        this.fieldCount = fieldCount;
        this.name = "rowDescription" /* rowDescription */;
        this.fields = new Array(this.fieldCount);
    }
}
exports.RowDescriptionMessage = RowDescriptionMessage;
class ParameterStatusMessage {
    constructor(length, parameterName, parameterValue) {
        this.length = length;
        this.parameterName = parameterName;
        this.parameterValue = parameterValue;
        this.name = "parameterStatus" /* parameterStatus */;
    }
}
exports.ParameterStatusMessage = ParameterStatusMessage;
class AuthenticationMD5Password {
    constructor(length, salt) {
        this.length = length;
        this.salt = salt;
        this.name = "authenticationMD5Password" /* authenticationMD5Password */;
    }
}
exports.AuthenticationMD5Password = AuthenticationMD5Password;
class BackendKeyDataMessage {
    constructor(length, processID, secretKey) {
        this.length = length;
        this.processID = processID;
        this.secretKey = secretKey;
        this.name = "backendKeyData" /* backendKeyData */;
    }
}
exports.BackendKeyDataMessage = BackendKeyDataMessage;
class NotificationResponseMessage {
    constructor(length, processId, channel, payload) {
        this.length = length;
        this.processId = processId;
        this.channel = channel;
        this.payload = payload;
        this.name = "notification" /* notification */;
    }
}
exports.NotificationResponseMessage = NotificationResponseMessage;
class ReadyForQueryMessage {
    constructor(length, status) {
        this.length = length;
        this.status = status;
        this.name = "readyForQuery" /* readyForQuery */;
    }
}
exports.ReadyForQueryMessage = ReadyForQueryMessage;
class CommandCompleteMessage {
    constructor(length, text) {
        this.length = length;
        this.text = text;
        this.name = "commandComplete" /* commandComplete */;
    }
}
exports.CommandCompleteMessage = CommandCompleteMessage;
class DataRowMessage {
    constructor(length, fields) {
        this.length = length;
        this.fields = fields;
        this.name = "dataRow" /* dataRow */;
        this.fieldCount = fields.length;
    }
}
exports.DataRowMessage = DataRowMessage;
class NoticeMessage {
    constructor(length, message) {
        this.length = length;
        this.message = message;
        this.name = "notice" /* notice */;
    }
}
exports.NoticeMessage = NoticeMessage;
//# sourceMappingURL=messages.js.map