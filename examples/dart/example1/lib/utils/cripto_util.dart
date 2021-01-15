import 'package:crypto/crypto.dart';
import 'dart:convert'; // for the utf8.encode method

class CriptoSha1Util {
  var bytes = utf8.encode("foobar"); // data being hashed

  var digest = sha1.convert(bytes);

  print("Digest as bytes: ${digest.bytes}");
  print("Digest as hex string: $digest");
}

class CriptoMD5Util {
  var bytes = utf8.encode("foobar"); // data being hashed

  var digest = md5.convert(bytes);

  print("Digest as bytes: ${digest.bytes}");
  print("Digest as hex string: $digest");
}