import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:pointycastle/export.dart';

class CryptoUtil {
  final Uint8List cryptoKey;
  bool verifyHmac;

  CryptoUtil(String key, {this.verifyHmac = false}) : cryptoKey = sha256.convert(utf8.encode(key)).bytes as Uint8List;

  String encrypt(Object obj) {
    final json = jsonEncode(obj);

    // First generate a random IV.
    // AES-256 IV size is sixteen bytes:
    final iv = _generateRandomBytes(16);

    // Make sure to use the 'iv' variant when creating the cipher object:
    final cipher = _createCipher(cryptoKey, iv);

    // Generate the encrypted json:
    final encryptedJson = cipher.process(Uint8List.fromList(utf8.encode(json)));

    // Include the hex-encoded IV + the encrypted base64 data
    // NOTE: We're using hex for encoding the IV to ensure that it's of constant length.
    var result = _bytesToHex(iv) + _bytesToHex(encryptedJson);
    String bs64 = base64.encode(result.codeUnits);

    if (verifyHmac) {
      // Prepend an HMAC to the result to verify its integrity prior to decrypting.
      // NOTE: We're using hex for encoding the hmac to ensure that it's of constant length
      final hmacResult = _calculateHmac(result);
      bs64 = hmacResult + bs64;
    }

    return bs64;
  }

  Uint8List _generateRandomBytes(int length) {
    final random = Random.secure();
    final values = List<int>.generate(length, (index) => random.nextInt(256));
    return Uint8List.fromList(values);
  }

  PaddedBlockCipher _createCipher(Uint8List key, Uint8List iv) {
    final cipher = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
    final cipherParams = ParametersWithIV(KeyParameter(key), iv);
    final paddedFinalCipher = PaddedBlockCipherParameters(cipherParams, null);
    return cipher..init(true, paddedFinalCipher);
  }

  String _bytesToHex(Uint8List bytes) {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
  }

  String _calculateHmac(String data) {
    final hmacSha256 = Hmac(sha256, cryptoKey);
    final hmacBytes = hmacSha256.convert(utf8.encode(data)).bytes;
    return _bytesToHex(Uint8List.fromList(hmacBytes));
  }
}

class DecryptGPT {
  //inicio decrip

  final Uint8List cryptoKey;

  DecryptGPT(String key) : cryptoKey = sha256.convert(utf8.encode(key)).bytes as Uint8List;

  Uint8List _calculateHmac(Uint8List data) {
    final hmacSha256 = Hmac(sha256, cryptoKey);
    return Uint8List.fromList(hmacSha256.convert(data).bytes);
  }

  String decryptAndVerify(String cipherText) {
    final encryptedData = base64.decode(cipherText);
    final expectedHmac = encryptedData.sublist(0, 32);
    final iv = encryptedData.sublist(32, 48);
    final encryptedJson = encryptedData.sublist(48);

    final actualHmac = _calculateHmac(Uint8List.fromList([...iv, ...encryptedJson]));

    if (!listEquals(expectedHmac, actualHmac)) {
      throw Exception('HMAC does not match');
    }

    final cipher = _createCipher(cryptoKey, iv);

    final cipherProcess = cipher.process(Uint8List.fromList(encryptedJson));
    List<int> t = cipherProcess;

    final decryptedJson = utf8.decode(t);

    return decryptedJson;
  }

  PaddedBlockCipher _createCipher(Uint8List key, Uint8List iv) {
    final cipher = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
    final cipherParams = ParametersWithIV(KeyParameter(key), iv);
    final paddedFinalCipher = PaddedBlockCipherParameters(cipherParams, null);
    return cipher..init(true, paddedFinalCipher);
  }

  // void main() {
  //   const key = 'memorian01042020-usemobile';
  //   const cipherText =
  //       '7cb786fad9b2bed27f9417d9329a9228072d27efc57adce29a0e7c41f8e3c42c8d0e963e31602db9de6bc9b62e552b0eNuxwdSnJlxREpoMky0eMHg==';

  //   final cryptoUtil = DecryptGPT(key);
  //   final decryptedText = cryptoUtil.decryptAndVerify(cipherText);
  //   print(decryptedText); // Output: 1234
  // }
}
// String encrypt(Object obj, Uint8List cryptoKey, bool verifyHmac) {
//   final json = jsonEncode(obj);

//   // First generate a random IV.
//   // AES-256 IV size is sixteen bytes:
//   final iv = _generateRandomBytes(16);

//   // Make sure to use the 'iv' variant when creating the cipher object:
//   final cipher = _createCipher('aes-256-cbc', cryptoKey, iv);

//   // Generate the encrypted json:
//   final encryptedJson = cipher.process(Uint8List.fromList(utf8.encode(json)));

//   // Include the hex-encoded IV + the encrypted base64 data
//   // NOTE: We're using hex for encoding the IV to ensure that it's of constant length.
//   final result = _bytesToHex(iv) + _bytesToHex(encryptedJson);

//   if (verifyHmac) {
//     // Prepend an HMAC to the result to verify its integrity prior to decrypting.
//     // NOTE: We're using hex for encoding the hmac to ensure that it's of constant length
//     final hmacResult = _calculateHmac(result, cryptoKey);
//     return hmacResult + result;
//   }

//   return result;
// }
