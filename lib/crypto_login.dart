import 'dart:convert';

import 'package:cryptography/cryptography.dart';

class CryptoLogin {
  Future<void> encrypt() async {
    final algorithm = AesCbc.with256bits(macAlgorithm: Hmac.sha256());

    final sink = Sha256().newHashSink();

    sink.add(utf8.encode('memorian01042020-usemobile'));

    sink.close();

    final hash = await sink.hash();

    final sk = SecretKey(hash.bytes);

    final stringfy = jsonEncode('2409');

    // Encrypt
    final secretBox = await algorithm.encryptString(
      stringfy,
      secretKey: sk,
    );

    final nonceHex = _toHex(secretBox.nonce);

    final cipherb64 = base64.encode(secretBox.cipherText);

    final mac = await Hmac.sha256().calculateMac(
      utf8.encode('$nonceHex$cipherb64'),
      secretKey: sk,
    );

    final macHex = _toHex(mac.bytes);

    print('$macHex$nonceHex$cipherb64');

    // Decrypt
    final clearText = await algorithm.decryptString(
      secretBox,
      secretKey: sk,
    );
    print('Cleartext: $clearText');
  }

  String _toHex(List<int> bytes) {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
  }
}
