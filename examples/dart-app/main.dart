import 'package:http/http.dart' as http;
import 'package:uuid/uuid.dart';
import 'package:intl/intl.dart';
import 'package:archive/archive.dart';
import 'dart:io';
import 'dart:convert';

void main() async {
  while (true) {
    // 1. UUID
    var uuid = Uuid();
    print('Dart UUID: ${uuid.v4()}');

    // 2. Intl
    var now = DateTime.now();
    var formatter = DateFormat('yyyy-MM-dd');
    print('Dart Date: ${formatter.format(now)}');

    // 3. Archive (Compression)
    var string = 'Hello World';
    var encoder = GZipEncoder();
    var data = encoder.encode(utf8.encode(string));
    print('Compressed data length: ${data?.length}');

    // 4. HTTP
    try {
      var url = Uri.parse('https://www.google.com');
      var response = await http.get(url);
      print('Google status code: ${response.statusCode}');
    } catch (e) {
      print('HTTP Error: $e');
    }

    sleep(Duration(seconds: 5));
  }
}
