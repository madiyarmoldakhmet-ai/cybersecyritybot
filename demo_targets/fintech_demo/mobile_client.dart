import 'dart:io';

class DemoBankingHttpClient {
  HttpClient createUnsafeClient() {
    final client = HttpClient();
    client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    return client;
  }
}
