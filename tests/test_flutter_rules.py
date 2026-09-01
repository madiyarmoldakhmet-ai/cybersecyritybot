import pytest
from pathlib import Path
from aegis.scanners.flutter_rules import FlutterSecurityScanner

@pytest.fixture
def vulnerable_flutter_project(tmp_path):
    project_dir = tmp_path / "test_flutter_app"
    project_dir.mkdir()
    
    # Rule 1 & 3 & 5 & 6 & 8
    lib_dir = project_dir / "lib"
    lib_dir.mkdir()
    main_dart = """
import 'dart:math';
import 'package:sqflite/sqflite.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/foundation.dart';

void main() async {
  // AEGIS-FLUTTER-006
  if (kDebugMode) {
    print("Debug mode!");
  }

  // AEGIS-FLUTTER-005
  final apiUrl = 'https://prod.api.example.com/v1';

  // AEGIS-FLUTTER-003
  final random = Random();
  final otp = random.nextInt(9999);

  // AEGIS-FLUTTER-001
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', '123456');

  // AEGIS-FLUTTER-008
  var db = await openDatabase('my_db.db');
}
"""
    (lib_dir / "main.dart").write_text(main_dart)

    # Rule 2 & 4
    network_dart = """
import 'dart:io';
import 'package:webview_flutter/webview_flutter.dart';

void initNetwork() {
  // AEGIS-FLUTTER-002
  HttpOverrides.global = new MyHttpOverrides();
}

class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

class MyWebView extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // AEGIS-FLUTTER-004
    return WebView(
      initialUrl: 'https://flutter.dev',
      javascriptMode: JavascriptMode.unrestricted,
    );
  }
}
"""
    (lib_dir / "network.dart").write_text(network_dart)

    # Rule 7
    pubspec = """
name: test_flutter_app
description: A new Flutter project.

environment:
  sdk: ">=2.17.0 <3.0.0"

dependencies:
  flutter:
    sdk: flutter
  shared_preferences: ^2.0.15
  sqflite: ^2.0.2
"""
    (project_dir / "pubspec.yaml").write_text(pubspec)

    # Rule 9
    ios_dir = project_dir / "ios" / "Runner"
    ios_dir.mkdir(parents=True)
    info_plist = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
"""
    (ios_dir / "Info.plist").write_text(info_plist)

    # Rule 10
    android_dir = project_dir / "android" / "app" / "src" / "main"
    android_dir.mkdir(parents=True)
    android_manifest = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    (android_dir / "AndroidManifest.xml").write_text(android_manifest)

    return project_dir

@pytest.mark.asyncio
async def test_flutter_scanner(vulnerable_flutter_project):
    scanner = FlutterSecurityScanner()
    findings = await scanner.scan(vulnerable_flutter_project)

    # We should have 10 findings matching all 10 rules
    assert len(findings) == 10
    
    rule_ids = [f.id for f in findings]
    
    assert "AEGIS-FLUTTER-001" in rule_ids
    assert "AEGIS-FLUTTER-002" in rule_ids
    assert "AEGIS-FLUTTER-003" in rule_ids
    assert "AEGIS-FLUTTER-004" in rule_ids
    assert "AEGIS-FLUTTER-005" in rule_ids
    assert "AEGIS-FLUTTER-006" in rule_ids
    assert "AEGIS-FLUTTER-007" in rule_ids
    assert "AEGIS-FLUTTER-008" in rule_ids
    assert "AEGIS-FLUTTER-009" in rule_ids
    assert "AEGIS-FLUTTER-010" in rule_ids
