"""
Unit tests for Mobile DevSecOps Scanner and Zero-Noise False-Positive Sanitizer.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from strix.scanners.mobile_scanner import MobileSecurityScanner
from strix.scanners.models import ScannerType, Severity, VulnerabilityFinding
from strix.scanners.sanitizer import (
    FalsePositiveSanitizer,
    calculate_shannon_entropy,
)


def test_shannon_entropy():
    # Predictable / Low entropy strings
    dummy_1 = "12345678901234567890"
    dummy_2 = "aaaaaaaaaaaaaaaaaaaa"
    dummy_3 = "test_key_test_key"
    
    assert calculate_shannon_entropy(dummy_1) < 3.5
    assert calculate_shannon_entropy(dummy_2) < 1.0
    assert calculate_shannon_entropy(dummy_3) < 3.2

    # High entropy mock keys
    high_entropy_key_1 = "ghp_MockTokenWithHighEntropy9876543210AbCdEfGhIjKlMn"
    high_entropy_key_2 = "Sec_Token_98xP_74bZqwTyUioPlkMnBvCxZaQwe12_Entropy"
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p"

    assert calculate_shannon_entropy(high_entropy_key_1) >= 3.8
    assert calculate_shannon_entropy(high_entropy_key_2) >= 3.8
    assert calculate_shannon_entropy(jwt_token) >= 4.0
    print("✅ test_shannon_entropy passed!")


def test_false_positive_sanitizer():
    sanitizer = FalsePositiveSanitizer()

    # 1. Dummy placeholder secret should be dropped
    f_dummy = VulnerabilityFinding(
        id="exposed-api-key",
        scanner=ScannerType.CUSTOM,
        title="Exposed API Key",
        description="Found key",
        severity=Severity.HIGH,
        file_path="lib/config.dart",
        code_snippet="const apiKey = 'YOUR_API_KEY_HERE';",
    )
    assert sanitizer.sanitize_finding(f_dummy) is None

    # 2. Test path finding should be dropped
    f_test = VulnerabilityFinding(
        id="hardcoded-credential",
        scanner=ScannerType.CUSTOM,
        title="Hardcoded Token in Test",
        description="Found token",
        severity=Severity.HIGH,
        file_path="tests/mock_auth_test.dart",
        code_snippet="final t = 'MockToken_98xP_74bZqwTyUioPlkMnBvCxZaQwe12_Entropy';",
    )
    assert sanitizer.sanitize_finding(f_test) is None

    # 3. Real secret in production file should be preserved
    f_real = VulnerabilityFinding(
        id="exposed-api-key",
        scanner=ScannerType.CUSTOM,
        title="Exposed API Key",
        description="Found key",
        severity=Severity.HIGH,
        file_path="lib/services/api.dart",
        code_snippet="const liveKey = 'SecToken_98xP_74bZqwTyUioPlkMnBvCxZaQwe12_LiveSecret';",
    )
    assert sanitizer.sanitize_finding(f_real) is not None
    print("✅ test_false_positive_sanitizer passed!")


async def test_mobile_security_scanner():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # 1. Vulnerable Dart file
        dart_dir = root / "lib"
        dart_dir.mkdir(parents=True)
        (dart_dir / "api_client.dart").write_text(
            """
            import 'dart:io';
            import 'package:shared_preferences/shared_preferences.dart';

            void setupClient() {
                HttpClient client = HttpClient();
                client.badCertificateCallback = (cert, host, port) => true;
                
                final url = Uri.parse("http://insecure-backend.com/api/v1");
            }

            void saveToken(String jwt) async {
                final prefs = await SharedPreferences.getInstance();
                prefs.setString("auth_token", jwt);
            }
            """,
            encoding="utf-8"
        )

        # 2. Insecure Firestore rules
        (root / "firestore.rules").write_text(
            """
            rules_version = '2';
            service cloud.firestore {
              match /databases/{database}/documents {
                match /{document=**} {
                  allow read, write: if true;
                }
              }
            }
            """,
            encoding="utf-8"
        )

        # 3. Insecure Android Manifest
        android_dir = root / "android" / "app" / "src" / "main"
        android_dir.mkdir(parents=True)
        (android_dir / "AndroidManifest.xml").write_text(
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application
                    android:allowBackup="true"
                    android:usesCleartextTraffic="true">
                </application>
            </manifest>
            """,
            encoding="utf-8"
        )

        # 4. Insecure iOS Info.plist
        ios_dir = root / "ios" / "Runner"
        ios_dir.mkdir(parents=True)
        (ios_dir / "Info.plist").write_text(
            """
            <plist version="1.0">
            <dict>
                <key>NSAppTransportSecurity</key>
                <dict>
                    <key>NSAllowsArbitraryLoads</key>
                    <true/>
                </dict>
            </dict>
            </plist>
            """,
            encoding="utf-8"
        )

        scanner = MobileSecurityScanner()
        findings = await scanner.scan(root)

        finding_ids = {f.id for f in findings}
        print("Discovered Mobile Finding IDs:", finding_ids)

        assert "FLUTTER-SSL-BYPASS" in finding_ids
        assert "FLUTTER-SHARED-PREFS-SECRET" in finding_ids
        assert "FLUTTER-CLEARTEXT-HTTP" in finding_ids
        assert "FIREBASE-OPEN-SECURITY-RULE" in finding_ids
        assert "ANDROID-ALLOW-BACKUP" in finding_ids
        assert "ANDROID-CLEARTEXT-TRAFFIC" in finding_ids
        assert "IOS-ATS-BYPASS" in finding_ids

        print("✅ test_mobile_security_scanner passed successfully with all 7 mobile checks!")


if __name__ == "__main__":
    test_shannon_entropy()
    test_false_positive_sanitizer()
    asyncio.run(test_mobile_security_scanner())
    print("\n🎉 ALL MOBILE & SANITIZER TESTS PASSED!")
