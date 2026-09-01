"""
Zero-Noise & False-Positive Sanitizer for Aegis.
Implements Shannon Entropy analysis and context-aware filtering to eliminate
dummy keys, test fixtures, mocks, and low-entropy hallucinations.
"""

import math
import re
from pathlib import Path
from typing import List, Optional, Set

from aegis.scanners.models import Severity, VulnerabilityFinding

# Known dummy/placeholder keywords
PLACEHOLDER_REGEX = re.compile(
    r"(?i)(your[_-]?(api[_-]?)?key|insert[_-]?(token|key)|replace[_-]?me|dummy[_-]?token|"
    r"test[_-]?secret|example[_-]?key|fake[_-]?api|placeholder|sample[_-]?key|"
    r"12345678|abcdef|xxxxxx|000000|todo|sk_test_|pk_test_|test_token|demo_secret)"
)

# Test and mock path patterns
TEST_PATH_REGEX = re.compile(
    r"(^|/)(tests?|__tests__|mocks?|fixtures?|examples?|samples?|test_data)/|"
    r"(\.example|\.sample|\.mock|\.test|\.spec)\.[a-zA-Z0-9]+$|"
    r"(_test\.dart|test_.*\.py|\.test\.(js|ts|jsx|tsx)|\.spec\.(js|ts|jsx|tsx))$",
    re.IGNORECASE,
)


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon Entropy for a given string: H(X) = -sum(P(x) * log2(P(x))).
    High entropy (H > 3.8) indicates cryptographically strong random secrets/keys.
    Low entropy (H < 3.2) indicates predictable text, repeated chars, or dummy strings.
    """
    if not data:
        return 0.0

    length = len(data)
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return round(entropy, 3)


class FalsePositiveSanitizer:
    """
    Sanitizes security scan results using Shannon entropy, placeholder detection,
    and test-path heuristics to ensure zero-noise actionable alerts.
    """

    def __init__(self, min_secret_entropy: float = 3.6, filter_test_paths: bool = True) -> None:
        self.min_secret_entropy = min_secret_entropy
        self.filter_test_paths = filter_test_paths

    @staticmethod
    def is_placeholder_text(text: str) -> bool:
        """Check if snippet or secret matches obvious dummy placeholder patterns."""
        if not text:
            return True

        if PLACEHOLDER_REGEX.search(text):
            return True

        # Check for angle bracket placeholders like <YOUR_KEY> or {API_KEY}
        if re.search(r"<[A-Z0-9_ -]{3,}>|\{[A-Z0-9_ -]{3,}\}", text):
            return True

        return False

    @staticmethod
    def is_test_file(file_path: str) -> bool:
        """Identify if file is located in a test, mock, or fixture path."""
        norm_path = file_path.replace("\\", "/")
        return bool(TEST_PATH_REGEX.search(norm_path))

    def is_valid_secret_entropy(self, secret_candidate: str) -> bool:
        """Validate whether candidate secret has sufficient Shannon entropy."""
        clean = secret_candidate.strip("\"' \t\n\r")
        if len(clean) < 8:
            return False

        # If it's a known placeholder, it's invalid
        if self.is_placeholder_text(clean):
            return False

        entropy = calculate_shannon_entropy(clean)
        return entropy >= self.min_secret_entropy

    def sanitize_finding(self, finding: VulnerabilityFinding) -> Optional[VulnerabilityFinding]:
        """
        Validate single finding. Returns sanitized finding or None if classified as False Positive.
        """
        file_path = finding.file_path.lower()

        # 1. Path Filtering: Filter out tests, examples, and mock files for high/critical findings
        if self.filter_test_paths and self.is_test_file(finding.file_path):
            # If in test file and not explicitly a dangerous shell/eval, drop or demote to INFO
            if "eval" not in finding.title.lower() and "sqli" not in finding.title.lower():
                return None

        # 2. Secret & API Key Sanitization
        is_secret_rule = any(
            kw in finding.title.lower() or kw in finding.id.lower()
            for kw in ["secret", "api key", "token", "credential", "private key", "password"]
        )

        if is_secret_rule:
            snippet = finding.code_snippet or ""
            # Extract potential string literal values from snippet
            literals = re.findall(r"['\"]([a-zA-Z0-9_\-\.\:\/]{8,})['\"]", snippet)

            if literals:
                # Check if at least one literal is high entropy and not a placeholder
                valid_secrets = [
                    lit for lit in literals
                    if not self.is_placeholder_text(lit) and calculate_shannon_entropy(lit) >= self.min_secret_entropy
                ]
                if not valid_secrets:
                    # All extracted literals were low entropy or placeholders
                    return None
            else:
                # Check snippet directly
                if self.is_placeholder_text(snippet):
                    return None

        return finding

    def sanitize_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Filter a list of findings, stripping out false positives and noise."""
        clean_findings: List[VulnerabilityFinding] = []
        seen_keys: Set[str] = set()

        for f in findings:
            validated = self.sanitize_finding(f)
            if not validated:
                continue

            # Deduplication key: file + line + title
            dedup_key = f"{validated.file_path}:{validated.line_start}:{validated.title}"
            if dedup_key in seen_keys:
                continue

            seen_keys.add(dedup_key)
            clean_findings.append(validated)

        return clean_findings
