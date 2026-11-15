import unittest
import subprocess
import sys
import tempfile
from pathlib import Path

from update_unicode_confusables import parse_confusables, render_dart


class UnicodeConfusablesGeneratorTests(unittest.TestCase):
    SAMPLE = """# confusables.txt
# Version: 18.0.0
0430 ; 0061 ; MA # CYRILLIC SMALL LETTER A
04CF ; 006C ; MA # CYRILLIC SMALL LETTER PALOCHKA
00E6 ; 0061 0065 ; MA # LATIN SMALL LETTER AE
1F600 ; 1F600 ; MA # GRINNING FACE
"""

    def test_parses_only_printable_ascii_targets(self):
        mappings = parse_confusables(self.SAMPLE, "18.0.0")
        self.assertEqual(mappings, {0x0430: "a", 0x04CF: "l", 0x00E6: "ae"})

    def test_rejects_version_mismatch(self):
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            parse_confusables(self.SAMPLE, "17.0.0")

    def test_renders_deterministic_dart_map(self):
        text = render_dart({0x0430: "a", 0x00E6: "ae"}, "18.0.0")
        self.assertIn("kUnicodeConfusablesVersion = \"18.0.0\"", text)
        self.assertIn("0x00E6: \"ae\"", text)
        self.assertLess(text.index("0x00E6"), text.index("0x0430"))

    def test_rejects_empty_or_missing_data(self):
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            parse_confusables("# empty file", "18.0.0")

    def test_dart_renderer_escapes_interpolation_markers(self):
        text = render_dart({0x2603: "$"}, "18.0.0")
        self.assertIn(r'0x2603: "\$"', text)

    def test_renderer_records_mapping_count(self):
        text = render_dart({0x0430: "a", 0x04CF: "l"}, "18.0.0")
        self.assertIn("kUnicodeConfusablesCount = 2", text)

    def test_parser_supports_multi_character_ascii_skeleton(self):
        text = "# Version: 18.0.0\n00E6 ; 0061 0065 ; MA # ae\n"
        self.assertEqual(parse_confusables(text, "18.0.0"), {0x00E6: "ae"})

    def test_parser_rejects_invalid_unicode_scalar(self):
        text = "# Version: 18.0.0\nD800 ; 0061 ; MA # invalid surrogate\n"
        with self.assertRaisesRegex(ValueError, "Invalid source scalar"):
            parse_confusables(text, "18.0.0")


    def test_minimum_mapping_guard_preserves_existing_output(self):
        script = Path(__file__).with_name("update_unicode_confusables.py")
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source = folder / "confusables.txt"
            output = folder / "unicode_confusables_data.dart"
            source.write_text(self.SAMPLE, encoding="utf-8")
            output.write_text("KEEP_FALLBACK\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--minimum-mappings",
                    "10",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("minimum required is 10", result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "KEEP_FALLBACK\n")


if __name__ == "__main__":
    unittest.main()
