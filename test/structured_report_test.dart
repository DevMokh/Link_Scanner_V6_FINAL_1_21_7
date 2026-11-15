import 'dart:convert';

import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/url_analyzer.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Structured JSON report', () {
    test('exports a stable schema and omits the raw path/query by default', () {
      const privateToken = 'SESSION_SECRET_123';
      final result = UrlAnalyzer.analyze(
        'https://example.com/account/reset?token=$privateToken',
      );

      final serialized = result.toJsonReport();
      final decoded = jsonDecode(serialized) as Map<String, dynamic>;
      final url = decoded['url'] as Map<String, dynamic>;

      expect(decoded['schema_version'], 1);
      expect(decoded['application'], 'Link Scanner');
      expect(decoded['verdict'], result.verdict.name);
      expect(url['hostname'], 'example.com');
      expect(url['full_url_included'], isFalse);
      expect(decoded['url_contents_redacted'], isTrue);
      expect(serialized, isNot(contains(privateToken)));
      expect(serialized, isNot(contains('/account/reset')));
      expect(serialized, isNot(contains('token=')));
      expect(decoded['findings'], isA<List<dynamic>>());
      expect(decoded['generated_at_utc'], isA<String>());
    });

    test('invalid input exports null risk score, not a false safe zero', () {
      final result = UrlAnalyzer.analyze('not a URL');
      final decoded = jsonDecode(result.toJsonReport()) as Map<String, dynamic>;

      expect(decoded['verdict'], Verdict.invalidInput.name);
      expect(decoded['score'], isNull);
      expect(decoded['risk_level'], isNull);
      expect(decoded['issue_code'], isNotNull);
    });
  });
}
