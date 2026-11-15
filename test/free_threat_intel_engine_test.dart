import 'package:cobra_shield/services/free_threat_intel_engine.dart';
import 'package:cobra_shield/services/http_util.dart';
import 'package:cobra_shield/services/online_intel.dart';
import 'package:cobra_shield/services/threat_intel_repository.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  setUp(() async {
    await ThreatIntelRepository.resetProcessCacheForTesting();
    SharedPreferences.setMockInitialValues(<String, Object>{});
    OnlineIntel.resetPhishTankRateLimitForTesting();
  });

  tearDown(() {
    httpOverride = null;
    OnlineIntel.resetPhishTankRateLimitForTesting();
  });

  test('الوضع المجاني يستعلم من PhishTank فقط عند تخطي RDAP', () async {
    final hosts = <String>[];
    httpOverride = (method, uri, {headers, body}) async {
      hosts.add(uri.host);
      expect(uri.host, 'checkurl.phishtank.com');
      expect(method, 'POST');
      return const HttpResult(200, '{"results":{"in_database":false}}');
    };

    final results = await FreeThreatIntelEngine.inspect(
      url: 'https://example.test/',
      domain: 'example.test',
      skipDomainAge: true,
      repository: ThreatIntelRepository.forTest(),
    );

    expect(results, hasLength(2));
    expect(results.first.source, 'عمر الدومين (RDAP)');
    expect(results.first.status, IntelStatus.skipped);
    expect(results.last.source, 'PhishTank');
    expect(results.last.status, IntelStatus.clean);
    expect(hosts, <String>['checkurl.phishtank.com']);
  });

  test('الوضع المجاني يشغّل RDAP وPhishTank بشكل مستقل ولا يستدعي خدمات مدفوعة', () async {
    final hosts = <String>[];
    httpOverride = (method, uri, {headers, body}) async {
      hosts.add(uri.host);
      if (uri.host == 'rdap.org') {
        return const HttpResult(200,
            '{"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}');
      }
      if (uri.host == 'checkurl.phishtank.com') {
        return const HttpResult(200, '{"results":{"in_database":false}}');
      }
      fail('مصدر غير مصرح به في الوضع المجاني: ${uri.host}');
    };

    final results = await FreeThreatIntelEngine.inspect(
      url: 'https://example.test/',
      domain: 'example.test',
      skipDomainAge: false,
      repository: ThreatIntelRepository.forTest(),
    );

    expect(results, hasLength(2));
    expect(results.map((e) => e.status), contains(IntelStatus.clean));
    expect(hosts.toSet(), <String>{'rdap.org', 'checkurl.phishtank.com'});
  });

  test('تعطل PhishTank لا يلغي نتيجة RDAP ولا يرمي استثناء', () async {
    httpOverride = (method, uri, {headers, body}) async {
      if (uri.host == 'rdap.org') {
        return const HttpResult(200,
            '{"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}');
      }
      if (uri.host == 'checkurl.phishtank.com') {
        return const HttpResult(503, '');
      }
      fail('مصدر غير متوقع: ${uri.host}');
    };

    final results = await FreeThreatIntelEngine.inspect(
      url: 'https://example.test/',
      domain: 'example.test',
      skipDomainAge: false,
      repository: ThreatIntelRepository.forTest(),
    );

    expect(results, hasLength(2));
    expect(results.first.source, 'عمر الدومين (RDAP)');
    expect(results.first.status, IntelStatus.clean);
    expect(results.last.source, 'PhishTank');
    expect(results.last.status, IntelStatus.error);
  });

}
