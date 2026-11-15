import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/http_util.dart';
import 'package:cobra_shield/services/online_intel.dart';
import 'package:flutter_test/flutter_test.dart';

const String _key = 'SECRET-KEY-12345';

void mockHttp(
  HttpResult Function(String method, Uri uri, Map<String, String>? headers, String? body) make,
) {
  httpOverride = (String method, Uri uri, {Map<String, String>? headers, String? body}) async =>
      make(method, uri, headers, body);
}

HttpResult jsonRes(int status, Object body) => HttpResult(status, jsonEncode(body));

void main() {
  tearDown(() {
    httpOverride = null;
    OnlineIntel.resetPhishTankRateLimitForTesting();
  });

  group('Google Web Risk Lookup', () {
    test('بدون مفتاح: notConfigured ومفيش طلب شبكة ولا نقاط', () async {
      mockHttp((m, u, h, b) => fail('لازم ما يتصلش بدون مفتاح'));
      final r = await OnlineIntel.webRisk('https://a.example.com/', '');
      expect(r.status, IntelStatus.notConfigured);
      expect(r.findings, isEmpty);
      expect(r.message, contains('غير مُعدّة'));
      expect(r.message, contains('لا يعني إنه نظيف'));
    });

    test('المفتاح المعطوب يُرفض قبل أي طلب شبكة', () async {
      mockHttp((m, u, h, b) => fail('لازم ما يتبعتش مفتاح معطوب'));
      for (final bad in <String>['abc\ndef12345', 'has space 12345', 'مفتاح-عربي-12345', 'short']) {
        final r = await OnlineIntel.webRisk('https://a.example.com/', bad);
        expect(r.status, IntelStatus.error, reason: bad);
        expect(r.findings, isEmpty);
        expect(r.message.contains(bad), isFalse);
      }
    });

    test('يستخدم GET على Web Risk ويرسل أنواع التهديد الأربعة والرابط مرمّزًا', () async {
      late Uri seen;
      late String seenMethod;
      mockHttp((m, u, h, b) {
        seen = u;
        seenMethod = m;
        expect(h?['accept'], 'application/json');
        expect(b, isNull);
        return jsonRes(200, <String, Object>{});
      });
      await OnlineIntel.webRisk('https://a.example.com/a?q=1&b=two', _key);
      expect(seenMethod, 'GET');
      expect(seen.host, 'webrisk.googleapis.com');
      expect(seen.path, '/v1/uris:search');
      expect(seen.queryParameters['uri'], 'https://a.example.com/a?q=1&b=two');
      expect(seen.queryParameters['key'], _key);
      expect(seen.queryParametersAll['threatTypes'], containsAll(<String>[
        'MALWARE', 'SOCIAL_ENGINEERING', 'SOCIAL_ENGINEERING_EXTENDED_COVERAGE',
        'UNWANTED_SOFTWARE',
      ]));
    });

    test('تطابق تهديد مؤكد: يقرأ threat.threatTypes ويعطي 80 نقطة', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{
        'threat': <String, Object>{
          'threatTypes': <String>['SOCIAL_ENGINEERING', 'MALWARE'],
          'expireTime': '2027-01-01T00:00:00Z',
        },
      }));
      final r = await OnlineIntel.webRisk('https://bad.example.com/x', _key);
      expect(r.source, 'Google Web Risk');
      expect(r.status, IntelStatus.hit);
      expect(r.findings.single.confirmed, isTrue);
      expect(r.findings.single.points, 80);
      expect(r.message, contains('تصيّد'));
      expect(r.message, contains('برمجيات خبيثة'));
    });

    test('الرد الفارغ يعني لا تطابق معروف، دون ادعاء أن الرابط آمن', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{}));
      final r = await OnlineIntel.webRisk('https://ok.example.com/', _key);
      expect(r.status, IntelStatus.clean);
      expect(r.findings.single.severity, Severity.good);
      expect(r.findings.single.points, 0);
      expect(r.findings.single.detail, contains('قد يكون التهديد جديدًا'));
      expect(r.message, contains('لا يضمن الأمان'));
    });

    test('أي بنية 200 غير معروفة لا تتحول إلى clean', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{'unexpected': true}));
      final r = await OnlineIntel.webRisk('https://schema.example.com/', _key);
      expect(r.status, IntelStatus.error);
      expect(r.findings, isEmpty);
      expect(r.message, contains('غير متوقع'));
    });

    for (final code in <int>[400, 401, 403, 429, 500, 503]) {
      test('رد $code = error وليس clean ولا يكشف المفتاح', () async {
        mockHttp((m, u, h, b) => HttpResult(code, ''));
        final r = await OnlineIntel.webRisk('https://a.example.com/', _key);
        expect(r.status, IntelStatus.error);
        expect(r.findings, isEmpty);
        expect(r.message.contains(_key), isFalse);
      });
    }

    test('رد JSON معطوب وأخطاء الشبكة = error', () async {
      mockHttp((m, u, h, b) => const HttpResult(200, '{not json'));
      expect((await OnlineIntel.webRisk('https://a.example.com/', _key)).status,
          IntelStatus.error);
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw const SocketException('x');
      expect((await OnlineIntel.webRisk('https://a.example.com/', _key)).status,
          IntelStatus.error);
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw TimeoutException('x');
      expect((await OnlineIntel.webRisk('https://a.example.com/', _key)).status,
          IntelStatus.error);
    });

    test('الاسم القديم safeBrowsing يظل متوافقًا لكنه يستخدم Web Risk', () async {
      late Uri seen;
      mockHttp((m, u, h, b) {
        seen = u;
        return jsonRes(200, <String, Object>{});
      });
      final r = await OnlineIntel.safeBrowsing('https://compat.example.com/', _key);
      expect(seen.host, 'webrisk.googleapis.com');
      expect(r.source, 'Google Web Risk');
    });
  });


  group('PhishTank المجاني', () {
    const sampleUrl = 'https://login.example.test/account?a=1&b=two';

    test('يستخدم POST إلى API الرسمي بدون مفتاح ويرسل User-Agent وصيغة JSON', () async {
      late String method;
      late Uri uri;
      late Map<String, String>? headers;
      late String? body;
      mockHttp((m, u, h, b) {
        method = m;
        uri = u;
        headers = h;
        body = b;
        return jsonRes(200, <String, Object>{
          'results': <String, Object>{'in_database': false},
        });
      });

      final result = await OnlineIntel.phishTank(sampleUrl);
      expect(result.status, IntelStatus.clean);
      expect(method, 'POST');
      expect(uri.host, 'checkurl.phishtank.com');
      expect(uri.path, '/checkurl/');
      expect(headers?['content-type'], 'application/x-www-form-urlencoded');
      expect(headers?['accept'], 'application/json');
      expect(headers?['user-agent'], contains('LinkScanner'));
      expect(body, contains('url=${Uri.encodeQueryComponent(sampleUrl)}'));
      expect(body, contains('format=json'));
    });

    test('رابط verified وvalid يصنف تصيّد مؤكد', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{
        'results': <String, Object>{
          'url': sampleUrl,
          'in_database': true,
          'phish_id': 12345,
          'verified': 'y',
          'valid': 'y',
        },
      }));
      final result = await OnlineIntel.phishTank(sampleUrl);
      expect(result.status, IntelStatus.hit);
      expect(result.findings.single.confirmed, isTrue);
      expect(result.findings.single.points, 85);
      expect(result.message, contains('12345'));
    });

    test('وجود بلاغ غير مؤكد لا يتحول إلى تهديد مؤكد', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{
        'results': <String, Object>{
          'in_database': true,
          'verified': 'n',
          'valid': 'y',
        },
      }));
      final result = await OnlineIntel.phishTank(sampleUrl);
      expect(result.status, IntelStatus.info);
      expect(result.findings.single.severity, Severity.info);
      expect(result.findings.single.confirmed, isFalse);
      expect(result.findings.single.points, 0);
    });

    test('يدعم الرد المتداخل url0 كما في شكل XML متعدد النتائج', () async {
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{
        'results': <String, Object>{
          'url0': <String, Object>{
            'in_database': true,
            'verified': true,
            'valid': true,
          },
        },
      }));
      expect((await OnlineIntel.phishTank(sampleUrl)).status, IntelStatus.hit);
    });

    test('509 يحترم مهلة المصدر ولا يعامل الرابط كآمن', () async {
      var calls = 0;
      mockHttp((m, u, h, b) {
        calls++;
        return const HttpResult(509, '', headers: <String, String>{
          'x-request-limit-interval': '300 Seconds',
          'x-request-limit': '5',
          'x-request-count': '5',
        });
      });
      final first = await OnlineIntel.phishTank(sampleUrl);
      final second = await OnlineIntel.phishTank('https://another.example.test/');
      expect(first.status, IntelStatus.error);
      expect(second.status, IntelStatus.skipped);
      expect(calls, 1);
      expect(first.findings, isEmpty);
    });

    test('الرد المعطوب أو غير المكتمل أو خطأ الشبكة لا يتحول إلى clean', () async {
      mockHttp((m, u, h, b) => const HttpResult(200, '{broken'));
      expect((await OnlineIntel.phishTank(sampleUrl)).status, IntelStatus.error);
      OnlineIntel.resetPhishTankRateLimitForTesting();

      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{'unexpected': true}));
      expect((await OnlineIntel.phishTank(sampleUrl)).status, IntelStatus.error);
      OnlineIntel.resetPhishTankRateLimitForTesting();

      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw const SocketException('offline');
      expect((await OnlineIntel.phishTank(sampleUrl)).status, IntelStatus.error);
    });

    test('الاستجابة المقطوعة لا يتم اعتمادها', () async {
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          const HttpResult(200, '{"results":{}}', truncated: true);
      expect((await OnlineIntel.phishTank(sampleUrl)).status, IntelStatus.error);
    });

    test('المدخل غير الصالح لا يرسل أي طلب', () async {
      mockHttp((m, u, h, b) => fail('لا يجب إرسال رابط غير صالح'));
      expect((await OnlineIntel.phishTank('file:///etc/passwd')).status,
          IntelStatus.skipped);
    });

  });

  group('VirusTotal', () {
    Object stats({int mal = 0, int sus = 0, int harmless = 60, int undetected = 10}) =>
        <String, Object>{
          'data': <String, Object>{
            'attributes': <String, Object>{
              'last_analysis_stats': <String, int>{
                'malicious': mal,
                'suspicious': sus,
                'harmless': harmless,
                'undetected': undetected,
              },
            },
          },
        };

    test('بدون مفتاح: notConfigured وبدون طلب شبكة', () async {
      mockHttp((m, u, h, b) => fail('لازم ما يتصلش بدون مفتاح'));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', '');
      expect(r.status, IntelStatus.notConfigured);
      expect(r.findings, isEmpty);
    });

    test('المفتاح بيتبعت في الهيدر فقط مش في العنوان', () async {
      late Uri seen;
      Map<String, String>? seenHeaders;
      mockHttp((m, u, h, b) {
        seen = u;
        seenHeaders = h;
        return jsonRes(200, stats());
      });
      await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(seenHeaders?['x-apikey'], _key);
      expect(seen.toString().contains(_key), isFalse);
      expect(seen.host, 'www.virustotal.com');
    });

    test('3 محركات أو أكتر = تهديد مؤكد', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats(mal: 5)));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.status, IntelStatus.hit);
      expect(r.findings.single.confirmed, isTrue);
      expect(r.findings.single.points, 70);
    });

    test('محرك واحد = اشتباه بدون تأكيد', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats(mal: 1)));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.findings.single.confirmed, isFalse);
      expect(r.findings.single.points, 35);
    });

    test('مشبوه فقط = 20 نقطة', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats(sus: 2)));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.findings.single.points, 20);
    });

    test('لا رصد: clean بدون نقاط ومع تنبيه إنه لا يضمن الأمان', () async {
      mockHttp((m, u, h, b) => jsonRes(200, stats()));
      final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
      expect(r.status, IntelStatus.clean);
      expect(r.findings.single.points, 0);
      expect(r.findings.single.detail, contains('لا يضمن'));
    });

    test('404 (لم يُفحص) = info مش clean، وبدون نتايج تحليل = info', () async {
      mockHttp((m, u, h, b) => const HttpResult(404, ''));
      expect((await OnlineIntel.virusTotal('https://a.example.com/', _key)).status,
          IntelStatus.info);
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{'data': <String, Object>{}}));
      expect((await OnlineIntel.virusTotal('https://a.example.com/', _key)).status,
          IntelStatus.info);
    });

    for (final code in <int>[401, 403, 429, 500]) {
      test('رد $code = error', () async {
        mockHttp((m, u, h, b) => HttpResult(code, ''));
        final r = await OnlineIntel.virusTotal('https://a.example.com/', _key);
        expect(r.status, IntelStatus.error);
        expect(r.message.contains(_key), isFalse);
      });
    }
  });

  group('عمر الدومين (RDAP)', () {
    HttpResult registeredDaysAgo(int days) {
      final d = DateTime.now().toUtc().subtract(Duration(days: days));
      return jsonRes(200, <String, Object>{
        'events': <Object>[
          <String, String>{
            'eventAction': 'registration',
            'eventDate': d.toIso8601String(),
          },
        ],
      });
    }

    test('دومين عمره 3 أيام: خطر 40 نقطة', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(3));
      final r = await OnlineIntel.rdap('new.example.com');
      expect(r.status, IntelStatus.hit);
      expect(r.findings.single.points, 40);
      expect(r.findings.single.confirmed, isFalse);
    });

    test('دومين عمره 15 يوم = 30، و60 يوم = 15، و200 يوم = 5', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(15));
      expect((await OnlineIntel.rdap('a.example.com')).findings.single.points, 30);
      mockHttp((m, u, h, b) => registeredDaysAgo(60));
      expect((await OnlineIntel.rdap('a.example.com')).findings.single.points, 15);
      mockHttp((m, u, h, b) => registeredDaysAgo(200));
      expect((await OnlineIntel.rdap('a.example.com')).findings.single.points, 5);
    });

    test('دومين قديم: clean بدون نقاط', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(2000));
      final r = await OnlineIntel.rdap('old.example.com');
      expect(r.status, IntelStatus.clean);
      expect(r.findings.single.points, 0);
    });

    test('الطلب بيروح لـ rdap.org بمسار الدومين فقط (مفيش الرابط الكامل)', () async {
      late Uri seen;
      mockHttp((m, u, h, b) {
        seen = u;
        return registeredDaysAgo(2000);
      });
      await OnlineIntel.rdap('shop.example.co.uk');
      expect(seen.scheme, 'https');
      expect(seen.host, 'rdap.org');
      expect(seen.path, '/domain/shop.example.co.uk');
      expect(seen.hasQuery, isFalse);
    });

    test('اسم غير ASCII أو غير قياسي ما بيتبعتش: skipped بدون شبكة', () async {
      mockHttp((m, u, h, b) => fail('لازم ما يتصلش'));
      for (final d in <String>['مثال.com', 'a b.com', 'a/b.com', 'example', '', 'a..com', '-a.com', '8.8.8.8']) {
        final r = await OnlineIntel.rdap(d);
        expect(r.status, IntelStatus.skipped, reason: d);
      }
    });

    test('punycode مسموح (دومين دولي بشكله ASCII)', () async {
      mockHttp((m, u, h, b) => registeredDaysAgo(2000));
      final r = await OnlineIntel.rdap('xn--mnchen-3ya.de');
      expect(r.status, IntelStatus.clean);
    });

    test('فشل RDAP (مهلة/شبكة) = error بدون نقاط (مفيش نقاط عشوائية عند فشل مصدر خارجي)', () async {
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw TimeoutException('x');
      final t = await OnlineIntel.rdap('a.example.com');
      expect(t.status, IntelStatus.error);
      expect(t.findings, isEmpty);
      httpOverride = (String m, Uri u, {Map<String, String>? headers, String? body}) async =>
          throw const SocketException('x');
      final n = await OnlineIntel.rdap('a.example.com');
      expect(n.status, IntelStatus.error);
      expect(n.findings, isEmpty);
    });

    test('404 / بدون تاريخ = skipped، و500 = error', () async {
      mockHttp((m, u, h, b) => const HttpResult(404, ''));
      expect((await OnlineIntel.rdap('a.example.com')).status, IntelStatus.skipped);
      mockHttp((m, u, h, b) => jsonRes(200, <String, Object>{'events': <Object>[]}));
      expect((await OnlineIntel.rdap('a.example.com')).status, IntelStatus.skipped);
      mockHttp((m, u, h, b) => const HttpResult(500, ''));
      expect((await OnlineIntel.rdap('a.example.com')).status, IntelStatus.error);
    });
  });
}
