import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../core/models.dart';
import 'http_util.dart';

/// حالة نتيجة مصدر تهديدات واحد.
///
///  - clean: المصدر اشتغل ومارصدش الرابط (مش معناها "آمن").
///  - hit: المصدر رصد تهديد أو مؤشر.
///  - info: المصدر اشتغل لكن لا توجد بيانات حاسمة (مثل بلاغ PhishTank غير مؤكد أو منتهي).
///  - skipped: المصدر مش منطبق على المدخل (عنوان IP، رابط مختصر، امتداد بدون RDAP).
///  - notConfigured: الخدمة غير مُعدّة (مفتاح API ناقص):
///    الرابط ما اتفحصش بيها، وده مش معناه إنه نظيف ولا بيتحسب كفشل في الفحص.
///  - error: المصدر فشل (مهلة / شبكة / مفتاح مرفوض / رد غير مفهوم): الفحص ناقص.
///    مفيش نقاط ولا حكم "نظيف" بيتبني على الحالة دي.
enum IntelStatus { clean, hit, info, skipped, notConfigured, error }

class IntelResult {
  const IntelResult({
    required this.source,
    required this.status,
    required this.message,
    this.findings = const <Finding>[],
    this.fromCache = false,
    this.checkedAt,
  });

  final String source;
  final IntelStatus status;
  final String message;
  final List<Finding> findings;

  /// true when this result was loaded from the local TTL cache, not fetched now.
  final bool fromCache;

  /// Time the underlying provider result was originally fetched, if known.
  final DateTime? checkedAt;
}

/// مصادر الاستعلام الحي. كل دالة لا ترمي استثناء: تعيد IntelResult دائمًا.
class OnlineIntel {
  OnlineIntel._();

  static const String _notConfiguredMsg =
      'الخدمة غير مُعدّة: أضف مفتاح API من تبويب أدوات. الرابط ما اتفحصش بها، وده لا يعني إنه نظيف.';
  static const String _badKeyMsg =
      'شكل المفتاح غير صالح (مسافات أو رموز غير مسموحة). لم يُرسل شيء. أعد إدخاله من تبويب أدوات.';

  /// فحص شكلي بس للمفتاح قبل ما نبعته: ASCII مطبوع من غير مسافات أو رموز تحكم، وطول معقول.
  /// الهدف إن مفتاح معطوب (فيه سطر جديد مثلًا) ما يتحوّلش لرد "غير متوقع" مبهم أو يتبعت كهيدر شاذ.
  /// ما بنفرضش صيغة معينة لأن شكل مفاتيح الخدمات ممكن يتغيّر.
  static final RegExp _keyShape = RegExp(r'^[\x21-\x7E]{8,512}$');
  static bool isPlausibleApiKey(String key) => _keyShape.hasMatch(key);

  // ---- عمر الدومين (RDAP) ---------------------------------------------
  static String _fmtAge(int days) {
    if (days < 60) return '$days يوم';
    if (days < 730) return '${(days / 30).round()} شهر';
    return '${(days / 365).floor()} سنة';
  }

  static final RegExp _asciiDomain =
      RegExp(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');

  static final RegExp _numericOnly = RegExp(r'^[0-9.]+$');

  static Future<IntelResult> rdap(String domain) async {
    const src = 'عمر الدومين (RDAP)';
    // الدومين لازم يوصل ASCII (punycode للأسماء الدولية) وبشكل اسم مضيف عادي؛ أي شيء تاني ما بنبعتوش.
    if (!_asciiDomain.hasMatch(domain) || _numericOnly.hasMatch(domain)) {
      return const IntelResult(
        source: src,
        status: IntelStatus.skipped,
        message: 'لا ينطبق: الاسم ليس دومينًا قياسيًا قابلًا للاستعلام.',
      );
    }
    try {
      final r = await httpRequest(
        'GET',
        Uri(scheme: 'https', host: 'rdap.org', pathSegments: <String>['domain', domain]),
        headers: <String, String>{'accept': 'application/rdap+json, application/json'},
        timeout: const Duration(seconds: 12),
        maxBytes: 1024 * 1024,
      );
      if (r.status == 404) {
        return const IntelResult(
          source: src,
          status: IntelStatus.skipped,
          message: 'لا توجد بيانات RDAP لهذا الامتداد.',
        );
      }
      if (r.status != 200) {
        return IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'تعذر الاستعلام (${r.status}).',
        );
      }
      final j = jsonDecode(r.body);
      DateTime? reg;
      if (j is Map && j['events'] is List) {
        for (final e in (j['events'] as List)) {
          if (e is Map && e['eventAction'] == 'registration') {
            reg = DateTime.tryParse('${e['eventDate']}');
            break;
          }
        }
      }
      if (reg == null) {
        return const IntelResult(
          source: src,
          status: IntelStatus.skipped,
          message: 'لم يُرجع السجل تاريخ التسجيل.',
        );
      }
      final days = DateTime.now().toUtc().difference(reg.toUtc()).inDays;
      final age = _fmtAge(days < 0 ? 0 : days);
      if (days < 7) {
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: 'الدومين عمره $age فقط.',
          findings: <Finding>[
            Finding(
              severity: Severity.danger,
              title: 'دومين جديد جدًا ($age)',
              detail: 'معظم حملات التصيّد تستخدم دومينات عمرها أيام. مؤشر قوي.',
              points: 40,
            ),
          ],
        );
      }
      if (days < 30) {
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: 'الدومين عمره $age.',
          findings: <Finding>[
            Finding(
              severity: Severity.danger,
              title: 'دومين حديث ($age)',
              detail: 'الدومينات الأقل من شهر أكثر عرضة للاستخدام في الاحتيال.',
              points: 30,
            ),
          ],
        );
      }
      if (days < 90) {
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: 'الدومين عمره $age.',
          findings: <Finding>[
            Finding(
              severity: Severity.warn,
              title: 'دومين حديث نسبيًا ($age)',
              detail: 'عمر أقل من 3 شهور. ليس دليلًا بذاته لكنه يستحق الحذر.',
              points: 15,
            ),
          ],
        );
      }
      if (days < 365) {
        return IntelResult(
          source: src,
          status: IntelStatus.info,
          message: 'الدومين عمره $age.',
          findings: <Finding>[
            Finding(
              severity: Severity.info,
              title: 'عمر الدومين $age',
              detail: 'أقل من سنة.',
              points: 5,
            ),
          ],
        );
      }
      return IntelResult(
        source: src,
        status: IntelStatus.clean,
        message: 'الدومين عمره $age.',
        findings: <Finding>[
          Finding(
            severity: Severity.good,
            title: 'دومين قديم ($age)',
            detail: 'عمر الدومين لا يضمن الأمان لكنه أقل شيوعًا في الاحتيال.',
          ),
        ],
      );
    } on TimeoutException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'انتهت المهلة.',
      );
    } on SocketException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'لا يوجد اتصال بالإنترنت.',
      );
    } catch (_) {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'رد غير متوقع من RDAP.',
      );
    }
  }

  // ---- Google Web Risk Lookup API (متوافق مع مفتاح Google Cloud القديم) ----
  static String _webRiskType(String t) {
    switch (t) {
      case 'MALWARE':
        return 'برمجيات خبيثة';
      case 'SOCIAL_ENGINEERING':
      case 'SOCIAL_ENGINEERING_EXTENDED_COVERAGE':
        return 'تصيّد / هندسة اجتماعية';
      case 'UNWANTED_SOFTWARE':
        return 'برامج غير مرغوبة';
      default:
        return t;
    }
  }

  /// Lookup API الحديثة من Web Risk. يتم الاحتفاظ باسم safeBrowsing أدناه
  /// كواجهة توافق حتى لا تنكسر أي إضافات قديمة تعتمد على الاسم السابق.
  static Future<IntelResult> webRisk(String url, String key) async {
    const src = 'Google Web Risk';
    if (key.isEmpty) {
      return const IntelResult(
        source: src,
        status: IntelStatus.notConfigured,
        message: _notConfiguredMsg,
      );
    }
    if (!isPlausibleApiKey(key)) {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: _badKeyMsg,
      );
    }
    try {
      final uri = Uri(
        scheme: 'https',
        host: 'webrisk.googleapis.com',
        path: '/v1/uris:search',
        queryParameters: <String, dynamic>{
          'threatTypes': <String>[
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'SOCIAL_ENGINEERING_EXTENDED_COVERAGE',
            'UNWANTED_SOFTWARE',
          ],
          'uri': <String>[url],
          'key': <String>[key],
        },
      );
      final r = await httpRequest(
        'GET',
        uri,
        headers: <String, String>{'accept': 'application/json'},
        timeout: const Duration(seconds: 12),
        maxBytes: 256 * 1024,
        follow: false,
      );
      if (r.status == 400 || r.status == 401 || r.status == 403) {
        return const IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'مفتاح Google Cloud غير صالح أو Web Risk API غير مفعّلة في المشروع.',
        );
      }
      if (r.status == 429) {
        return const IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'تجاوزت حد طلبات Google Web Risk. جرّب لاحقًا.',
        );
      }
      if (r.status != 200) {
        return IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'رد غير متوقع من Web Risk (${r.status}).',
        );
      }

      final decoded = jsonDecode(r.body);
      if (decoded is! Map) {
        throw const FormatException('Unexpected Web Risk response type');
      }
      // توثيق Web Risk يحدد الرد الفارغ {} كحالة عدم وجود تطابق.
      // أي بنية أخرى غير مفهومة لازم تبقى error، مش clean، لتجنب الاطمئنان الكاذب.
      if (decoded.isEmpty) {
        return const IntelResult(
          source: src,
          status: IntelStatus.clean,
          message: 'لم يظهر الرابط في قوائم Web Risk التي تم الاستعلام عنها. هذا لا يضمن الأمان.',
          findings: <Finding>[
            Finding(
              severity: Severity.good,
              title: 'Google Web Risk: لا يوجد تطابق معروف',
              detail: 'لم يظهر تطابق في قوائم التهديد المطلوبة؛ قد يكون التهديد جديدًا أو غير مدرج.',
            ),
          ],
        );
      }
      final threat = decoded['threat'];
      if (threat is! Map || threat['threatTypes'] is! List) {
        throw const FormatException('Unexpected Web Risk threat schema');
      }
      final types = (threat['threatTypes'] as List)
          .whereType<String>()
          .toSet()
          .toList();
      if (types.isEmpty) {
        throw const FormatException('Web Risk threatTypes is empty or invalid');
      }
      final labels = types.map(_webRiskType).toSet().join('، ');
      return IntelResult(
        source: src,
        status: IntelStatus.hit,
        message: 'Google Web Risk يصنّفه: $labels.',
        findings: <Finding>[
          Finding(
            severity: Severity.danger,
            title: 'Google Web Risk: موقع غير آمن',
            detail: 'أنواع التهديد المطابقة: $labels.',
            points: 80,
            confirmed: true,
          ),
        ],
      );
    } on TimeoutException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'انتهت مهلة الاتصال بـ Google Web Risk.',
      );
    } on SocketException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'لا يوجد اتصال بالإنترنت عند الاستعلام من Web Risk.',
      );
    } catch (_) {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'رد غير متوقع من Google Web Risk.',
      );
    }
  }

  /// اسم قديم محفوظ للتوافق مع الإضافات والبيانات السابقة؛ ينفذ Web Risk وليس Safe Browsing v4.
  static Future<IntelResult> safeBrowsing(String url, String key) =>
      webRisk(url, key);


  // ---- PhishTank Community API (مجاني، دون مفتاح في الوضع المحدود) ----
  static DateTime? _phishTankLastRequestAt;
  static DateTime? _phishTankBlockedUntil;
  static const Duration _phishTankMinimumGap = Duration(seconds: 5);

  /// يعيد حالة قيمة API بصيغ bool و"true"/"false" و"y"/"n".
  static bool? _phishTankFlag(Object? value) {
    if (value is bool) return value;
    if (value is num) return value != 0;
    if (value is String) {
      switch (value.trim().toLowerCase()) {
        case 'true':
        case 'yes':
        case 'y':
        case '1':
          return true;
        case 'false':
        case 'no':
        case 'n':
        case '0':
          return false;
      }
    }
    return null;
  }

  static Duration? _phishTankRateInterval(Map<String, String> headers) {
    final raw = headers['x-request-limit-interval'];
    if (raw == null) return null;
    final match = RegExp(r'(\d+)\s+seconds?', caseSensitive: false).firstMatch(raw);
    final seconds = int.tryParse(match?.group(1) ?? '');
    if (seconds == null || seconds <= 0 || seconds > 86400) return null;
    return Duration(seconds: seconds);
  }

  static void _updatePhishTankRateGate(HttpResult response, DateTime now) {
    final interval = _phishTankRateInterval(response.headers);
    final limit = int.tryParse(response.headers['x-request-limit'] ?? '');
    final count = int.tryParse(response.headers['x-request-count'] ?? '');
    final exhausted = limit != null && count != null && limit > 0 && count >= limit;
    if (response.status == 509 || response.status == 429 || exhausted) {
      // If a rate-limited response omits its interval, pause for 15 minutes.
      // This is a local backoff only; it does not claim the provider limit is 15m.
      final delay = interval ?? const Duration(minutes: 15);
      final until = now.add(delay);
      if (_phishTankBlockedUntil == null || until.isAfter(_phishTankBlockedUntil!)) {
        _phishTankBlockedUntil = until;
      }
    }
  }

  /// Test helper to isolate rate-limit state between tests.
  static void resetPhishTankRateLimitForTesting() {
    _phishTankLastRequestAt = null;
    _phishTankBlockedUntil = null;
  }

  /// Checks a URL against PhishTank's free URL lookup API.
  /// The complete URL is transmitted only from the advanced online scan flow,
  /// which already requires explicit user consent. No API key is required;
  /// PhishTank documents lower rate limits without an application key.
  static Future<IntelResult> phishTank(String url) async {
    const src = 'PhishTank';
    final parsed = Uri.tryParse(url);
    if (parsed == null ||
        (parsed.scheme != 'http' && parsed.scheme != 'https') ||
        parsed.host.isEmpty ||
        parsed.userInfo.isNotEmpty ||
        url.length > 8192) {
      return const IntelResult(
        source: src,
        status: IntelStatus.skipped,
        message: 'الرابط غير مناسب لاستعلام PhishTank.',
      );
    }

    final now = DateTime.now().toUtc();
    final blockedUntil = _phishTankBlockedUntil;
    if (blockedUntil != null && blockedUntil.isAfter(now)) {
      return IntelResult(
        source: src,
        status: IntelStatus.skipped,
        message: 'تم إيقاف استعلام PhishTank مؤقتًا احترامًا لحد الطلبات. جرّب لاحقًا؛ لم يتم التحقق من الرابط بهذا المصدر.',
      );
    }
    final last = _phishTankLastRequestAt;
    if (last != null && now.difference(last) < _phishTankMinimumGap) {
      return const IntelResult(
        source: src,
        status: IntelStatus.skipped,
        message: 'تم تأجيل استعلام PhishTank لثوانٍ قليلة لتقليل الطلبات. لم يتم التحقق من الرابط بهذا المصدر.',
      );
    }

    _phishTankLastRequestAt = now;
    try {
      final body = 'url=${Uri.encodeQueryComponent(url)}&format=json';
      final response = await httpRequest(
        'POST',
        Uri.https('checkurl.phishtank.com', '/checkurl/'),
        headers: const <String, String>{
          'accept': 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
          'user-agent': 'LinkScanner/1.19.0 (free URL security scanner)',
        },
        body: body,
        timeout: const Duration(seconds: 8),
        totalTimeout: const Duration(seconds: 10),
        maxBytes: 256 * 1024,
        follow: false,
      );
      _updatePhishTankRateGate(response, DateTime.now().toUtc());
      if (response.truncated) {
        return const IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'رد PhishTank تجاوز حد الحجم؛ لم يتم اعتماد النتيجة.',
        );
      }
      if (response.status == 509 || response.status == 429) {
        return const IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'PhishTank فرض حدًا للطلبات. أوقفنا الاستعلام مؤقتًا؛ لم يتم اعتبار الرابط نظيفًا.',
        );
      }
      if (response.status != 200) {
        return IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'تعذر الاستعلام من PhishTank (${response.status}).',
        );
      }

      final decoded = jsonDecode(response.body);
      if (decoded is! Map || decoded['results'] is! Map) {
        throw const FormatException('Unexpected PhishTank response schema');
      }
      final rawResults = decoded['results'] as Map;
      Map? result;
      if (rawResults.containsKey('in_database')) {
        result = rawResults;
      } else {
        for (final value in rawResults.values) {
          if (value is Map && value.containsKey('in_database')) {
            result = value;
            break;
          }
        }
      }
      if (result == null) {
        throw const FormatException('Missing PhishTank URL result');
      }
      final inDatabase = _phishTankFlag(result['in_database']);
      if (inDatabase == null) {
        throw const FormatException('Invalid PhishTank in_database flag');
      }
      if (!inDatabase) {
        return const IntelResult(
          source: src,
          status: IntelStatus.clean,
          message: 'لم يسجل PhishTank هذا الرابط كتصيّد معروف. هذا لا يضمن أمانه.',
          findings: <Finding>[
            Finding(
              severity: Severity.good,
              title: 'PhishTank: لا يوجد تطابق معروف',
              detail: 'لم يظهر الرابط في قاعدة PhishTank وقت الاستعلام؛ قد يكون تهديدًا جديدًا أو غير مدرج.',
            ),
          ],
        );
      }

      final verified = _phishTankFlag(result['verified']);
      final valid = _phishTankFlag(result['valid']);
      if (verified == true && valid == true) {
        final phishId = '${result['phish_id'] ?? ''}'.trim();
        final suffix = phishId.isEmpty ? '' : ' (ID: $phishId)';
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: 'PhishTank أكد أن الرابط تصيّد نشط$suffix.',
          findings: <Finding>[
            Finding(
              code: 'phishtank_verified_phish',
              severity: Severity.danger,
              title: 'PhishTank: تصيّد مؤكد',
              detail: 'الرابط موجود في قاعدة PhishTank وتم التحقق منه وما زال صالحًا.',
              points: 85,
              confirmed: true,
              family: 'phishing',
            ),
          ],
        );
      }
      return const IntelResult(
        source: src,
        status: IntelStatus.info,
        message: 'الرابط موجود في PhishTank لكن حالته غير مؤكدة أو لم تعد صالحة؛ لم نعتبره تهديدًا مؤكدًا.',
        findings: <Finding>[
          Finding(
            severity: Severity.info,
            title: 'PhishTank: بلاغ غير مؤكد أو منتهي',
            detail: 'وجود بلاغ وحده لا يكفي لتصنيف الرابط كتصيّد نشط.',
          ),
        ],
      );
    } on TimeoutException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'انتهت مهلة PhishTank؛ بقية فحوص التطبيق تستمر بشكل طبيعي.',
      );
    } on SocketException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'PhishTank غير متاح بسبب مشكلة اتصال؛ لم يتم اعتبار الرابط نظيفًا.',
      );
    } catch (_) {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'رد غير متوقع من PhishTank؛ لم يتم اعتماد النتيجة.',
      );
    }
  }

  // ---- VirusTotal (مفتاحك) --------------------------------------------
  static Future<IntelResult> virusTotal(String url, String key) async {
    const src = 'VirusTotal';
    if (key.isEmpty) {
      return const IntelResult(
        source: src,
        status: IntelStatus.notConfigured,
        message: _notConfiguredMsg,
      );
    }
    if (!isPlausibleApiKey(key)) {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: _badKeyMsg,
      );
    }
    try {
      final id = base64Url.encode(utf8.encode(url)).replaceAll('=', '');
      final r = await httpRequest(
        'GET',
        Uri.parse('https://www.virustotal.com/api/v3/urls/$id'),
        headers: <String, String>{'x-apikey': key},
        timeout: const Duration(seconds: 12),
      );
      if (r.status == 404) {
        return const IntelResult(
          source: src,
          status: IntelStatus.info,
          message: 'الرابط لم يُفحص من قبل لدى VirusTotal.',
        );
      }
      if (r.status == 401 || r.status == 403) {
        return const IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'مفتاح VirusTotal غير صالح.',
        );
      }
      if (r.status == 429) {
        return const IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'تجاوزت حد الطلبات (المفتاح المجاني 4 طلبات/دقيقة).',
        );
      }
      if (r.status != 200) {
        return IntelResult(
          source: src,
          status: IntelStatus.error,
          message: 'رد غير متوقع (${r.status}).',
        );
      }
      final j = jsonDecode(r.body);
      Map<dynamic, dynamic>? stats;
      if (j is Map && j['data'] is Map) {
        final attrs = (j['data'] as Map)['attributes'];
        if (attrs is Map && attrs['last_analysis_stats'] is Map) {
          stats = attrs['last_analysis_stats'] as Map;
        }
      }
      if (stats == null) {
        return const IntelResult(
          source: src,
          status: IntelStatus.info,
          message: 'لا توجد نتائج تحليل بعد.',
        );
      }
      int n(String k) {
        final v = stats![k];
        return v is int ? v : 0;
      }

      final mal = n('malicious');
      final sus = n('suspicious');
      final total = mal + sus + n('harmless') + n('undetected');
      if (mal >= 3) {
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: '$mal من $total محرك يعتبره خبيثًا.',
          findings: <Finding>[
            Finding(
              severity: Severity.danger,
              title: 'VirusTotal: $mal محرك يرصده',
              detail: 'عدد كبير من محركات الفحص صنّفته خبيثًا.',
              points: 70,
              confirmed: true,
            ),
          ],
        );
      }
      if (mal >= 1) {
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: '$mal من $total محرك يعتبره خبيثًا.',
          findings: <Finding>[
            Finding(
              severity: Severity.warn,
              title: 'VirusTotal: $mal محرك يرصده',
              detail: 'عدد قليل من المحركات صنّفته خبيثًا. قد يكون إنذارًا كاذبًا، لكن تعامل بحذر.',
              points: 35,
            ),
          ],
        );
      }
      if (sus >= 1) {
        return IntelResult(
          source: src,
          status: IntelStatus.hit,
          message: '$sus محرك يراه مشبوهًا.',
          findings: <Finding>[
            Finding(
              severity: Severity.warn,
              title: 'VirusTotal: مشبوه عند $sus محرك',
              detail: 'لا تصنيف خبيث صريح لكن هناك شبهات.',
              points: 20,
            ),
          ],
        );
      }
      return IntelResult(
        source: src,
        status: IntelStatus.clean,
        message: 'لا محرك رصده (من $total).',
        findings: const <Finding>[
          Finding(
            severity: Severity.good,
            title: 'VirusTotal: لا رصد',
            detail: 'لم يرصده أي محرك، وهذا لا يضمن الأمان.',
          ),
        ],
      );
    } on TimeoutException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'انتهت المهلة.',
      );
    } on SocketException {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'لا يوجد اتصال بالإنترنت.',
      );
    } catch (_) {
      return const IntelResult(
        source: src,
        status: IntelStatus.error,
        message: 'رد غير متوقع.',
      );
    }
  }
}
