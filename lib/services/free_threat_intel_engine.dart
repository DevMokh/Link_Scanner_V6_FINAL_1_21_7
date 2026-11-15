import 'online_intel.dart';
import 'threat_intel_repository.dart';

/// Free-only reputation orchestration used by the advanced scanner.
/// Every provider is isolated: an unavailable source returns an error/info
/// result and never aborts the other local or remote analysis stages.
class FreeThreatIntelEngine {
  FreeThreatIntelEngine._();

  static Future<IntelResult> _isolate(
    String source,
    Future<IntelResult> Function() request,
  ) async {
    try {
      return await request();
    } catch (_) {
      return IntelResult(
        source: source,
        status: IntelStatus.error,
        message: 'تعذر الاتصال بالمصدر؛ بقية فحوص التطبيق تستمر ولا يعني ذلك أن الرابط آمن.',
      );
    }
  }

  static Future<List<IntelResult>> inspect({
    required String url,
    required String domain,
    required bool skipDomainAge,
    ThreatIntelRepository? repository,
  }) async {
    final cache = repository ?? ThreatIntelRepository.instance;
    final requests = <Future<IntelResult>>[];

    if (skipDomainAge) {
      requests.add(Future<IntelResult>.value(const IntelResult(
        source: 'عمر الدومين (RDAP)',
        status: IntelStatus.skipped,
        message: 'لا ينطبق على عنوان IP أو رابط مختصر.',
      )));
    } else {
      requests.add(_isolate('عمر الدومين (RDAP)', () => cache.lookup(
        sourceId: 'rdap',
        target: domain,
        cleanTtl: const Duration(hours: 24),
        hitTtl: const Duration(hours: 1),
        fetch: () => OnlineIntel.rdap(domain),
      )));
    }

    // PhishTank is a free community lookup. The caller reaches this class only
    // after the user has accepted the advanced online-scan consent dialog.
    requests.add(_isolate('PhishTank', () => cache.lookup(
      sourceId: 'phishtank',
      target: url,
      cleanTtl: const Duration(minutes: 15),
      hitTtl: const Duration(hours: 6),
      fetch: () => OnlineIntel.phishTank(url),
    )));

    // Future.wait preserves source order; each future is isolated separately.
    return Future.wait<IntelResult>(requests);
  }
}
