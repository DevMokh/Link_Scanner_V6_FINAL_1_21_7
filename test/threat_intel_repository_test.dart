import 'dart:async';

import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/online_intel.dart';
import 'package:cobra_shield/services/threat_intel_repository.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

IntelResult _clean() => const IntelResult(
      source: 'Google Web Risk',
      status: IntelStatus.clean,
      message: 'No known match; this does not guarantee safety.',
      findings: <Finding>[
        Finding(
          severity: Severity.good,
          title: 'No known match',
          detail: 'No known threat match at lookup time.',
        ),
      ],
    );

IntelResult _hit() => const IntelResult(
      source: 'Google Web Risk',
      status: IntelStatus.hit,
      message: 'Threat match.',
      findings: <Finding>[
        Finding(
          severity: Severity.danger,
          title: 'Phishing',
          detail: 'A trusted source reported this target.',
          points: 80,
          confirmed: true,
          code: 'web_risk_hit',
        ),
      ],
    );

void main() {
  setUp(() async {
    await ThreatIntelRepository.resetProcessCacheForTesting();
    SharedPreferences.setMockInitialValues(<String, Object>{});
  });

  test('caches completed clean lookups and does not persist the raw URL', () async {
    var clock = DateTime.utc(2026, 11, 15, 12);
    final repository = ThreatIntelRepository.forTest(clock: () => clock);
    var calls = 0;
    const target = 'https://private.example/account?token=should-not-be-stored';

    final first = await repository.lookup(
      sourceId: 'google_web_risk',
      target: target,
      fetch: () async {
        calls++;
        return _clean();
      },
    );
    final second = await repository.lookup(
      sourceId: 'google_web_risk',
      target: target,
      fetch: () async {
        calls++;
        return _hit();
      },
    );

    expect(first.status, IntelStatus.clean);
    expect(second.status, IntelStatus.clean);
    expect(first.fromCache, isFalse);
    expect(second.fromCache, isTrue);
    expect(second.checkedAt, clock);
    expect(calls, 1);
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString('cobra.threat_intel.cache.v1')!;
    expect(stored, isNot(contains(target)));
    expect(stored, isNot(contains('should-not-be-stored')));
    expect(stored, contains('No known match'));

    clock = clock.add(const Duration(minutes: 4));
    final refreshed = await repository.lookup(
      sourceId: 'google_web_risk',
      target: target,
      fetch: () async {
        calls++;
        return _hit();
      },
    );
    expect(refreshed.status, IntelStatus.hit);
    expect(calls, 2);
  });

  test('reuses persisted cache across repository instances', () async {
    final firstRepository = ThreatIntelRepository.forTest(
      clock: () => DateTime.utc(2026, 11, 15, 12),
    );
    var calls = 0;
    await firstRepository.lookup(
      sourceId: 'virustotal',
      target: 'https://example.org/path',
      fetch: () async {
        calls++;
        return _hit();
      },
    );

    final secondRepository = ThreatIntelRepository.forTest(
      clock: () => DateTime.utc(2026, 11, 15, 12, 1),
    );
    final result = await secondRepository.lookup(
      sourceId: 'virustotal',
      target: 'https://example.org/path',
      fetch: () async {
        calls++;
        return _clean();
      },
    );

    expect(result.status, IntelStatus.hit);
    expect(result.fromCache, isTrue);
    expect(result.checkedAt, DateTime.utc(2026, 11, 15, 12));
    expect(calls, 1);
  });

  test('merges persisted entries when older repository instances write later', () async {
    final firstRepository = ThreatIntelRepository.forTest(
      clock: () => DateTime.utc(2026, 11, 15, 12),
    );
    final secondRepository = ThreatIntelRepository.forTest(
      clock: () => DateTime.utc(2026, 11, 15, 12, 1),
    );

    // Both objects load the initially empty store before either writes a
    // cacheable result. This reproduces a stale-instance overwrite race.
    await firstRepository.lookup(
      sourceId: 'source_a',
      target: 'https://a.example/',
      fetch: () async => const IntelResult(
        source: 'source_a', status: IntelStatus.error, message: 'temporary',
      ),
    );
    await secondRepository.lookup(
      sourceId: 'source_b',
      target: 'https://b.example/',
      fetch: () async => const IntelResult(
        source: 'source_b', status: IntelStatus.error, message: 'temporary',
      ),
    );

    var callsA = 0;
    var callsB = 0;
    await firstRepository.lookup(
      sourceId: 'source_a',
      target: 'https://a.example/',
      fetch: () async {
        callsA++;
        return _clean();
      },
    );
    await secondRepository.lookup(
      sourceId: 'source_b',
      target: 'https://b.example/',
      fetch: () async {
        callsB++;
        return _hit();
      },
    );

    final reader = ThreatIntelRepository.forTest(
      clock: () => DateTime.utc(2026, 11, 15, 12, 2),
    );
    final cachedA = await reader.lookup(
      sourceId: 'source_a',
      target: 'https://a.example/',
      fetch: () async {
        callsA++;
        return _hit();
      },
    );
    final cachedB = await reader.lookup(
      sourceId: 'source_b',
      target: 'https://b.example/',
      fetch: () async {
        callsB++;
        return _clean();
      },
    );

    expect(cachedA.status, IntelStatus.clean);
    expect(cachedA.fromCache, isTrue);
    expect(cachedB.status, IntelStatus.hit);
    expect(cachedB.fromCache, isTrue);
    expect(callsA, 1);
    expect(callsB, 1);
  });

  test('does not cache network errors, skipped, or not-configured results', () async {
    final repository = ThreatIntelRepository.forTest();
    var calls = 0;
    for (final status in <IntelStatus>[
      IntelStatus.error,
      IntelStatus.skipped,
      IntelStatus.notConfigured,
      IntelStatus.info,
    ]) {
      Future<IntelResult> fetch() async {
        calls++;
        return IntelResult(source: 'source', status: status, message: status.name);
      }

      await repository.lookup(
        sourceId: 'source_${status.name}',
        target: 'target',
        fetch: fetch,
      );
      await repository.lookup(
        sourceId: 'source_${status.name}',
        target: 'target',
        fetch: fetch,
      );
    }
    expect(calls, 8);
    expect(repository.cachedEntries, 0);
  });

  test('deduplicates simultaneous requests for the same source and target', () async {
    final repository = ThreatIntelRepository.forTest();
    final gate = Completer<IntelResult>();
    final started = Completer<void>();
    var calls = 0;

    Future<IntelResult> fetch() {
      calls++;
      if (!started.isCompleted) started.complete();
      return gate.future;
    }

    final first = repository.lookup(
      sourceId: 'google_web_risk',
      target: 'https://same.example',
      fetch: fetch,
    );
    final second = repository.lookup(
      sourceId: 'google_web_risk',
      target: 'https://same.example',
      fetch: fetch,
    );
    await started.future;
    expect(calls, 1);
    gate.complete(_clean());
    expect((await first).status, IntelStatus.clean);
    expect((await second).status, IntelStatus.clean);
  });

  test('source namespace is isolated and hit entries expire', () async {
    var clock = DateTime.utc(2026, 11, 15, 12);
    final repository = ThreatIntelRepository.forTest(clock: () => clock);
    var calls = 0;

    Future<IntelResult> fetchHit() async {
      calls++;
      return _hit();
    }

    await repository.lookup(
      sourceId: 'source_a',
      target: 'same-target',
      fetch: fetchHit,
      hitTtl: const Duration(minutes: 2),
    );
    await repository.lookup(
      sourceId: 'source_b',
      target: 'same-target',
      fetch: fetchHit,
      hitTtl: const Duration(minutes: 2),
    );
    expect(calls, 2);

    clock = clock.add(const Duration(minutes: 3));
    await repository.lookup(
      sourceId: 'source_a',
      target: 'same-target',
      fetch: fetchHit,
      hitTtl: const Duration(minutes: 2),
    );
    expect(calls, 3);
  });

  test('clear removes only the threat-intelligence cache', () async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('unrelated.setting', 'keep');
    final repository = ThreatIntelRepository.forTest();
    await repository.lookup(
      sourceId: 'google_web_risk',
      target: 'https://example.test',
      fetch: () async => _clean(),
    );

    await repository.clear();
    expect(repository.cachedEntries, 0);
    expect(prefs.getString('cobra.threat_intel.cache.v1'), isNull);
    expect(prefs.getString('unrelated.setting'), 'keep');
  });


  test('clear during an in-flight lookup prevents that result being re-cached', () async {
    final repository = ThreatIntelRepository.forTest();
    final gate = Completer<IntelResult>();
    final started = Completer<void>();
    final pending = repository.lookup(
      sourceId: 'google_web_risk',
      target: 'https://pending.example',
      fetch: () {
        if (!started.isCompleted) started.complete();
        return gate.future;
      },
    );
    await started.future;
    await repository.clear();
    gate.complete(_clean());
    expect((await pending).status, IntelStatus.clean);
    expect(repository.cachedEntries, 0);
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('cobra.threat_intel.cache.v1'), isNull);
  });

  test('corrupt cache is ignored without failing the lookup', () async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('cobra.threat_intel.cache.v1', '{broken');
    final repository = ThreatIntelRepository.forTest();
    final result = await repository.lookup(
      sourceId: 'google_web_risk',
      target: 'https://example.test',
      fetch: () async => _clean(),
    );
    expect(result.status, IntelStatus.clean);
  });
}
