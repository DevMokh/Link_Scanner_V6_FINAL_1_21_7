import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:crypto/crypto.dart' as crypto;
import 'package:shared_preferences/shared_preferences.dart';

import '../core/models.dart';
import 'online_intel.dart';

/// Local, privacy-preserving cache and de-duplication layer for reputation lookups.
///
/// Raw URLs/domains are never written to SharedPreferences. The cache key is a
/// SHA-256 digest of the source namespace and target. Only source verdicts and
/// their user-facing findings are stored locally. A missing/expired cache entry
/// always triggers a fresh lookup; errors and unconfigured sources are never cached.
class ThreatIntelRepository {
  ThreatIntelRepository._({DateTime Function()? clock})
      : _clock = clock ?? DateTime.now;

  /// Shared application instance used by the advanced scanner.
  static final ThreatIntelRepository instance = ThreatIntelRepository._();

  /// Isolated instance for unit tests.
  ThreatIntelRepository.forTest({DateTime Function()? clock})
      : this._(clock: clock);

  static const String _storageKey = 'cobra.threat_intel.cache.v1';
  static const int _maxEntries = 256;

  // Share hot entries between repository objects in the same isolate. This is
  // only an optimization; SharedPreferences remains the durable cache.
  static final Map<String, _CachedIntel> _processEntries =
      <String, _CachedIntel>{};

  // Serialize writes from multiple repository objects. This prevents stale
  // instances from overwriting cache entries persisted by newer instances.
  static Future<void> _writeQueue = Future<void>.value();
  static int _globalGeneration = 0;

  /// Resets isolate-local cache state between tests that replace the
  /// SharedPreferences mock store. Waits for queued persistence writes first,
  /// then advances the generation so in-flight lookups from an earlier test
  /// cannot repopulate the shared cache. Production code should use [clear].
  @visibleForTesting
  static Future<void> resetProcessCacheForTesting() async {
    await _writeQueue;
    _globalGeneration++;
    _processEntries.clear();
  }

  final DateTime Function() _clock;
  final Map<String, _CachedIntel> _entries = <String, _CachedIntel>{};
  final Map<String, Future<IntelResult>> _inFlight = <String, Future<IntelResult>>{};
  Future<void>? _loadFuture;
  SharedPreferences? _preferences;

  int get cachedEntries => _entries.length;

  /// Looks up one source/target pair. Concurrent duplicate requests share the
  /// same Future. [sourceId] must be a stable, non-secret identifier such as
  /// "google_web_risk", "virustotal", or "rdap".
  Future<IntelResult> lookup({
    required String sourceId,
    required String target,
    required Future<IntelResult> Function() fetch,
    Duration cleanTtl = const Duration(minutes: 3),
    Duration hitTtl = const Duration(minutes: 10),
  }) async {
    await _ensureLoaded();
    final key = _cacheKey(sourceId, target);
    final now = _clock();
    final cached = _entries.remove(key);
    if (cached != null && cached.expiresAt.isAfter(now)) {
      // Reinsert to update the least-recently-used order.
      _entries[key] = cached;
      return cached.asCachedResult();
    }
    if (cached != null) {
      await _persist();
    }

    final pending = _inFlight[key];
    if (pending != null) return pending;

    final generation = _globalGeneration;
    final future = _fetchAndCache(
      key: key,
      generation: generation,
      fetch: fetch,
      cleanTtl: cleanTtl,
      hitTtl: hitTtl,
    );
    _inFlight[key] = future;
    try {
      return await future;
    } finally {
      if (identical(_inFlight[key], future)) _inFlight.remove(key);
    }
  }

  Future<IntelResult> _fetchAndCache({
    required String key,
    required int generation,
    required Future<IntelResult> Function() fetch,
    required Duration cleanTtl,
    required Duration hitTtl,
  }) async {
    final result = await fetch();
    Duration? ttl;
    if (result.status == IntelStatus.clean) ttl = cleanTtl;
    if (result.status == IntelStatus.hit) ttl = hitTtl;
    // Never turn unavailable, failed, skipped, or unknown results into a
    // reusable "clean" answer. In particular, API/network errors stay uncached.
    if (ttl != null && ttl > Duration.zero && generation == _globalGeneration) {
      final cached = _CachedIntel(
        result: result,
        checkedAt: _clock(),
        expiresAt: _clock().add(ttl),
      );
      _entries.remove(key);
      _entries[key] = cached;
      _processEntries[key] = cached;
      _trimExpiredAndOldest();
      await _persist();
    }
    return result;
  }

  String _cacheKey(String sourceId, String target) {
    final canonicalSource = sourceId.trim().toLowerCase();
    final input = 'link-scanner-threat-cache-v1\u0000$canonicalSource\u0000$target';
    return crypto.sha256.convert(utf8.encode(input)).toString();
  }

  Future<void> _ensureLoaded() {
    return _loadFuture ??= _load();
  }

  Future<void> _load() async {
    try {
      // Do not read while another repository instance is midway through a write.
      await _writeQueue;
      final prefs = await SharedPreferences.getInstance();
      // Reload where supported. A few fallback/test backends do not implement
      // reload; the isolate-wide process cache below keeps readers consistent.
      try {
        await prefs.reload();
      } catch (_) {
        // Continue with the plugin's current snapshot.
      }
      _preferences = prefs;
      final raw = prefs.getString(_storageKey);
      if (raw != null && raw.isNotEmpty) {
        try {
          final decoded = jsonDecode(raw);
          if (decoded is Map) {
            final now = _clock();
            for (final entry in decoded.entries) {
              if (entry.key is! String || entry.value is! Map) continue;
              final parsed = _CachedIntel.fromJson(
                Map<String, dynamic>.from(entry.value as Map),
              );
              if (parsed == null || !parsed.expiresAt.isAfter(now)) continue;
              _entries[entry.key as String] = parsed;
            }
          }
        } catch (_) {
          // Ignore corrupt storage and still use valid in-process entries.
        }
      }
      final nowForShared = _clock();
      for (final entry in _processEntries.entries) {
        if (!entry.value.expiresAt.isAfter(nowForShared)) continue;
        final existing = _entries[entry.key];
        if (existing == null ||
            entry.value.checkedAt.isAfter(existing.checkedAt)) {
          _entries[entry.key] = entry.value;
        }
      }
      _trimExpiredAndOldest();
    } catch (_) {
      // Cache is an optimization only. Storage/JSON failures must not prevent
      // an online reputation lookup from running.
      _entries.clear();
    }
  }

  void _trimExpiredAndOldest() {
    final now = _clock();
    _entries.removeWhere((_, value) => !value.expiresAt.isAfter(now));
    while (_entries.length > _maxEntries) {
      _entries.remove(_entries.keys.first);
    }
  }

  Future<void> _persist() async {
    final previous = _writeQueue;
    final done = Completer<void>();
    _writeQueue = done.future;
    await previous;
    try {
      final prefs = _preferences ?? await SharedPreferences.getInstance();
      try {
        await prefs.reload();
      } catch (_) {
        // setString remains usable even when this backend has no reload API.
      }
      _preferences = prefs;

      // Merge disk state with this instance's current state. A repository
      // created earlier must not erase entries written by another instance.
      final merged = <String, _CachedIntel>{};
      final raw = prefs.getString(_storageKey);
      if (raw != null && raw.isNotEmpty) {
        try {
          final decoded = jsonDecode(raw);
          if (decoded is Map) {
            for (final entry in decoded.entries) {
              if (entry.key is! String || entry.value is! Map) continue;
              final parsed = _CachedIntel.fromJson(
                Map<String, dynamic>.from(entry.value as Map),
              );
              if (parsed != null && parsed.expiresAt.isAfter(_clock())) {
                merged[entry.key as String] = parsed;
              }
            }
          }
        } catch (_) {
          // Ignore corrupt persisted data; the in-memory entries remain valid.
        }
      }
      final nowForShared = _clock();
      for (final entry in _processEntries.entries) {
        if (!entry.value.expiresAt.isAfter(nowForShared)) continue;
        final existing = merged[entry.key];
        if (existing == null ||
            !entry.value.checkedAt.isBefore(existing.checkedAt)) {
          merged[entry.key] = entry.value;
        }
      }
      for (final entry in _entries.entries) {
        final existing = merged[entry.key];
        if (existing == null ||
            !entry.value.checkedAt.isBefore(existing.checkedAt)) {
          merged[entry.key] = entry.value;
        }
      }

      _entries
        ..clear()
        ..addAll(merged);
      _trimExpiredAndOldest();
      _processEntries
        ..removeWhere((_, value) => !value.expiresAt.isAfter(_clock()))
        ..addAll(_entries);
      final encoded = <String, Object>{};
      for (final entry in _entries.entries) {
        encoded[entry.key] = entry.value.toJson();
      }
      await prefs.setString(_storageKey, jsonEncode(encoded));
    } catch (_) {
      // Keep the in-memory result usable even when persistence is unavailable.
    } finally {
      done.complete();
    }
  }

  /// Clears cached reputation results. Does not clear API keys or scan history.
  Future<void> clear() async {
    _globalGeneration++;
    _entries.clear();
    _processEntries.clear();
    _inFlight.clear();

    // Serialize removal with writes from every repository instance so an older
    // lookup cannot recreate the cache immediately after the user clears it.
    final previous = _writeQueue;
    final done = Completer<void>();
    _writeQueue = done.future;
    await previous;
    try {
      final prefs = _preferences ?? await SharedPreferences.getInstance();
      try {
        await prefs.reload();
      } catch (_) {
        // Removal itself is still attempted for fallback/test backends.
      }
      _preferences = prefs;
      await prefs.remove(_storageKey);
    } catch (_) {
    } finally {
      done.complete();
    }
  }
}

class _CachedIntel {
  const _CachedIntel({
    required this.result,
    required this.checkedAt,
    required this.expiresAt,
  });

  final IntelResult result;
  final DateTime checkedAt;
  final DateTime expiresAt;

  IntelResult asCachedResult() => IntelResult(
        source: result.source,
        status: result.status,
        message: result.message,
        findings: result.findings,
        fromCache: true,
        checkedAt: checkedAt,
      );

  Map<String, Object> toJson() => <String, Object>{
        'checkedAtMs': checkedAt.millisecondsSinceEpoch,
        'expiresAtMs': expiresAt.millisecondsSinceEpoch,
        'source': result.source,
        'status': result.status.name,
        'message': result.message,
        'findings': result.findings
            .map((f) => <String, Object>{
                  'severity': f.severity.name,
                  'title': f.title,
                  'detail': f.detail,
                  'points': f.points,
                  'confirmed': f.confirmed,
                  'code': f.code,
                  'family': f.family,
                })
            .toList(growable: false),
      };

  static _CachedIntel? fromJson(Map<String, dynamic> json) {
    try {
      final checkedAtMs = json['checkedAtMs'];
      final expiresAtMs = json['expiresAtMs'];
      final source = json['source'];
      final statusName = json['status'];
      final message = json['message'];
      final rawFindings = json['findings'];
      if (checkedAtMs is! int || expiresAtMs is! int || source is! String ||
          statusName is! String || message is! String || rawFindings is! List) {
        return null;
      }
      final status = IntelStatus.values.firstWhere((e) => e.name == statusName);
      final findings = <Finding>[];
      for (final raw in rawFindings) {
        if (raw is! Map) return null;
        final map = Map<String, dynamic>.from(raw);
        final severityName = map['severity'];
        final title = map['title'];
        final detail = map['detail'];
        if (severityName is! String || title is! String || detail is! String) {
          return null;
        }
        final severity = Severity.values.firstWhere((e) => e.name == severityName);
        findings.add(Finding(
          severity: severity,
          title: title,
          detail: detail,
          points: map['points'] is int ? map['points'] as int : 0,
          confirmed: map['confirmed'] == true,
          code: map['code'] is String ? map['code'] as String : '',
          family: map['family'] is String ? map['family'] as String : '',
        ));
      }
      // Fail closed for old/corrupt records that claim a non-cacheable state.
      if (status != IntelStatus.clean && status != IntelStatus.hit) return null;
      return _CachedIntel(
        result: IntelResult(
          source: source,
          status: status,
          message: message,
          findings: findings,
        ),
        checkedAt: DateTime.fromMillisecondsSinceEpoch(checkedAtMs, isUtc: true),
        expiresAt: DateTime.fromMillisecondsSinceEpoch(expiresAtMs, isUtc: true),
      );
    } catch (_) {
      return null;
    }
  }
}
