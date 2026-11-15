import 'dart:convert';
import 'dart:io';

import 'package:cobra_shield/core/app_info.dart';
import 'package:cobra_shield/core/models.dart';
import 'package:cobra_shield/services/url_analyzer.dart';

/// Offline, reproducible benchmark. The fixtures are synthetic examples on
/// reserved .example names plus documented benign examples; results are NOT
/// production precision/recall claims and no network requests are made.
class _Fixture {
  const _Fixture({
    required this.id,
    required this.url,
    required this.expectedThreat,
    required this.category,
  });

  final String id;
  final String url;
  final bool expectedThreat;
  final String category;
}

int _percentile(List<int> sorted, double p) {
  if (sorted.isEmpty) return 0;
  final index = ((sorted.length - 1) * p)
      .round()
      .clamp(0, sorted.length - 1)
      .toInt();
  return sorted[index];
}

double? _ratio(int numerator, int denominator) =>
    denominator == 0 ? null : numerator / denominator;

Future<void> main(List<String> args) async {
  var iterations = 64;
  String? outputPath;
  for (final arg in args) {
    if (arg.startsWith('--iterations=')) {
      iterations = int.tryParse(arg.substring('--iterations='.length)) ?? 64;
    } else if (arg.startsWith('--output=')) {
      outputPath = arg.substring('--output='.length);
    } else {
      stderr.writeln('Unknown argument: $arg');
      exitCode = 64;
      return;
    }
  }
  if (iterations < 1 || iterations > 1000) {
    stderr.writeln('--iterations must be between 1 and 1000');
    exitCode = 64;
    return;
  }

  final corpusFile = File('tool/url_quality_corpus.json');
  if (!await corpusFile.exists()) {
    stderr.writeln('Missing benchmark corpus: ${corpusFile.path}');
    exitCode = 2;
    return;
  }
  final decoded = jsonDecode(await corpusFile.readAsString()) as List<dynamic>;
  final fixtures = decoded.map((row) {
    final item = row as Map<String, dynamic>;
    return _Fixture(
      id: item['id'] as String,
      url: item['url'] as String,
      expectedThreat: item['expected_threat'] as bool,
      category: item['category'] as String,
    );
  }).toList(growable: false);
  if (fixtures.isEmpty || fixtures.map((f) => f.id).toSet().length != fixtures.length) {
    stderr.writeln('Benchmark corpus must be non-empty and use unique IDs.');
    exitCode = 2;
    return;
  }

  var tp = 0;
  var fp = 0;
  var tn = 0;
  var fn = 0;
  final categoryCounts = <String, int>{};
  for (final fixture in fixtures) {
    categoryCounts.update(fixture.category, (value) => value + 1, ifAbsent: () => 1);
    final result = UrlAnalyzer.analyze(fixture.url);
    final predictedThreat = result.hasScore && result.score >= kBandMedium;
    if (fixture.expectedThreat && predictedThreat) {
      tp++;
    } else if (!fixture.expectedThreat && predictedThreat) {
      fp++;
    } else if (!fixture.expectedThreat && !predictedThreat) {
      tn++;
    } else {
      fn++;
    }
  }

  // Warm up static tables/caches and the analyzer before collecting timings.
  for (final fixture in fixtures) {
    UrlAnalyzer.analyze(fixture.url);
  }

  final latenciesUs = <int>[];
  final total = Stopwatch()..start();
  for (var round = 0; round < iterations; round++) {
    for (final fixture in fixtures) {
      final one = Stopwatch()..start();
      UrlAnalyzer.analyze(fixture.url);
      one.stop();
      latenciesUs.add(one.elapsedMicroseconds);
    }
  }
  total.stop();
  latenciesUs.sort();

  final scans = latenciesUs.length;
  final elapsedSeconds = total.elapsedMicroseconds / 1000000.0;
  final result = <String, Object?>{
    'benchmark_schema': 1,
    'benchmark_type': 'synthetic_offline_regression',
    'application_version': kAppVersion,
    'platform': Platform.operatingSystem,
    'platform_version': Platform.operatingSystemVersion,
    'dart_runtime': Platform.version,
    'generated_at_utc': DateTime.now().toUtc().toIso8601String(),
    'corpus_file': 'tool/url_quality_corpus.json',
    'corpus_size': fixtures.length,
    'threat_fixtures': fixtures.where((f) => f.expectedThreat).length,
    'benign_fixtures': fixtures.where((f) => !f.expectedThreat).length,
    'category_counts': categoryCounts,
    'prediction_rule': 'completed scan score >= $kBandMedium',
    'confusion_matrix': <String, int>{
      'true_positive': tp,
      'false_positive': fp,
      'true_negative': tn,
      'false_negative': fn,
    },
    'synthetic_metrics': <String, double?>{
      'precision': _ratio(tp, tp + fp),
      'recall': _ratio(tp, tp + fn),
      'accuracy': _ratio(tp + tn, tp + fp + tn + fn),
    },
    'performance': <String, Object?>{
      'iterations_per_fixture': iterations,
      'scans': scans,
      'elapsed_ms': total.elapsedMilliseconds,
      'scans_per_second': elapsedSeconds <= 0 ? null : scans / elapsedSeconds,
      'mean_latency_us': scans == 0
          ? null
          : latenciesUs.reduce((a, b) => a + b) / scans,
      'p50_latency_us': _percentile(latenciesUs, 0.50),
      'p95_latency_us': _percentile(latenciesUs, 0.95),
    },
    'limitations': <String>[
      'Fixtures are synthetic or benign examples, not a representative live threat feed.',
      'Precision and recall apply only to this bundled fixture set.',
      'Do not use these values as production detection accuracy claims.',
      'Timing varies by device, runtime, thermal state, and build mode.',
      'No network access is used by this benchmark.',
    ],
  };
  final json = const JsonEncoder.withIndent('  ').convert(result);
  stdout.writeln(json);
  if (outputPath != null && outputPath.isNotEmpty) {
    final file = File(outputPath);
    await file.parent.create(recursive: true);
    await file.writeAsString('$json\n');
  }
}
