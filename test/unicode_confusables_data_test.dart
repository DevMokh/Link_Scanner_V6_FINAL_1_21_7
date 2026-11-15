import 'package:cobra_shield/core/unicode_confusables_data.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('bundled Unicode data metadata matches its actual map', () {
    expect(kUnicodeConfusablesVersion, '18.0.0');
    expect(kUnicodeConfusablesCount, kUnicodeConfusables.length);
  });
}
