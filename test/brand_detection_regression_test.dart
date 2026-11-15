import 'package:cobra_shield/core/brands.dart';
import 'package:cobra_shield/services/url_analyzer.dart';
import 'package:flutter_test/flutter_test.dart';

/// Synthetic regression fixtures only. These .example URLs are not live threat
/// reports and the measured values are not claims about real-world accuracy.
void main() {
  const brandSignals = <String>{
    'brand_impersonation',
    'brand_lookalike',
    'brand_typo',
    'brand_transposition',
    'brand_in_path',
    'official_lookalike',
  };

  const suspectedImpersonation = <String>[
    'https://paypal-security.example/signin',
    'https://google-account.example/verify',
    'https://amazon-login.example/password',
    'https://microsoft-verify.example/login',
    'https://facebook-support.example/confirm',
    'https://instagram-account.example/signin',
    'https://vodafone-egypt.example/verify',
    'https://binance-wallet.example/login',
    'https://googleaccount.example/login',
    'https://paypalaccount.example/secure',
    'https://googel-login.example/signin',
    'https://paypa1-security.example/login',
    'https://evil.example/раураl/login',
    'https://evil.example/gοοgle/login',
    'https://evil.example/ｐａｙｐａｌ/login',
    'https://فودافون-كاش.example/تسجيل-الدخول',
    'https://ڤودافون-كاش.example/تسجيل-الدخول',
    'https://انستاباي-تحديث.example/تأكيد',
    'https://البنك-الاهلي-المصري.example/تسجيل-الدخول',
    'https://المصرية-للاتصالات.example/تسجيل-الدخول',
    'https://جوميا-شحن.example/تسجيل-الدخول',
    'https://بنك-مصر-اونلاين.example/تسجيل-الدخول',
    'https://فوري-دفع.example/تسجيل-الدخول',
    'https://اتصالات-كاش.example/تسجيل-الدخول',
  ];

  const benignOrAmbiguous = <String>[
    'https://www.google.com/search?q=paypal',
    'https://www.paypal.com/myaccount/summary',
    'https://support.apple.com/ar-eg',
    'https://www.bbc.com/news/facebook-account-changes',
    'https://medium.com/@x/why-paypal-won',
    'https://apple-pie-recipes.com/best',
    'https://evil.example/notpaypalish/login',
    'https://example.com/مرحبا/login',
    'https://paypalish.example/article',
    'https://googley.example/news',
    'https://applepie.example/recipe',
    'https://brandless.example/reference/paypal',
    'https://docs.example/article?q=google-account',
    'https://example.com/فوري/مقال-اخباري',
    'https://example.com/خبر-عن-فودافون-بدون-تسجيل',
    'https://example.com/تحديث-اتصالات-الطرق',
    'https://example.com/طلب-دفع-اورنج-في-مقال',
  ];

  bool hasBrandSignal(String url) {
    final result = UrlAnalyzer.analyze(url);
    return result.findings.any((finding) => brandSignals.contains(finding.code));
  }

  test('synthetic impersonation examples produce a brand signal', () {
    final missed = <String>[];
    for (final url in suspectedImpersonation) {
      if (!hasBrandSignal(url)) missed.add(url);
    }
    expect(missed, isEmpty, reason: missed.join('\n'));
  });

  test('benign and ambiguous examples avoid brand-impersonation signals', () {
    final falsePositives = <String>[];
    for (final url in benignOrAmbiguous) {
      if (hasBrandSignal(url)) falsePositives.add(url);
    }
    expect(falsePositives, isEmpty, reason: falsePositives.join('\n'));
  });

  test('official domains in the bundled brand directory are not impersonators', () {
    final falsePositives = <String>[];
    for (final brand in kBrands) {
      for (final domain in brand.domains) {
        final url = 'https://$domain/';
        if (hasBrandSignal(url)) falsePositives.add('${brand.name}: $url');
      }
    }
    expect(falsePositives, isEmpty, reason: falsePositives.join('\n'));
  });

  test('brand-prefix matching only accepts known security suffixes', () {
    expect(hasBrandSignal('https://paypalaccount.example/login'), isTrue);
    expect(hasBrandSignal('https://googlelogin.example/verify'), isTrue);
    expect(hasBrandSignal('https://paypalish.example/article'), isFalse);
    expect(hasBrandSignal('https://googley.example/news'), isFalse);
    expect(hasBrandSignal('https://applepie.example/recipe'), isFalse);
  });

  test('brand name before the actual registrable domain is not trusted', () {
    expect(hasBrandSignal('https://paypal.com.evil.example/login'), isTrue);
    expect(hasBrandSignal('https://accounts.google.com/signin'), isFalse);
    expect(hasBrandSignal('https://notpaypal.example/article'), isFalse);
  });

  test('trailing one-character extensions are not enough for a typo signal', () {
    expect(hasBrandSignal('https://googley.example/news'), isFalse);
    expect(hasBrandSignal('https://googlee.example/news'), isFalse);
    expect(hasBrandSignal('https://gogle-login.example/signin'), isTrue);
  });


  test('Arabic Egyptian brand aliases are matched on host and path', () {
    expect(hasBrandSignal('https://فودافون-كاش.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://ڤودافون-كاش.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://انستاباي-تحديث.example/تأكيد'), isTrue);
    expect(hasBrandSignal('https://البنك-الاهلي-المصري.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://المصرية-للاتصالات.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://جوميا-شحن.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://بنك-مصر-اونلاين.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://فوري-دفع.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://اتصالات-كاش.example/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://evil.example/فودافون/تسجيل-الدخول'), isTrue);
    expect(hasBrandSignal('https://evil.example/اورنج/تسجيل-الدخول'), isTrue);
    // Short Arabic aliases (for example Fawry/فوري) still require a credential
    // context; ordinary article paths remain covered by the negative corpus.
    expect(hasBrandSignal('https://evil.example/فوري/تسجيل-الدخول'), isTrue);
  });

  test('Arabic common words do not trigger a brand signal by themselves', () {
    expect(hasBrandSignal('https://example.com/فوري/مقال-اخباري'), isFalse);
    expect(hasBrandSignal('https://example.com/خبر-عن-فودافون-بدون-تسجيل'), isFalse);
    expect(hasBrandSignal('https://example.com/تحديث-اتصالات-الطرق'), isFalse);
    expect(hasBrandSignal('https://example.com/طلب-دفع-اورنج-في-مقال'), isFalse);
  });

  test('brand corpus regression metrics meet the synthetic baseline', () {
    // Use all simple keys from the bundled brand catalog as deterministic
    // generated positive samples, plus every listed official domain as a
    // negative sample. This catches accidental catalog/rule regressions.
    final positives = <String>{...suspectedImpersonation};
    final keyPattern = RegExp(r'^[a-z0-9]+$');
    for (final brand in kBrands) {
      for (final key in brand.keys) {
        if (key.length >= 5 && keyPattern.hasMatch(key)) {
          positives.add('https://$key-secure.example/login');
        }
      }
    }

    final negatives = <String>{...benignOrAmbiguous};
    for (final brand in kBrands) {
      for (final domain in brand.domains) {
        negatives.add('https://$domain/');
      }
    }

    var truePositive = 0;
    var falseNegative = 0;
    var trueNegative = 0;
    var falsePositive = 0;
    for (final url in positives) {
      if (hasBrandSignal(url)) {
        truePositive++;
      } else {
        falseNegative++;
      }
    }
    for (final url in negatives) {
      if (hasBrandSignal(url)) {
        falsePositive++;
      } else {
        trueNegative++;
      }
    }

    final precision = truePositive + falsePositive == 0
        ? 0.0
        : truePositive / (truePositive + falsePositive);
    final recall = truePositive + falseNegative == 0
        ? 0.0
        : truePositive / (truePositive + falseNegative);

    // Thresholds apply only to this synthetic regression corpus, not to
    // arbitrary URLs seen in production.
    expect(positives.length, greaterThanOrEqualTo(40));
    expect(negatives.length, greaterThanOrEqualTo(40));
    expect(precision, greaterThanOrEqualTo(0.98),
        reason: 'TP=$truePositive FP=$falsePositive TN=$trueNegative FN=$falseNegative');
    expect(recall, greaterThanOrEqualTo(0.98),
        reason: 'TP=$truePositive FP=$falsePositive TN=$trueNegative FN=$falseNegative');
  });
}
