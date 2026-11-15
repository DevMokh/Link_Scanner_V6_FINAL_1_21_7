## 1.21.7+31
- Make the test-only process-cache reset asynchronous and wait for queued writes before clearing shared in-memory entries.
- Advance the cache generation during test reset so in-flight lookups from a prior test cannot repopulate the process cache.
- Await cache reset before replacing SharedPreferences mocks in repository and free-provider tests, preventing cross-test contamination of RDAP and PhishTank results.
- Keep persisted cache timestamps restored as UTC instants (`isUtc: true`) for deterministic comparisons and expiry calculations.

## 1.21.6+30
- Fix UTC preservation when restoring cached threat-intelligence timestamps.
- Add deterministic reset of isolate-local threat cache for SharedPreferences-backed tests.
- Isolate free threat-intelligence tests from prior repository test cache state.

## 1.21.5+29 — fix CI regressions in benign encoded search URLs and shared cache reads
- Avoid flagging an ordinary percent-encoded URL in a generic search parameter (for example Google `/url?q=...`) as a concealed redirect by itself. Opaque state, fragment, and redirect-context payloads remain deeply inspected; risky decoded destinations still trigger findings.
- Share the in-process threat-intelligence cache between repository instances while retaining the persistent SharedPreferences cache. This lets a fresh repository instance reuse a just-completed verdict even when a test/fallback storage backend cannot reload its snapshot.
- Keep durable writes serialized and merge the freshest valid entries, without storing raw URLs. Cache clearing invalidates outstanding fetches across repository instances and clears the process cache.
- No scan feature, dependency, paid API, mandatory API key, subscription, or runtime network requirement was added or removed.

## 1.21.4+28 — Arabic brand aliases, raw hidden-link inspection, and shared cache consistency
- Match brand aliases against both the Unicode IDN hostname and its confusable skeleton. The skeleton remains useful for Latin lookalikes, while the original Unicode spelling preserves Arabic brand names that UTS #39 folding may otherwise change.
- Allow short Arabic brand aliases in path analysis while retaining the credential-context requirement; common Arabic article text without login/verification context remains non-suspicious.
- Run deep-link extraction against the original raw query and fragment before global URL refanging. Defanged destinations such as `hxxps[:]//paypa1[.]com` therefore retain their concealed/encoded evidence and are independently analyzed without opening the destination.
- Reload and merge persisted threat-intelligence cache entries before writes, serialize writes/removals across repository instances, and prevent one instance from overwriting another instance's newer cache. Cache keys remain SHA-256 digests; raw URLs are not persisted.
- Added an explicit Fawry Arabic path regression case. Existing five failing CI cases are targeted by the source changes; Flutter/Dart tests and APK build must still pass in GitHub Actions before release approval.
- No scan feature, dependency, paid API, mandatory API key, subscription, or runtime network requirement was added or removed.

## 1.21.3+27 — fix Dart analyzer error in optional network metadata
- Fixed the CI analyzer failure in `lib/services/network_intelligence.dart`: removed a stale read of `_RipeNetwork.error`, a property that does not exist after the internal result model was simplified.
- Kept `NetworkIntelligenceReport.error` for fatal/blocked DNS inspection outcomes; optional RIPEstat lookup availability remains described by `registrationMessage` and does not turn an otherwise successful DNS inspection into a failure.
- Preserved the previous 1.21.2 PhishTank test helper correction and redirect-findings report display. No feature or dependency was removed or added.
- Source-level consistency checks and the available Python/shell tests are run for this package. Flutter/Dart analyzer, Flutter tests, and APK build still require GitHub Actions verification.

## 1.21.2+26 — fix analyzer and test compilation
- Fixed two Dart test compile errors in `test/online_intel_test.dart`: the test now calls `OnlineIntel.resetPhishTankRateLimitForTesting()` directly rather than referencing a local helper declared later in the enclosing group.
- Removed the unused `_RipeNetwork.error` constructor parameter/field and stale imports/helpers reported by `flutter analyze`.
- Kept redirect-chain findings visible in the advanced report. The findings are now rendered below the redirect timeline rather than being calculated and discarded.
- No scan feature, screen, source, or dependency was removed. No paid API, mandatory key, subscription, or always-on network dependency was added.
- Verified in this environment: Python compile checks; 9 Unicode-generator tests; 27 sandbox-service tests; shell syntax checks. Flutter/Dart are not installed here, so `dart format`, `flutter analyze`, `flutter test`, and APK build still require GitHub Actions verification.

## 1.21.1+25 — redirect test reliability and short-link regression coverage
- Fixed the local redirect test server helper so it accepts and applies the explicit HTTP status code used by its 307/308/304 test cases; this removed a Dart test-compilation mismatch.
- Expanded short-link-style local integration coverage to exercise all followed redirect statuses (301, 302, 303, 307, 308), relative `Location` values, query-string preservation, and the non-following 304 behavior.
- No production feature was removed, and no dependency, paid API, subscription, API key, or mandatory online service was added.
- Python syntax checks, the Unicode generator tests, and sandbox-service tests pass in this environment. Flutter/Dart are not installed here, so Dart formatting, `flutter analyze`, `flutter test`, and APK build remain unverified and must pass in CI before production release.

## 1.21.0+24 — safer redirect handling and private redirect timelines
- Follow only the standard HTTP redirect statuses 301, 302, 303, 307, and 308; a redirect response without a non-empty `Location` is now an incomplete/bad-redirect result rather than a successful expansion.
- Do not follow `Location` on non-redirect 3xx responses such as 304.
- Redact redirect paths, query strings, fragments, and URL user-info in both redirect timeline widgets. The original URLs remain in memory for analysis; only their visual representation is masked.
- Added regression tests for missing `Location`, 307/308, 304, and secret redaction.
- No new dependencies, paid APIs, subscriptions, API keys, or runtime network requirements were added; existing local scanning and features are preserved.
- Flutter/Dart are unavailable in the editing environment, so Dart formatting, analyzer, Flutter tests, and APK build remain to be confirmed in GitHub Actions.

## 1.20.0+23 — Offline quality benchmark and analyzer performance
- Cache normalized brand aliases once per app process to reduce repeated Unicode normalization/tokenization during URL and batch scans.
- Tighten one-edit brand typo detection: a single character appended/removed only at the end (e.g. `googley`) no longer triggers a typo signal; internal edits and substitutions remain detectable.
- Add deceptive-host regression cases where a brand-like label appears before an unrelated registrable domain (e.g. `paypal.com.evil.example`) while preserving real official subdomains.
- Add a balanced, synthetic, offline URL corpus and a repeatable Dart benchmark that records confusion-matrix metrics plus throughput and p50/p95 latency. The CI artifact is informational and explicitly not a real-world accuracy claim.
- No new dependencies, API keys, subscriptions, external service calls, or removed features.

# Changelog

## 1.19.0+22 — 2026-11-15
- Added Unicode-aware brand tokenization for Arabic and other scripts using Dart Unicode property escapes.
- Added Arabic aliases for verified Egyptian brands (Vodafone, InstaPay, CIB, Banque Misr, NBE, Etisalat, Orange, Telecom Egypt/WE, Egypt Post, Jumia, and QNB/Fawry variants).
- Added Arabic login/verification context to brand impersonation checks and protected ambiguous aliases with the same context requirement.
- Reused tokenized path buffers during brand-in-path checks to avoid repeatedly splitting/normalizing the same path for each catalog entry.
- Added synthetic Arabic positive and negative regression cases, including Vodafone Arabic letterform variants.
- No paid APIs, dependencies, subscriptions, or runtime network requirements were added.

## 1.18.0+21 — Batch 7
- Narrowed concatenated brand-prefix matching to a reviewed allowlist of security/account suffixes to reduce false positives.
- Expanded synthetic brand regression fixtures, including known official domains and catalog-derived samples.
- Added synthetic precision/recall guardrails; these are regression metrics, not real-world accuracy claims.
- No new paid services, API keys, or package dependencies.

## 1.17.0+20 — Unicode build pipeline and private JSON reports

- Hardened the Unicode UTS #39 generator with a configurable minimum mapping count and generated mapping-count metadata. A tiny or truncated source cannot silently replace the bundled table.
- Updated GitHub Actions to attempt a free, pinned download of the official Unicode 18.0.0 `confusables.txt` file. The generator only replaces the local fallback after version validation and at least 100 printable-ASCII target mappings.
- The exact Unicode data artifact validated and tested in the CI job is passed to the APK build job. If Unicode download is unavailable, the existing bundled fallback remains and the app still builds without a runtime network dependency.
- Added the Unicode License V3 copyright and permission notice to generated/bundled data, as required for distribution.
- Added structured JSON scan reports and a share action. The JSON export is privacy-preserving by default: it excludes the full URL, path, query parameters, and finding details while retaining verdict, score, finding codes, and host metadata. The existing text report remains unchanged.
- Added regression tests for Unicode generator metadata/malformed scalars and JSON report privacy/invalid-input semantics.
- No new runtime package, API key, subscription, or paid service. No existing feature was removed.
- Flutter/Dart are unavailable in the editing environment; `flutter analyze`, `flutter test`, and APK build remain to be confirmed by GitHub Actions.

## 1.16.0+19 — تحسين كشف انتحال العلامات التجارية

- إضافة كشف تبديل حرفين متجاورين في أسماء العلامات غير الملتبسة (مثل `googel` بدل `google`)؛ كان هذا النمط يُحسب مسافتين في Levenshtein ولا يُكتشف سابقًا.
- إضافة كشف اسم علامة مكتوب بحروف Unicode متشابهة داخل مسار الرابط، وليس في اسم المضيف فقط، مع اشتراط سياق حساس مثل تسجيل الدخول أو التحقق، ومطابقة حدود الكلمات لتجنب الكلمات الأطول غير المرتبطة.
- إضافة اختبارات تراجع لحالات التبديل، وانتحال العلامة داخل المسار بحروف سيريلية، وحالة نص عربي عادي لتقليل الإنذارات الكاذبة.
- الحفاظ على الفحص المحلي ومصادر النسخة المجانية دون إضافة خدمات أو مفاتيح أو اشتراكات جديدة.
- لم يتم تضمين جدول Unicode UTS #39 الكامل في هذه الدفعة: ملف المصدر الرسمي لم يكن قابلًا للتنزيل من بيئة التحرير. بقيت مجموعة البيانات الحالية كما هي، ويظل استكمالها بندًا مفتوحًا؛ لا ندّعي اكتمال تغطية UTS #39.
- لم تتوفر Flutter/Dart في بيئة التحرير؛ اختبارات Dart المضافة تحتاج تشغيلًا في GitHub Actions قبل اعتماد الإصدار.

## 1.15.0+18 — محرك استخبارات مجاني متعدد المصادر

- إضافة `FreeThreatIntelEngine` لتنسيق RDAP وPhishTank دون ربط الفحص التلقائي بخدمات قد تتجاوز حصصًا مجانية أو تحتاج ترخيصًا/اشتراكًا.
- إضافة موصل PhishTank المجاني باستخدام API الرسمي، دون مفتاح في الوضع المحدود، وبترويسة User-Agent وصفحة موافقة تشرح إرسال الرابط الكامل.
- قراءة استجابة PhishTank مع تصنيف التهديد فقط عندما تكون الحالة `verified` و`valid` مؤكدة؛ البلاغ غير المؤكد يعرض كمعلومة بلا نقاط.
- احترام `X-Request-Limit-*` وHTTP 509/429، وإضافة تهدئة محلية قصيرة، وعدم تحويل حد الطلبات أو خطأ الشبكة إلى نتيجة نظيفة.
- عزل كل مصدر؛ فشل PhishTank لا يلغي نتيجة RDAP أو التحليل المحلي ولا يوقف التطبيق.
- تعطيل الاستدعاء التلقائي لـGoogle Web Risk وVirusTotal في وضع الفحص المجاني لتجنب رسوم أو شروط استخدام غير مناسبة؛ الاحتفاظ بدوال التوافق ومفاتيح الإصدارات القديمة دون إرسالها.
- تحديث موافقة الإنترنت والخصوصية والإعدادات وقائمة مصادر التقرير لتوضيح مصدر البيانات وما يغادر الجهاز.
- إضافة اختبارات لطلب PhishTank، والتطابق المؤكد، والبلاغ غير المؤكد، والحدود، والردود المعطوبة، وعزل المصادر.
- لم تتوفر Flutter/Dart في بيئة التحرير؛ يلزم تشغيل `dart format`, `flutter analyze`, `flutter test` وبناء APK في CI قبل اعتماد الإصدار.

# Changelog

## 1.14.0+17 — Chromium network policy hardening

- Tightened outbound IP screening for the Chromium analysis worker: explicit NAT64, local-use NAT64, Teredo/6to4, IPv4-mapped IPv6, documentation, benchmarking, and special-purpose IPv4 ranges are rejected.
- Added bounded DNS answer validation: rejects empty, malformed, mixed public/private, and excessive DNS response sets; DNS resolution now fails closed on timeout.
- Added deterministic resolver injection for unit tests without changing production DNS behavior.
- Updated sandbox deployment guidance to clarify that application DNS checks do not eliminate Chromium DNS TOCTOU; host egress firewall and disposable VM isolation remain mandatory.
- Added regression tests for special-use IPs and DNS answer edge cases.

## 15 نوفمبر 2026 — Threat intelligence cache وUnicode pipeline (1.13.0+16)

- إضافة `ThreatIntelRepository` لتخزين نتائج السمعة المحلية لفترات قصيرة ومختلفة حسب المصدر والحالة.
- استخدام SHA-256 لمفاتيح الكاش؛ لا يتم حفظ الرابط أو الدومين الخام داخل الكاش.
- دمج استعلامات RDAP وGoogle Web Risk وVirusTotal عبر طبقة واحدة، مع منع تخزين الأخطاء والمصادر غير المُعدّة والمتخطاة.
- إزالة تكرار الطلبات المتزامنة لنفس المصدر والهدف، وتحديد حجم الكاش وحذف المنتهي.
- تحسين تصنيف `wholeLookalike` حتى لا تُعامل الحروف العربية وحدها كتقليد لاتيني.
- إضافة مابينجز Unicode إضافية موثقة، وبناء أداة لتوليد جدول ASCII confusables من Unicode UTS #39 18.0.0.
- إضافة اختبارات Python لأداة توليد بيانات Unicode، واختبارات Dart للكاش ولمحرك Unicode.
- أداة Unicode جاهزة، لكن جدول البيانات الرسمي المولّد لم يُضمّن بعد؛ يلزم تشغيل الأداة على ملف Unicode الرسمي قبل الادعاء بتغطية UTS #39 كاملة.
- لم تتوفر Flutter/Dart في بيئة التحرير؛ يجب أن يثبت GitHub Actions تنسيق Dart والتحليل والاختبارات وبناء APK.

## 15 نوفمبر 2026 — ترحيل Google Safe Browsing v4 إلى Web Risk Lookup API (1.12.0+15)

- نقل الاستعلام الحالي من `safebrowsing.googleapis.com/v4/threatMatches:find` إلى `webrisk.googleapis.com/v1/uris:search`.
- طلب قوائم `MALWARE` و`SOCIAL_ENGINEERING` و`SOCIAL_ENGINEERING_EXTENDED_COVERAGE` و`UNWANTED_SOFTWARE` في استعلام GET واحد، وقراءة بنية `threat.threatTypes` الجديدة.
- الاحتفاظ بحقل المفتاح الداخلي `cobra.key.gsb` وواجهة `OnlineIntel.safeBrowsing` القديمة للتوافق مع الإعدادات والامتدادات السابقة؛ الاسم القديم أصبح يوجّه إلى Web Risk وليس Safe Browsing v4.
- تحديث واجهة الإعدادات ورسالة الموافقة وتوثيق الخصوصية لتمييز Web Risk عن Safe Browsing v4.
- تعطيل اتباع التحويلات لهذا الطلب لأن مفتاح API موجود في query parameter، ومنع إعادة توجيه الطلب إلى مضيف آخر.
- إضافة اختبارات تغطي شكل الطلب الجديد، الأنواع المتعددة، التطابق، الرد الفارغ، البنية غير المتوقعة، الأخطاء، والتوافق مع الاسم القديم.
- اعتبار `{}` فقط رد عدم وجود تطابق؛ أي بنية استجابة 200 غير معروفة تُعامل كخطأ لتجنب الحكم النظيف الكاذب.
- تم تحديث رقم التطبيق إلى `1.12.0+15`. لم تتوفر Flutter/Dart في بيئة التحرير؛ يلزم تشغيل CI للتأكد من التنسيق والتحليل والاختبارات وبناء APK.

## 14 نوفمبر 2026 — Deep URL Analysis Engine
- إضافة `DeepLinkInspector` لاستخراج الروابط المخفية من query وfragment وحمولات Base64/Base64URL وJSON escapes وHTML entities وطبقات الترميز.
- تحليل الوجهات المستخرجة بنفس محرك `UrlAnalyzer` بعمق محدود، وإظهار خطورة الوجهة المخفية مع الأسباب بدل الاكتفاء برؤية الرابط الخارجي.
- كشف وجود أكثر من وجهة داخل الحمولة الواحدة، مع معايرة تمنع اعتبار روابط البحث العادية تهديدًا لمجرد احتوائها على URL.
- توسيع كشف النطاقات المولدة آليًا باستخدام إنتروبيا الحروف ونسبة الحروف المتحركة، إلى جانب القواعد السابقة.
- إضافة اختبارات تغطي Base64 JSON وJSON escapes وfragment وتعدد الوجهات والـ opaque tokens وحالات DGA-like.
- لم تتغير خدمات الشبكة أو مفاتيح API أو قواعد التقييم الحالية إلا بإشارات الكشف الجديدة؛ لم يتوفر Flutter SDK لتشغيل الاختبارات محليًا.

## 14 نوفمبر 2026 — إعادة تصميم Cyber Operations / Terminal (V5)
- تغيير الهوية من Graphite / Indigo إلى واجهة Cyber Operations: خلفية شبه سوداء، أخضر فوسفوري للتحكم، سماوي لبيانات النظام، وحدود وزوايا حادة.
- إعادة بناء الشاشة الرئيسية كمركز عمليات أمني، مع حالة المحرك المحلي، زر تحليل الرابط، مؤشرات حقيقية من السجل، وحدات التحليل، التدريب، النشاط الأخير وملاحظة أمنية.
- إعادة تنظيم تبويب المزيد إلى وحدات جمع وتحليل، معمل تدريب، أدوات مساعدة، وتهيئة النظام.
- إعادة تصميم القائمة الجانبية والترويسات وشريط التنقل السفلي، وتوحيد المكونات المشتركة والحقول والتقارير على الهوية الجديدة.
- تحديث صفحات الفحص والتدريب والسجل والصور والرسائل لتستخدم زوايا أكثر حدة وألوان Cyber Terminal عبر المكونات المشتركة.
- الاحتفاظ بمسارات كل الوحدات والوظائف السابقة؛ لا يوجد حذف لملف Dart أو خدمة أو شاشة أو وجهة callback.
- تحديث اختبار ألوان الثيم. لم يتم تشغيل Flutter/Dart SDK في بيئة التحرير؛ يلزم تشغيل `dart format`, `flutter analyze`, و`flutter test` من GitHub Actions قبل اعتماد الإصدار.

## 14 نوفمبر 2026 — تحديث الأداء وإزالة قاعدة OpenPhish
- إزالة قاعدة OpenPhish المحلية وعمليات تنزيلها وتحليلها ومطابقتها من التشغيل والفحص المتقدم والإعدادات.
- إزالة ملفات القاعدة القديمة المخزنة تلقائيًا بعد ترقية التطبيق.
- الإبقاء على الفحص المحلي، وتتبع التحويلات، وRDAP، وGoogle Web Risk، وVirusTotal، مع إعداد المفاتيح والموافقة كما كانت.
- تحسين فهرسة الدومينات وقوائم الاستضافات، وتقليل إعادة الحساب، ونقل الفحص المجمّع إلى isolate، وتقليل إعادة بناء شاشات التبويبات.

## أيقونة قائمة جانبية مخصصة — 14 نوفمبر 2026

- إضافة `AppMenuGlyph` كأيقونة Vector مرسومة بـ `CustomPainter` بدل الاعتماد على أيقونتي Material الجاهزتين `menu_rounded` و`tune_rounded`.
- تصميم الأيقونة من ثلاثة مسارات أفقية وعُقد إشارة متباعدة بألوان Indigo وTurquoise لتتماشى مع هوية Link Scanner.
- استخدام الأيقونة نفسها في ترويسات الأدوات والشاشة الرئيسية، مع Tooltip ووسم وصول عربي واضح.
- الإبقاء على سلوك الفتح كما هو: زر الترويسة يستدعي `Scaffold.openDrawer()`، وزر الرئيسية يستدعي `onMenu`؛ لم يتغير أي مسار تنقل أو وظيفة.
- تحديث اختبار `AppHeader` ليتحقق من المكوّن الجديد ومن فتح القائمة الفعلية بدل التحقق من رمز Material القديم.
- لم يُشغّل Flutter Test أو Analyze محليًا لعدم توفر Flutter SDK في بيئة التحرير؛ يلزم تأكيد النتيجة من GitHub Actions.

## إعادة تصميم تجربة الاستخدام بالكامل — 14 نوفمبر 2026

- إعادة بناء الرئيسية كـ Security Command Center: زر فحص الرابط في المقدمة، إحصائيات من السجل الحقيقي، شبكة أدوات، تعلم وتدريب، آخر الفحوصات، وتنبيه تحديث مصادر التهديدات.
- تغيير موضع عناصر التنقل إلى شريط سفلي عائم بخمس وجهات، مع الحفاظ على ترتيب التبويبات ومعرّفاتها.
- إعادة تصميم شاشة فحص الرابط: حقل URL أوضح، زر تحليل رئيسي، وأزرار منفصلة للصق وقراءة QR؛ مع الإبقاء على كل بطاقات النتائج والفحص المتقدم والإجراءات.
- إعادة تنظيم تبويب المزيد في مجموعات وشبكات حسب نوع المهمة بدل قائمة طويلة متشابهة.
- توحيد ترويسات الصفحات والبطاقات والحقول على أسطح Graphite وحدود هادئة وتباعد أوضح.
- تمت مقارنة الملفات وأسماء الدوال والكلاسات في الملفات المعاد تصميمها مع النسخة المصدر؛ لم يُحذف ملف أصلي أو دالة/كلاس سابق.
- فحوص YAML وShell وPython نجحت. لم يتم تشغيل Flutter/Dart SDK في بيئة التحرير؛ لذلك لا يوجد ادعاء بنجاح analyze أو tests أو APK محليًا.

## إصلاح CI وإعادة ضبط الهوية البصرية — 14 نوفمبر 2026

- تغيير الهوية البصرية العامة إلى Graphite / Indigo: خلفيات محايدة أغمق، أسطح بطاقات متدرجة، لون أساسي نيلي، ولون ثانوي تركوازي مع إبقاء ألوان الخطر والنجاح مستقلة.
- تحديث `AppHeader` وإزالة null-aware call غير الضروري في زر القائمة؛ الزر يفتح الـ Drawer فقط عندما يكون موجودًا.
- تحديث مظهر الأزرار والبطاقات المشتركة من غير تغيير واجهاتها البرمجية أو وظائف الشاشات.
- تحديث GitHub Actions إلى إصدارات Node.js 24، وFlutter 3.50.0 كإعداد افتراضي.
- فصل الاعتماديات: ملف `pubspec.lock` الناتج في بوابة التحقق يُنقل إلى Job البناء ويُفرض باستخدام `flutter pub get --enforce-lockfile`.
- إيقاف إنشاء ورفع APK غير متحقق منه: فشل التنسيق أو التحليل أو أي اختبار يمنع Job البناء، وفشل تحقق APK يمنع رفعه.
- لم تُحذف ملفات `lib` أو `test`، ولم تُحذف أي وظيفة أو dependency من `pubspec.yaml`، ولم يتغير رقم التطبيق.
- لم يُنفّذ Flutter SDK داخل بيئة التحرير؛ لذلك لا ندّعي نجاح `flutter analyze` أو `flutter test` أو بناء APK محليًا. يجب تشغيل Actions بعد رفع هذه النسخة للتحقق النهائي.

# سجل التغييرات (Changelog)

## إعادة تصميم الواجهة: كاشف الروابط | Link Scanner (على 1.11.1+14)
> **حالة التحقق:** ما اتشغّلش `dart format` ولا `flutter analyze` ولا `flutter test` ولا بناء الـ APK في بيئة التطوير (مفيش Flutter/Dart SDK ولا شبكة).
> اللي اتعمل: فحص أقواس/نصوص Dart ساكن، وحل كل الـ imports، وفحص الـ imports غير المستخدمة (لأن الـ CI بيوقف على أي تحذير).
> أول تشغيل فعلي هو الـ CI. رقم الإصدار ما اتغيّرش (1.11.1+14) لأن التغيير في الواجهة فقط.

- **الاسم والهوية:** "كاشف الروابط | Link Scanner" في العنوان وأيقونة التطبيق (Manifest label) وكل النصوص الظاهرة. المعرّفات الداخلية (اسم الحزمة،
  `cobra_shield` في pubspec، مفاتيح `cobra.*`، قنوات `cobra/ocr` و`cobra/share`) ما اتغيّرتش عمدًا.
- **ثيم (اتجاه "أزرق ليلي"):** كحلي `#060D1C` + أزرق سماوي `#31D0FF` (`C.accent`) وأزرق أعمق للتدرجات (`C.accentDeep`)، والأخضر `C.green` لحالات الأمان/النجاح فقط
  (`C.emerald` اتغيّر اسمه لـ `C.accent`)، وأسطح Material 3 (حوارات/قوائم) بنفس الألوان. التوهج خفيف.
- **شعار جديد** (`brand_logo.dart`): درع + رمز رابط بلون سماوي، مرسوم بالكود. أيقونات الإطلاق `mipmap-*` اتولّدت من نفس الهندسة، وشاشة تشغيل كحلية بالأيقونة
  (`android_overlay/res/drawable/launch_background.xml` بيتنسخ في الـ workflow).
- **قائمة جانبية** (`app_drawer.dart`) وشريط تنقل سفلي بتوهج، وزر قائمة في ترويسة تبويبات الشاشة الرئيسية. فحص المرسل والفحص المجمّع بقوا متاحين
  من القائمة (`openSenderTool`/`openBatchTool` في `more_screen.dart`).
- **الشاشة الرئيسية** اتكتبت من جديد: بطاقة حالة بتدرّج أزرق "جاهز للفحص" (أو كهرماني "حدّث قاعدة التهديدات" لو قاعدة OpenPhish مش محمّلة أو أقدم من 14 يوم)، وثلاث بطاقات إحصاء
  حقيقية (الروابط المفحوصة / التهديدات / عدد الفحوصات)، زر "فحص رابط جديد"، اختصارات الأدوات، آخر الفحوصات.
- **فحص الرابط:** حقل بزر مسح، زر "ابدأ الفحص" الرئيسي، لصق وفحص، QR، بطاقة "الرابط المفحوص" (الشكل بعد التنظيف) مع نسخ، حكم بأيقونة وتوهج،
  مشاركة التقرير، "فحص رابط آخر"، ونصائح قبل أول فحص. انتقال ناعم بين النصائح والنتيجة. منطق التحليل ما اتلمسش.
- **QR:** أركان سماوية وخط مسح متحرك (زخرفة بصرية فقط؛ القراءة والكشاف زي ما هم).
- `ScaleHeader` اتبدّل بـ `AppHeader` (نفس الواجهة + الشعار)، وزر `PrimaryButton` (تدرّج أزرق → سماوي) موحّد في شاشات الرابط/الرسالة/الصورة/الرئيسية.
- `HistoryStore.maxItems` بقى عام (للعرض في الشاشة الرئيسية).
- `kAppName`/`kAppNameAr`/`kAppNameEn`/`kAppBuild` في `app_info.dart`، وتغطيتهم في `app_info_test.dart` (بيتأكد إن `kAppBuild` = رقم البناء في pubspec).
- اختبارات جديدة: `brand_logo_test`، `app_shell_widgets_test`، `home_dashboard_test`.
- **مش موجود في التطبيق وما اتضافش (عمدًا):** شاشة أمان الواي فاي، حظر الروابط، اشتراك/Premium، حماية لحظية في الخلفية، شاشة "عن التطبيق". ما ضفناش أزرار شكلية ليهم.
  مفيش Firebase في المشروع أصلًا. الخط عربي النظام (مفيش خط عربي مضمّن).


## 1.11.1+14
> **حالة التحقق:** نفس تحذير 1.11.0: التعديلات مكتوبة في الملفات الفعلية، لكن **`flutter analyze` و`flutter test` وبناء الـ APK
> ما اتشغّلوش في بيئة التطوير** (مفيش Flutter/Dart SDK ولا شبكة). القيم المتوقعة في الاختبارات الجديدة اتحسبت يدويًا وبنطاقات (≥).
> أول تشغيل فعلي هو الـ CI. العتبات (الأوزان والحدود الدنيا) **ما اتعايرتش على عيّنة تصيّد حقيقية**؛ هي مبنية على الحالات المعروفة وروابط الاختبار.

### أخطاء اتصلّحت (طلعت من اختبار حقيقي على التطبيق)
- **فحص الدفعة كان بيسقّط الرابط بصمت:** أي نص فيه `@` من غير `http` كان بيتتجاهل (لتفادي الإيميلات)، فرابط مثل
  `hxxp:\\www.google.com@0x7f000001/...` كان بيختفي من التقرير (22 صف من 23). دلوقتي الإيميل الحقيقي بس هو اللي بيتتجاهل،
  والنصوص اللي مش متعرف عليها بتظهر في لوحة "غير مفحوص" وبتدخل التقرير المنسوخ (`batch_input.dart` جديد، ومعاه اختبارات).
- **درجة الفحص المتقدم** بقت بنفس طريقة التجميع الموحّدة (`aggregateScore`): كانت "درجة + نقاط" بحساب منفصل ممكن يخرج عن المقياس.
- **عدّ مزدوج:** حرف خفي مرمّز داخل اسم الموقع (`exa%0Ample.com`) كان بيتحسب مرتين (حروف خفية 20 + اسم موقع مرمّز 20). بقى 20 + 5 رمزية.
- **روابط التصيّد الواضحة كانت بتطلع أقل من اللازم** لأن الجمع الحسابي وحده ما بيوصّلهاش لـ "احتيال مرجّح". أضفنا حدودًا دنيا لتجمعات نادرة في
  المواقع السليمة (إشارة `combo_floor` بالفرق، فمجموع النقاط المعروض يفضل = الدرجة):
  `paypal.com@evil.com` ≥ 75، علامة معروفة + حروف متشابهة ≥ 85، علامة معروفة في دومين مش ليها + كلمات حساسة/امتداد مشبوه ≥ 70،
  خطأ إملائي مقصود + كلمات دخول ≥ 60، IP مموّه ≥ 55 (≥ 70 مع كلمات)، IP عام + كلمات ≥ 50، دومين مرمّز %XX + كلمات دخول ≥ 55.
  عناوين الراوتر (`192.168.x.x`) مستثناة.

### الوجهة المخبّأة داخل الرابط
- بنفك الوجهة لو كانت **base64** (`?url=aHR0cDov...`) أو اسم دومين من غير http (`?redirect=evil.com`) في الباراميترات الصريحة بس، وبنحللها **بنفس المحرك**
  (مرة واحدة): `nested_url` (+15) و`nested_url_encoded` (+10) و`nested_target_risk` (حتى +35 حسب درجة الوجهة). تنقّل الموقع لنفسه (`continue=` لدومين فرعي منه)
  أو بين دومينين رسميين مش بيتعلّم. توكنات الجلسات وbase64 اللي مش بيفك لرابط ما بتتعلّمش.

### تغطية أوسع
- **كلمات عربية** في المسار والاستعلام (تسجيل الدخول، كلمة المرور، حساب، بنك، مخالفة، غرامة، جائزة...) بتتحسب بنفس منطق الكلمات الإنجليزية (حتى لو مرمّزة %D8..).
- **منصات المحتوى المفتوح** (S3، githubusercontent، sharepoint، firebasestorage، t.me، wa.me، linktr.ee...) بقت `free_host` (+15) بدل "دومين رسمي" بصفر نقاط:
  الدومين موثوق لكن أي حد يرفع عليه صفحة. **أثر جانبي معروف:** روابط سليمة على الدومينات دي بتاخد +15 (لسه "منخفض" لوحدها).
- **استخراج الروابط من الرسائل** اتوسّع: `hxxp:\\` و`hxxps[:]//`، IP صريح بمسار/منفذ، مضيف hex أو عشري كبير بمسار، `paypal.com@evil.com` من غير http،
  وأي امتداد معروف (من قائمة اللاحقات) لو معاه مسار أو منفذ. أسماء الملفات (`main.py`) والإيميلات وأرقام الإصدار مش بتتلقط.
- تفكيك الرابط في الواجهة بيعرض المضيف بصيغة Punycode والرابط الفعلي بعد التنظيف.
- نصوص المحرك اتوحّدت على الفصحى (كانت مختلطة بالعامية).

### اللي لسه ناقص (متعمّد نقوله)
- قائمة اللاحقات العامة لقطة 2025-12-28؛ تحديثها محتاج شبكة (`tool/gen_psl.py`).
- OCR العربي على أجهزة حقيقية، وحماية DNS-rebinding، لسه ما اتجرّبوش على جهاز أو شبكة حقيقية.
- العتبات ما اتعايرتش على عيّنة تصيّد حقيقية (نسبة إنذار كاذب/فوات مجهولة).

## 1.11.0+13
> **حالة التحقق:** كل التعديلات دي مكتوبة في الملفات الفعلية، لكن **`flutter analyze` و`flutter test` و`dart format` وبناء الـ APK
> ما اتشغّلوش في بيئة التطوير** (مفيش Flutter/Dart SDK ولا شبكة للتثبيت). القيم المتوقعة في الاختبارات اتتبّعت يدويًا.
> أول تشغيل فعلي هو الـ CI (راجع `REVIEW_REPORT_1.11.0.md`).

### التحقق من المدخل (رابط / مش رابط)
- `url_validator.dart` (جديد): المدخل لازم يكون رابط ويب (http/https فقط). `not-a-url`، `https://`، `ftp://`، `mailto:`، منفذ غلط،
  مضيف غير صالح، `localhost` وكلمة واحدة = **إدخال غير صالح** (`ScanState.invalidInput`): مفيش درجة خطر ومفيش "مشبوه"
  ومفيش "لا مؤشرات". رسالة الإدخال الفاضي الأصلية متحفوظة. الروابط المموّهة المقصودة (`%0A`، `∕`، `\@`) لسه بتتحلل
  كروابط حقيقية. `javascript:` و`data:` بيتحللوا كخطر مش كـ"غير مدعوم".

### Hostname مقابل Registrable Domain
- قائمة اللاحقات العامة الرسمية (Public Suffix List) مضمّنة (`psl_data.dart`، لقطة 2025-12-28، 10,098 قاعدة)، مولّدة بـ `tool/gen_psl.py`،
  ومعاها خوارزمية القواعد الكاملة (wildcard + exception + ICANN/PRIVATE). `example.co.uk` و`user.github.io` بيتعاملوا صح.
- IDN / punycode: الدومين العربي أو الألماني السليم بيتعلّم معلوماتي بس؛ التقليد الفعلي (skeleton بيطابق دومين رسمي، أو خلط أنظمة كتابة) بيتعلّم.
- فشل DNS أو تعذّر الوصول **ليس دليل تصيّد** وما بيضيفش نقاط (`host_unreachable`، حالة معلوماتية).

### مقياس خطر موحّد (`models.dart`)
- حدود واحدة لكل الشاشات: `kBandMedium=20`، `kBandHigh=45`، `kBandCritical=70`؛ `levelForScore` و`tierForScore` والسجل بيستخدموها كلهم.
- `aggregateScore`: نفس الـ `Finding.code` بيتحسب مرة واحدة (الأعلى)، والإشارات الضعيفة (`family: weak`) مجموعها محدود بـ `kWeakFamilyCap=12` (أقل من "مشبوه").
- 7 حالات حكم (`Verdict`): تهديد مؤكد / مشبوه / لا مؤشرات واضحة / معلومات غير كافية / إدخال غير صالح / فشل التحليل / فحص جزئي. "لا مؤشرات" مش "آمن" والنص بيقول كده.
- إشارات بتتفعّل بالسياق (مش لوحدها): مثلًا TLD رخيص أو شرطات كتير بدون علامة تجارية أو طلب بيانات = إشارة ضعيفة.
- **تغيير سلوك متعمّد:** رابط ضعيف الإشارات وبدون علامة تجارية (مثل `win-prize-now.top/claim`) بقى "لا مؤشرات واضحة" (مع تنبيه إنه مش ضمان) بدل "مشبوه"، لتقليل الإنذارات الكاذبة. القيم قابلة للضبط.
  العناوين الداخلية (`192.168.x.x`، `[::1]`) بقت "متوسط" مش "عالي" عشان روابط الراوتر العادية.

### الرسائل عربي / إنجليزي / مختلط
- إشارات الاستعجال وطلب البيانات والمال والتهديد والتحقق بنفس القوة بالعربي والإنجليزي والمختلط (`knowledge.dart` + `message_analyzer.dart` + `text_utils.dart`).
- LRM/RLM/ALM وعلامات الاتجاه **مش تهديد تلقائي**: بتتشال من الأطراف وبتتجاهل في تطابق الكلمات؛ بس الحروف الخفية داخل الدومين بتتعلّم.

### OCR
- حالات واضحة للنتيجة (`OcrOutcome` / `OcrQuality`): نجاح، جودة منخفضة، فشل، رجوع لـ ML Kit اللاتيني (بتنبيه إن العربي ممكن يضيع)؛ والنص الناتج من OCR ناقص = فحص جزئي.
- **دقة العربي على أندرويد الفعلي لسه ما اتجرّبتش.** مفيش ادّعاء إن OCR العربي مكتمل.

### OpenPhish
- `threat_feed.dart`: التحديث ذري، بيتحقق من الحجم والصيغة قبل الاستبدال، بيحفظ في مجلد بيانات التطبيق الدائم، ومعاه وقت آخر تحديث ناجح وحالة آخر محاولة (`FeedUpdateStatus`). التحديث الفاشل ما بيمسحش القاعدة القديمة.

### SSRF / DNS Rebinding
- `NetGuard`: حل DNS بأنفسنا، فحص **كل** العناوين الراجعة (واحد داخلي = رفض الكل)، والاتصال بعنوان الـ IP اللي اتحقق منه مع الإبقاء على اسم الموقع للـ TLS/SNI؛ كل تحويلة بتتحقق منها قبل الاتصال.
- اختبارات تكامل بخادم محلي (`link_expander_network_test`، شهادة اختبار في `test/fixtures`). **ما اتشغّلتش**؛ مفيش ادّعاء إن الحماية من DNS Rebinding مكتملة قبل أول تشغيل ناجح.

### مفاتيح API والخصوصية
- حالة جديدة `IntelStatus.notConfigured` ("الخدمة غير مُعدّة"): مفتاح Google/VirusTotal ناقص ≠ نظيف ≠ فشل، ومفيش نقاط. فشل GSB/VT (مهلة / مفتاح مرفوض) = "تعذّر الفحص" والنتيجة "فحص جزئي".
- `isPlausibleApiKey`: مفتاح بشكل غلط ما بيتبعتش وما بيتكرّرش في رسائل الخطأ.
- مفتاح تبديل **"السماح بالفحص المتقدم عبر الإنترنت"** في تبويب أدوات ← مصادر التهديدات الحية (كان الإذن بيتحفظ بدون طريقة لسحبه).
- `usesCleartextTraffic="false"` في الـ Manifest. `PRIVACY.md` (جديد): تدفق البيانات من قراءة الكود.
- `clientVersion` في طلب Google Safe Browsing بقى من `kAppVersion` (`lib/core/app_info.dart`).
- RDAP: بيتبعت الدومين المسجّل بس وبشكل ASCII/punycode قياسي؛ مش IP ومش رابط مختصر.

### CI (`.github/workflows/main.yml`)
- يشتغل على push وPull Request (مش يدوي فقط) + تشغيل يدوي `debug` / `release`.
- بوابة: `flutter pub get` → تنسيق → `flutter analyze --no-fatal-infos` → `flutter test`. التنسيق: على push بيتطبّق جوه الـ runner بس (من غير commit،
  عشان ما يتعارضش مع أدوات الرفع)، وبالتشغيل اليدوي `commit_format` بيتعمل commit (`github-actions[bot]`)؛ على Pull Request بيتحقق بـ
  `--set-exit-if-changed` وأي ملف مش متنسّق = فشل.
- Debug APK بيتبني تلقائيًا بعد كل push حتى لو analyze/test فشلوا، بالاسم `app-debug-UNVERIFIED` وتحذير (الغرض: اختبار ميداني)؛
  `app-debug` = البوابة والتحقق نجحوا. Release بيتطلب نجاح البوابة. الرفع بيحصل حتى لو `verify_apk.sh` فشل (الـ job بيفضل أحمر).
  اتشال `continue-on-error` من الـ format واتشال `--no-fatal-warnings`. الملاحظات الأسلوبية (infos) بتظهر ومبتوقفش البناء، والتحذيرات والأخطاء بتوقف.
- `analysis_options.yaml` (جديد، بدل include ناقص كان بيطلّع تحذير مخفي) + قاعدة `avoid_print`.
- بناء Debug بعد البوابة؛ Release بيتطلب أسرار التوقيع وبيفشل بوضوح لو ناقصة (مفيش توقيع بمفتاح debug).
- `tool/verify_apk.sh`: يتأكد إن الـ APK موجود وسليم ومطابق لإصدار pubspec والأذونات والتوقيع، وبعدين الرفع. `pubspec.lock` بيترفع كـ artifact من الحل الفعلي (مفيش lock مصطنع).
- تصحيح مصدر خطأ تحليلي: حروف الاتجاه الحرفية في الكود (`text_direction_code_point_in_literal`) اتبدّلت كلها بـ `\uXXXX`.

### الاختبارات (مكتوبة، أول تشغيل فعلي في الـ CI)
- جديد: `url_validator_test`، `scoring_test`، `public_suffix_test` (معاها المتجهات الرسمية `test_psl.txt` — اتحقق منها بنسخة Python من الخوارزمية)، `app_info_test`، `invisible_chars_test`، `link_expander_network_test`، `http_util_redirect_test`، `threat_feed_update_test`، `ocr_service_test`، `ocr_text_test`.
- محدّث: `url_analyzer_test` و`message_analyzer_test` و`verdict_test` و`online_intel_test` و`url_normalizer_test` (توقعات اتغيّرت بسبب المعايرة الجديدة، وحالات علامات اتجاه).

### حدود معروفة
- أول تشغيل للـ CI (فعلي، 2026-11-10) وقف عند فحص التنسيق: 62 من 78 ملف مش متنسّقين (الكود اتكتب يدويًا). اتحلّ بالتنسيق التلقائي
  في الـ workflow (نجح). التشغيل التالي وقف عند analyze بـ 6 مشاكل (import ناقص `ocr_text.dart` في `ocr_service_test`، وimportين غير مستخدمين)؛ اتصلّحوا. **الاختبارات لسه ما اتشغّلتش**.
- السجل بيحفظ الدرجة بس: فحص جزئي أو غير كافٍ بيظهر في السجل كدرجة 0.
- مفيش `pubspec.lock` ولا APK اتبنى هنا.

## 1.10.0+12
### محرك تحليل الروابط: تطبيع وكشف التمويه (كله على الجهاز، بدون إنترنت)
- **مطبّع جديد** `url_normalizer.dart` بيشتغل قبل أي فحص ولا بيرمي استثناءات (الأخطاء بتتسجّل في `errors`):
  - تقسيم الرابط على حدوده **الخام** الأول (scheme / user@ / host / path) وبعدين فك الترميز لكل جزء
    لوحده، فك متكرر (`%252F` ← `/`) بسقف 6 جولات. (فك الترميز قبل التقسيم خطر: `https://paypal.com%2F@evil.com`
    المتصفح رايح فيه لـ evil.com.)
  - إزالة الحروف الخفية والتحكم (صفر العرض، اتجاه النص، `\n` `\r` tab، `%0A`) حتى لو ظهرت بعد فك الترميز؛ الأطراف
    بتتنضف بدون تعليم لأن تطبيقات المراسلة بتضيفها.
  - إصلاح البروتوكول: `http:/x`، `http:\\x`، `https//x`، `//x`، بدون بروتوكول، وصيغة defang (`hxxp`، `[.]`).
  - مسافات داخل المضيف بتتشال وتتعلّم، وشرطة معكوسة `\` بتتعامل زي المتصفح، ولو أدوات RFC هتقرأ مضيفًا مختلفًا
    (`https://evil.com\@google.com`) بتتعلّم كاختلاف قراءة (+35).
  - **صيغ الـ IP**: عشري / رقم واحد (DWORD) / `0x` / ثماني / مختلط / مختصر (`127.1`) بنفس قواعد inet_aton،
    وIPv6 بين أقواس. المضيف الرقمي غير الصالح (`example.123`) = رابط غير صالح زي المتصفح.
  - فك Punycode (`xn--`) يدويًا (RFC 3492) لفحص الحروف، وطي الحروف العريضة والمزخرفة (ｐａｙｐａｌ، 𝐩𝐚𝐲𝐩𝐚𝐥)
    زي ما المتصفح بيعمل.
- **كاشفات التمويه** `url_evasion.dart` + جدول أوزان واحد `UrlWeights` (IP +30، IP مموّه +35، `@` +35،
  Homograph +25، مستويات فرعية كثيرة +15، كلمات حساسة كثيرة +15، حروف خفية +20 ...).
  - Homograph بدقة أعلى: خلط أنظمة كتابة (لاتيني + سيريلي/يوناني/أرمني)، أو ليبل كله حروف شبيهة، أو skeleton
    بيطابق **دومين رسمي** (+40 `official_lookalike`). الدومين العربي/الصيني/الألماني السليم بيتعلّم "IDN" معلوماتي (+8) بس.
  - `@`: بيعرض "اللي ظاهر" مقابل "الوجهة الفعلية"، و+10 لو الجزء قبل `@` بيذكر علامة معروفة.
- **تقرير منظم** `UrlAnalyzer.report(url)` ← `UrlThreatReport`: الدرجة (0-100)، `rawScore` قبل القص، المستوى
  (`ThreatTier`: لا مؤشرات / مشبوه / خطير، بنفس عتبات `RiskLevel`)، `cleanUrl`، وقايمة `ThreatFlag`
  (code، شدة، عنوان، شرح، وزن) + `toJson()` و`toText()`. `UrlAnalyzer.analyze` شغال بنفس الواجهة القديمة.
- `Finding.code`: معرّف ثابت لكل إشارة (اتضاف لكل إشارات المحلل).
- فشل داخلي غير متوقع في التحليل بيطلع "تعذّر تحليل الرابط" (+25، `partial`) ومش بيعتبر الرابط آمن.
- نص أطول من 4096 حرف بيتحلل أوله بس ويتعلّم `partial`.
- `parts.normalizedUrl` (اللي بيستخدمه الفحص المتقدم للاتصال) بقى رابط بنيته الخامة سليمة والمضيف بشكله القياسي،
  مش النص الأصلي؛ والـ IP المموّه بيتحول لشكله العشري القياسي قبل ما يوصل لحارس الشبكة.
- تغييرات أوزان: "كلمات حساسة كثيرة" 16 ← 15 (مطابقة للجدول). تعديل سلوك: الدومين غير اللاتيني السليم مبقاش +25+15
  تلقائيًا (كان بيتعلّم مشبوه)؛ بقى +8 معلوماتي ما لم يكن فيه تقليد فعلي.
### الاختبارات (مكتوبة، أول تشغيل فعلي في الـ CI)
- `url_normalizer_test` (جديد): فك الترميز، الحروف الخفية، البروتوكول، المسافات، صيغ IPv4/IPv6، punycode (قيم من Python)،
  skeleton والحروف المزخرفة، الرابط النظيف.
- `url_analyzer_test`: 20 رابط تمويه بحد أدنى للمستوى، 4 روابط دولية سليمة، أوزان المحرك، التقرير المنظم، والروابط المكسورة.

## 1.9.0+11
### نموذج الحالات (Verdict)
- حكم نهائي رسمي لكل نتيجة (`models.dart`): **تهديد مؤكد** / **مشبوه** (بالمستوى التفصيلي) /
  **لا مؤشرات واضحة** / **معلومات غير كافية**.
- "مؤكد" بيتحدد بعلامة `Finding.confirmed` اللي بتتحط بس على: تطابق كامل مع OpenPhish، تصنيف
  Google Safe Browsing، أو 3+ محركات في VirusTotal. تطابق المضيف/الدومين أو محرك واحد = اشتباه، مش تأكيد.
- "لا مؤشرات" مبتتقالش لو الفحص ناقص (`ScanResult.partial`: مصدر فشل، تتبع التحويلات فشل أو اتمنع،
  رسالة اتقطعت، أو روابط زيادة عن الحد). بيظهر "معلومات غير كافية" بدالها.
- بطاقة النتيجة والتقرير المنسوخ والترجمة (عربي/إنجليزي) بيعكسوا الحكم.
- فشل الفحص بالكامل (OCR/QR/شبكة) مفيهوش نتيجة أصلًا، وبيظهر كرسالة فشل صريحة.
### التخزين
- قاعدة التهديدات اتنقلت من المجلد المؤقت لمجلد بيانات التطبيق الدائم (`path_provider`)،
  مع ترحيل تلقائي من الموقع القديم.
### الاختبارات (أول مرة بتتشغّل في الـ CI)
- `verdict_test`, `online_intel_test` (GSB/VirusTotal/RDAP بردود وهمية)، `threat_feed_update_test`
  (تحديث ذري بملفات حقيقية)، `ocr_service_test` (قناة وهمية + رجوع للاحتياطي)،
  `qr_analyzer_test`، و`link_expander_test` بخادم محلي حقيقي (تحويلات، حلقات، تحويلة لعنوان
  metadata/شبكة داخلية، رفض HEAD).
- نقاط حقن للاختبار فقط (`@visibleForTesting`): `httpOverride`، `ThreatFeed.forTest`،
  `OcrService.latinFallbackOverride`، `NetGuard.allowLoopbackForTesting` (الافتراضي false).
### CI
- كلمات سر التوقيع اللي فيها `\` أو مسافة أول القيمة بتتهرّب صح في `key.properties`.

## 1.8.0+10
### أمان الشبكة
- **حارس الشبكة** `lib/services/net_guard.dart`: تتبع الروابط بيرفض بروتوكولات غير http/https،
  `user:pass@`، المنافذ غير المعتادة، الأسماء المحلية (`localhost`, `*.local`, `*.internal`, اسم من
  كلمة واحدة)، عناوين IP بصيغ مخفية (عشري/سداسي عشري/ثماني/مختصر)، وكل نطاقات IP المحلية والخاصة
  و link-local و metadata (`169.254.169.254`) و CGNAT و multicast، لـ IPv4 و IPv6 (بما فيها
  IPv4-mapped و NAT64 و 6to4 و Teredo).
- **تتبع الروابط** `link_expander.dart`: كل رابط وكل تحويلة بتتفحص قبل الاتصال؛ وقت الاتصال بنعمل
  DNS lookup بأنفسنا ونتحقق من كل العناوين ونتصل بالعنوان اللي اتحقق منه (`connectionFactory`)
  لتقليل خطر DNS rebinding؛ مفيش بروكسي؛ مهلة كلية 30 ثانية؛ كشف حلقات التحويل.
  تحويلة لوجهة داخلية بتتحسب مؤشر خطر (+30).
- `http_util.dart`: https فقط للخدمات الخارجية، وعلامة `truncated` للردود المقطوعة.
### مفاتيح API
- المفاتيح بتتخزن في **Android Keystore** عبر `flutter_secure_storage` (`secret_store.dart`)
  بدل SharedPreferences. ترحيل آمن للنسخة القديمة (كتابة ← قراءة ← مقارنة ← مسح القديم).
  لو التخزين الآمن فشل: المفاتيح بتشتغل للجلسة بس وما بتتكتبش كنص عادي أبدًا، والواجهة بتنبّه.
### قائمة التهديدات
- تحديث **ذري**: بنقرأ ونتحقق (مش مقطوع، 80%+ أسطر صالحة، مش أصغر من 20% من الحالية) وبعدين
  نبدّل القاعدة ونكتب الملف عبر ملف مؤقت + rename. القاعدة القديمة بتفضل لو الجديدة معطوبة
  (قبل كده كانت بتتمسح أولًا).
### نتائج الفحص
- "الفحص المتقدم غير مكتمل" بيظهر كمؤشر ورسالة لما مصدر يفشل (فشل مصدر ≠ آمن).
- الرسائل الطويلة (> 5000 حرف) و أكتر من 8 روابط: تحذير إن الباقي ما اتفحصش.
### CI
- الاختبارات إلزامية (شلنا `continue-on-error`).
- مدخل جديد `build_type`: `debug` (افتراضي، بدون مفاتيح) أو `release` (يفشل بوضوح لو أسرار التوقيع
  ناقصة، مفيش رجوع صامت لتوقيع debug).
- الأسرار بتتمرر كمتغيرات بيئة ومبتتطبعش.
- فحص `dart format` (معلوماتي لحد ما الكود يتفورمت).
- اختبارات جديدة: net_guard، link_expander (بدون شبكة)، threat_feed، settings_store (تخزين وهمي)، ocr_text.
### حدود معروفة
راجع `FINAL_REPORT.md`.

## 1.7.0+9
### جديد
- **قراءة النص العربي من الصور (OCR) على الجهاز** باستخدام Tesseract (عربي + إنجليزي)،
  بدل ML Kit اللي كان بيدعم اللاتيني بس. القراءة بتتم بدون إنترنت.
  - كود أندرويد أصلي: `android_overlay/TesseractOcr.kt` + قناة `cobra/ocr` في `MainActivity.kt`.
  - نماذج اللغة (`ara`, `eng` من `tessdata_fast`) بتتنزّل وقت البناء من commit مثبّت
    مع التحقق من SHA-256؛ لو ناقصة أو متغيّرة البناء بيفشل.
  - لو Tesseract فشل أو مش متاح بيحصل رجوع تلقائي لـ ML Kit اللاتيني، والشاشة بتقول
    للمستخدم صراحة إن العربي ما اتقراش.
  - فشل القراءة بيظهر كفشل ("مش معناه إن الصورة آمنة")، مش كنتيجة سليمة.
- `lib/services/ocr_text.dart`: تنظيف نص الـ OCR (دالة نقية) + اختبارات.
### تغييرات بناء
- `patch_build_gradle.py` بيضيف مستودع JitPack ومكتبة `tesseract4android:4.9.0` لملف التطبيق (آمن للتكرار).
- قواعد R8 للمكتبة الجديدة في `proguard-rules.pro`.
- خطوة workflow جديدة: "Fetch OCR language models (verified)".
### حدود معروفة
- دقة العربي لم تُختبر على صور حقيقية بعد (قراءة العربي تُعرض للمستخدم كـ"تجريبية").
- حجم التطبيق بيزيد (نماذج ~5.5 MB + مكتبات أصلية لكل معمارية).

## 1.6.0+8
- إعادة تنظيم الواجهة: 5 تبويبات (الرئيسية، رابط، رسالة، السجل، المزيد). شاشة "المزيد" فيها كل
  الأدوات في أقسام (فحوصات إضافية، تعلّم وتدرّب، أدوات كلمات السر والروابط، الإعدادات).
- أزرار سريعة في الرئيسية (رابط، رسالة، QR، صورة، تدرّب، دروس).

## 1.5.x
- تحسينات محلل الروابط (اسم علامة تجارية داخل مسار الرابط، نطاقات عشوائية الشكل) مع اختبارات.
- إصلاحات البناء: workflow يدوي فقط، بناء arm/arm64، قواعد R8 لمكتبة ML Kit،
  `proguard-android-optimize.txt`.

- إصلاح توافق أيقونة زر القائمة في `AppHeader` مع اختبار الواجهة: استعادة `menu_rounded` مع الحفاظ على التصميم المطوّر.

## Performance refresh

- Added a one-time suffix index for official brand domains to avoid scanning every brand on each URL inspection.
- Optimized open-host checks to use hostname suffix lookups instead of walking the complete provider list.
- Replaced the typo-distance dynamic-programming matrix with a linear one-edit check for the analyzer's existing distance-one use case.
- Hoisted repeatedly-created random-domain regular expressions and short-circuited embedded-link counting.
- Kept the five root tab widgets stable across ordinary navigation and refreshes them on settings changes so locale updates remain correct.
- Moved batch URL analysis (4+ links) into a background isolate and added a busy/progress state without changing the analysis rules or removing tools.
- Added tests for indexed brand-domain matching and background batch-result equivalence.

- Optimized digit counting in random-looking hostname detection to stop once the four-digit threshold is reached.

- Deferred OpenPhish feed loading until after the first frame and moved large feed parsing/verification into a background isolate; advanced scanning waits for readiness.

## 2026-11-14 — V6 Scan Report dossier
- Reworked the completed advanced scan report into expandable sections for redirects, page/JavaScript inspection, DNS/TLS/ASN, local campaign correlation, reputation providers, and consolidated findings.
- Bound all report values to the existing analysis result objects; no mock intelligence or synthetic scan values were introduced.
- Added explicit partial-scan and unavailable-source messaging, and preserved selectable monospace technical values.
- Flutter/Dart analysis and tests were not run in this environment because the SDK is unavailable.

## 2026-11-14 — Remote Chromium dynamic analysis integration

- Added an optional remote Chromium analysis client and an isolated FastAPI worker under `sandbox_service/`.
- Added secure-storage configuration, separate user consent, report findings, timeout/error states, and privacy disclosure.
- Browser worker is non-root and explicitly enables Chromium's browser sandbox; Docker deployment requires host seccomp user-namespace configuration and private-egress firewall rules.
- This is a bounded page observer, not a certified malware detonation environment. Host deployment and Flutter tests/build remain required before production use.
