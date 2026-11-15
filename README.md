# كاشف الروابط | Link Scanner

## Latest release candidate — 1.21.5+29
- Fixes the CI regression where a normal Google search URL containing an encoded `q=` URL was incorrectly treated as a concealed redirect.
- Shares recent threat-intelligence cache entries between repository instances in the same isolate, while preserving the persistent privacy-safe cache.
- The Dart test suite and APK build must pass in CI before this candidate is verified.

## Previous release candidate — 1.21.4+28
- Corrected Arabic brand matching by evaluating both the Unicode IDN hostname and its confusable skeleton; short Arabic aliases in paths remain gated by credential context.
- Deep-link analysis now inspects the raw query and fragment so defanged embedded destinations retain their concealment evidence before normalization.
- Threat-intelligence cache reads and writes now reload, merge, and serialize persisted state across repository instances.
- These changes target the five failing test cases reported by CI. Flutter analysis, the complete Dart test suite, and APK build must still pass in GitHub Actions before the candidate can be called verified.

- Arabic brand detection now uses Unicode-aware word boundaries and supports documented local names such as ڤودافون، انستاباي، سي اي بي، بنك مصر، البنك الأهلي المصري، أورنج، المصرية للاتصالات، جوميا، وفوري. Ambiguous names still require a login/verification context before becoming an impersonation signal.
- The Arabic aliases are matched locally in host/path text; no link is sent to an external service for this feature. Existing official-domain entries were not changed.

- Tightened concatenated brand-name matching: only a controlled set of security/account suffixes (for example `account`, `login`, `secure`, and `verify`) is accepted. Arbitrary words such as `paypalish`, `googley`, and `applepie` are not treated as impersonation merely because they start with a brand key.
- Expanded synthetic brand regression coverage with official-domain checks and catalog-derived positive/negative fixtures. The reported precision/recall thresholds are regression gates for this synthetic corpus only, not real-world accuracy claims.
- No new package dependency, paid service, required API key, or runtime network requirement was added.


- Added shareable structured JSON reports with a versioned schema, UTC generation time, verdict, score, finding codes, and host metadata. For privacy, the JSON export omits the full URL, path, query parameters, and finding details by default; the existing human-readable report remains available.
- Improved the Unicode UTS #39 generator with a minimum-mapping guard and an explicit generated mapping count.
- CI now makes a best-effort download of the pinned official Unicode 18.0.0 dataset, validates at least 100 ASCII-target mappings, and passes the exact generated data file from verification to APK build. Network failure retains the bundled fallback and does not add a runtime network dependency.
- Added regression tests for safe JSON report redaction and invalid-input reports that correctly carry null risk scores.

The free-only advanced reputation path now uses RDAP and the PhishTank URL lookup API. It does not automatically call Google Web Risk or VirusTotal, so users are not exposed to their quotas, keys, or possible charges. PhishTank requests require explicit advanced-scan consent, are rate-limited, and fail independently; local scanning remains available when offline or when the provider is unavailable. The optional Chromium worker retains its network boundary hardening from 1.14.0+17.



> (اسم المشروع الداخلي لسه `cobra_shield` وبكج أندرويد `com.cobrashield.cobra_shield` عمدًا، عشان بيانات المستخدمين الحاليين وملفات البناء ما تتأثرش. اللي اتغيّر هو الاسم والهوية اللي بيشوفها المستخدم.)

تطبيق Flutter (أندرويد) بواجهة عربية داكنة (Material 3) لفحص الروابط والرسائل ورموز QR وصور
الرسائل بحثًا عن علامات الاحتيال والتصيّد. التحليل الأساسي بيتم على الجهاز.

## الميزات
- فحص رابط: نقاط خطورة + أسباب مفصّلة (انتحال علامات تجارية، نطاقات مريبة، اختصارات، مسارات...).
  قبل التحليل الرابط بيتنضّف ويتفك تمويهه: ترميز % متكرر، حروف خفية، بروتوكول مكسور، IP بصيغ
  hex/ثماني/رقم واحد، `@` المخادعة، حروف متشابهة (Homograph). فيه كمان تقرير منظم
  (`UrlAnalyzer.report`): الدرجة، المستوى (لا مؤشرات/مشبوه/خطير)، الرابط بعد التنظيف، والإشارات بشرح ووزن.
- فحص رسالة: استخراج الروابط وتحليل أسلوب الرسالة (استعجال، طلب بيانات، ...).
  (عربي / إنجليزي / مختلط بنفس القوة؛ علامات الاتجاه LRM/RLM مش تهديد لوحدها.)
- مسح QR وفحص الرابط قبل فتحه.
- فحص صورة رسالة: قراءة النص من لقطة الشاشة (عربي + إنجليزي، على الجهاز) ثم تحليله.
- فحص المرسل، فحص مجمّع، أدوات كلمات السر والروابط، تدريب ودروس.
- خيارات متقدمة اختيارية: توسيع الروابط المختصرة، وفحص السمعة المجاني عبر RDAP وPhishTank بعد موافقة المستخدم.

## Latest analyzer improvements — 1.20.0+23
- Detects adjacent transposition typos in non-ambiguous protected brand names (for example, `googel` vs `google`).
- Caches normalized brand aliases and excludes a lone trailing character addition/deletion (such as `googley`) from typo detection, while retaining internal typo and transposition checks.
- Adds regression cases for deceptive registrable-domain boundaries such as `paypal.com.evil.example` and valid official subdomains.
- CI produces a repeatable offline JSON benchmark with synthetic confusion-matrix and latency metrics. These metrics describe only the bundled fixtures, not real-world detection performance.
- Detects supported Unicode confusable brand names in URL paths when a sensitive login/verification context is also present.
- The source package keeps a small offline Unicode fallback table. GitHub Actions now attempts to fetch the pinned official Unicode 18.0.0 confusables data, requires at least 100 printable-ASCII mappings before replacing the fallback, then passes the exact generated file from the verification job into the APK build. If the fetch fails, CI keeps the fallback instead of blocking the app or falsely claiming complete UTS #39 coverage.
- The generated Unicode table includes the Unicode License V3 copyright and permission notice. The data is bundled into the APK and works offline after installation; no paid API or runtime download is required.
- The result is a printable-ASCII-target subset of UTS #39 suitable for the current ASCII brand/domain skeleton comparison, not every possible Unicode spoofing mechanism.

## وضع النسخة المجانية — 1.20.0+23
- الفحص التلقائي لمصادر السمعة يستخدم RDAP وPhishTank فقط بعد موافقة المستخدم.
- لا يتم إرسال أي طلب تلقائي إلى Google Web Risk أو VirusTotal، حتى لو كانت مفاتيح قديمة محفوظة من إصدار سابق.
- PhishTank مجاني، لكن له حدود طلبات متغيرة؛ عند تجاوز الحد يتم تأجيل هذا المصدر فقط، ولا يتوقف التطبيق ولا يُصنّف الرابط كآمن.
- فشل الإنترنت لا يمنع الفحص المحلي. عدم وجود تطابق في PhishTank لا يضمن سلامة الرابط.

## سجل تاريخي: Google Web Risk (تحديث 1.12.0+15)
> هذا القسم يوثق ترقية سابقة؛ في الإصدار 1.16.0+19 لم يعد المحرك المجاني يستدعي Web Risk تلقائيًا.
- تم ترحيل فحص Google من Safe Browsing v4 المتقاعد إلى Web Risk Lookup API.
- يستعلم عن قوائم Malware وSocial Engineering وExtended Coverage وUnwanted Software.
- المفتاح القديم محفوظ بنفس مفتاح التخزين الداخلي لتجنب فقد إعدادات المستخدم، لكن يجب تفعيل Web Risk API ومراجعة قيود المفتاح في Google Cloud.
- لم يتغير خيار موافقة الفحص المتقدم؛ الرابط الكامل لا يُرسل إلى Google إلا عند تفعيل الموافقة وإدخال المفتاح.
- الاستعلام لا يتبع تحويلات HTTP حتى لا يُعاد توجيه المفتاح إلى مضيف آخر.

## الهوية والتصميم
- هوية **Cyber Operations / Terminal**: خلفية سوداء شبه مطفية، أسطح مستطيلة وحدود تقنية، أخضر فوسفوري للتحكم والحالة النشطة، وسماوي لبيانات التتبع، مع واجهة RTL كاملة (عربي/إنجليزي).
  الأصفر والبرتقالي والأحمر مخصّصة لمستويات الخطورة، والأخضر الهادئ لمؤشرات النجاح.
- الشاشة الرئيسية أصبحت لوحة عمليات أمنية (SOC-style): حالة المحرك المحلي، وحدات تحليل مرقمة، مؤشرات سجل حقيقية، وسجل نشاط مختصر.
- تبويب المزيد والقائمة الجانبية منظّمان كمجموعات عمليات ووحدات جمع وتحليل وتدريب وإعدادات، مع الإبقاء على كل وجهات الأدوات السابقة.
- الشعار: **درع أخضر فوسفوري بداخله رمز رابط (سلسلة)**، مرسوم بالكود (`lib/widgets/brand_logo.dart`) بدون صور أو عدسة مكبرة.
  بيظهر في الشاشة الرئيسية والقائمة الجانبية والترويسات وأيقونة التطبيق وشاشة التشغيل.
- القائمة الجانبية (`app_drawer.dart`): كل بند بيودّي لوجهة حقيقية في التطبيق. مفيش بنود شكلية.
- الشاشة الرئيسية: كل الأرقام (الروابط المفحوصة، التهديدات، عدد الفحوصات، آخر فحص) من سجل الفحوصات على الجهاز؛ مفيش أرقام تجريبية.
  حالة الحماية بتقول "جاهز للفحص" مش "أنت في أمان"، لأن التطبيق بيفحص لما تطلب منه ومفيش حماية لحظية في الخلفية.
- مكوّنات مشتركة: `theme.dart` (الألوان `C.accent`/`C.green`...)، `PrimaryButton`، `AppHeader`، `Panel`.

## تراخيص البيانات الخارجية
- إشعار Unicode UTS #39 ورخصة Unicode License V3 موجودان في `THIRD_PARTY_NOTICES.md`، كما يتضمن ملف البيانات المضمّن إشعار حقوق النشر والإذن المطلوب.

## الخصوصية
- التحليل المحلي ما بيرسلش نص الرسائل أو الصور لأي خادم.
- الميزات اللي بتستخدم الإنترنت اختيارية: توسيع الرابط (بيتصل بالرابط نفسه)، والفحص المتقدم (RDAP وPhishTank بعد الموافقة). الإصدار المجاني لا يستدعي Web Risk أو VirusTotal تلقائيًا.
- قراءة الصور (OCR) بتتم بالكامل على الجهاز.
- مفاتيح Google/VirusTotal القديمة، لو موجودة، تظل في Android Keystore للتوافق فقط؛ النسخة المجانية لا تستخدمها ولا ترسلها.
- تتبع الروابط بيرفض الوجهات المحلية/الداخلية (راجع `lib/services/net_guard.dart`).
- الفحص المتقدم (تتبّع الروابط + RDAP + PhishTank) محتاج موافقتك، وتقدر تسحبها في أي وقت من
  أدوات ← مصادر الفحص المتقدم ← "السماح بالفحص المتقدم عبر الإنترنت".
- "الخدمة غير مُعدّة" أو فشل أي مصدر خارجي **لا يعني إن الرابط آمن** ولا بيضيف نقاط خطر. التفاصيل الكاملة
  لتدفق البيانات في [`PRIVACY.md`](PRIVACY.md).

## نتيجة الفحص: حالات مستقلة
- **إدخال غير صالح** (`not-a-url`، `https://`، بروتوكول غير http/https): مفيش درجة خطر أصلًا.
- **تهديد مؤكد** / **مشبوه** (متوسط / عالي / حرج بحدود موحّدة 20 / 45 / 70) / **لا مؤشرات واضحة** / **معلومات غير كافية** /
  **فحص جزئي** / **فشل التحليل**.
- "لا مؤشرات واضحة" **مش "آمن"**: عدم ظهور مؤشرات في التحليل لا يضمن سلامة الرابط.
- فشل DNS أو الوصول للموقع مش دليل تصيّد. التمييز بين الـ Hostname والـ Registrable Domain بيستخدم Public Suffix List
  حقيقية مضمّنة (`lib/core/psl_data.dart`، تتولّد بـ `tool/gen_psl.py`).

## البنية
- `lib/core`: نماذج، معرفة، علامات تجارية، ثيم، سيناريوهات.
- `lib/services`: المحللات (رابط/رسالة/مرسل/QR)، OCR، الإعدادات، السجل، مصادر الفحص الخارجي...
  - محرك الروابط: `url_normalizer.dart` (تطبيع + فك تمويه)، `url_confusables.dart` (حروف متشابهة)،
    `url_evasion.dart` (كواشف التمويه + جدول الأوزان `UrlWeights`)، `url_report.dart` (التقرير المنظم)،
    و`url_analyzer.dart` (التجميع النهائي والدرجة).
  - `url_validator.dart` (التحقق من إن المدخل رابط ويب)، `public_suffix.dart` (النطاق المسجّل)،
    `net_guard.dart` / `link_expander.dart` / `http_util.dart` (حماية الاتصالات الخارجية)، `online_intel.dart` (مصادر الفحص الخارجي).
- `lib/screens`, `lib/widgets`: الواجهة (`brand_logo` الشعار، `app_header` الترويسة، `app_drawer` القائمة الجانبية، `common` المكوّنات المشتركة).
- `android_overlay`: ملفات أندرويد بتتطبّق وقت البناء (Manifest، MainActivity، Tesseract، قواعد R8، سكربت تعديل Gradle).
- `test`: اختبارات الوحدة.

## البناء والـ CI (GitHub Actions)
المشروع مرفوع بدون مجلد `android`؛ الـ workflow (`.github/workflows/main.yml`) بيشتغل على **كل push وPull Request**
وكمان يدويًا (`workflow_dispatch`). بيولّد مجلد android ويطبّق `android_overlay` وينزّل نماذج OCR مع التحقق من SHA-256.

**البوابة (job `verify`)، أي فشل = لا يوجد APK:**
1. `flutter pub get` لإنشاء lockfile واحد.
2. `dart format lib test tool` داخل بيئة CI، من غير تعديل تلقائي للمستودع أو commit.
3. `flutter analyze --no-fatal-infos` (أي خطأ أو تحذير يوقف البوابة).
4. تجهيز شهادة HTTPS محلية للاختبارات ثم `flutter test`.

بعد نجاح البوابة فقط، يبدأ `build`: ينقل ملف `pubspec.lock` نفسه من Job التحقق ويستخدم
`flutter pub get --enforce-lockfile`، ثم يولّد مجلد Android ويطبّق `android_overlay` وينزّل نماذج OCR مع التحقق من SHA-256.
بعدها يبني APK ويشغّل `tool/verify_apk.sh` للتحقق من الملف والإصدار والأذونات والتوقيع.
**لا يتم بناء APK أو رفعه عند فشل التحليل أو الاختبارات، ولا يتم رفعه إذا فشل التحقق النهائي.**

إصدارات Actions مضبوطة على Node.js 24، وإصدار Flutter الافتراضي `3.50.0` (يمكن تغييره من `workflow_dispatch`).
لو بتستخدم أداة ترفع كل ملف في commit منفصل، الـ concurrency بيلغي الـ runs القديمة ويكمّل آخر واحد بس.
عند التشغيل اليدوي اختر `build_type`:
- `debug` (الافتراضي): APK للتجربة، من غير أي مفاتيح توقيع.
- `release`: APK موقّع بمفتاحك. محتاج أسرار الريبو: `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`,
  `KEY_PASSWORD`, `KEY_ALIAS`. لو ناقصة البناء بيفشل برسالة واضحة (مفيش توقيع بمفتاح debug بشكل صامت).
  الأسرار بتتمرر كمتغيرات بيئة ومبتتطبعش في اللوج.

**تشغيل أول مرة:** تم تحديث الثيم ومسار CI في هذه النسخة، لكن Flutter/Dart SDK غير متاح داخل بيئة التحرير الحالية؛ لذلك لم يتم الادعاء بتشغيل `flutter analyze` أو `flutter test` أو بناء APK هنا.
GitHub Actions ينشئ `pubspec.lock` ويرفعه كـ artifact باسم `pubspec-lock`، ويستخدم نفس الملف داخل البناء. بعد أول تشغيل ناجح، نزّل الـ artifact وأضف `pubspec.lock` إلى المستودع لتثبيت إصدارات الاعتماديات بين مرات التشغيل.

## الاختبارات
مجلد `test`: التحقق من المدخل (`url_validator_test`)، المقياس الموحّد (`scoring_test`)، حالات الحكم (`verdict_test`)،
Public Suffix List والمتجهات الرسمية (`public_suffix_test`)، تطبيع الروابط وكشف التمويه، الرسائل، الحروف الخفية/علامات الاتجاه،
حارس الشبكة وتتبّع الروابط (بما فيها اختبارات تكامل بخادم محلي)، الفحص المتقدم، تنظيف ملفات الإصدار القديم، مفاتيح API والتخزين، OCR.
واجهة التصميم الجديد: `brand_logo_test` (الشعار)، `app_shell_widgets_test` (القائمة الجانبية والترويسة والزر الرئيسي والثيم)،
`home_dashboard_test` (إحصائيات الشاشة الرئيسية)، `batch_scanner_test` (تكافؤ نتائج الفحص بالخلفية)، `brand_domain_index_test`، `legacy_data_cleanup_test`، و`app_info_test` (الاسم ورقم الإصدار).
اختبارات الشبكة المحلية ما بتحتاجش إنترنت.

## قراءة العربي (OCR)
- المحرك: Tesseract (`tesseract4android` 4.9.0، من JitPack) + نماذج `tessdata_fast` للعربية والإنجليزية.
- الرجوع التلقائي لـ ML Kit اللاتيني لو Tesseract فشل، والشاشة بتنبّه المستخدم.
- دقة العربي بتعتمد على جودة الصورة؛ القراءة الآلية بتخطئ أحيانًا خصوصًا في الروابط، لذلك النص
  المستخرج قابل للتعديل قبل الفحص.

## تراخيص مكوّنات OCR
Tesseract و tessdata_fast و Tesseract4Android كلها بترخيص Apache-2.0.

## حدود معروفة
- دقة OCR العربي على أجهزة أندرويد حقيقية **لسه ما اتجرّبتش** (راجع `REVIEW_REPORT_1.11.0.md`).
- الحماية من DNS Rebinding متصمّمة (فحص كل العناوين + الاتصال بالـ IP المتحقق منه) لكن ما اتثبتتش عمليًا لسه.
- السجل بيحفظ الدرجة فقط، فالنتائج الجزئية بتظهر فيه كدرجة 0.
- تفاصيل أكتر: `CHANGELOG.md` و`REPAIR_REPORT.md` و`REVIEW_REPORT_1.11.0.md` و`PRIVACY.md`.

## تحديث الواجهة — 14 نوفمبر 2026

أُعيد تنظيم التطبيق حول مركز تحكم رئيسي، وشريط تنقل سفلي عائم، وشبكات أدوات مقسمة حسب المهمة. شاشة فحص الرابط تعرض حقل الإدخال وإجراءات اللصق وQR بترتيب أوضح. راجع `DESIGN_REFRESH_REPORT.md` لمعرفة تفاصيل التغييرات ونطاق التحقق.

## تحديث الأداء وإزالة قاعدة البيانات
قاعدة OpenPhish المحلية أُزيلت من هذا الإصدار لتقليل حجم العمل والتحميل؛ لا توجد قائمة تصيّد كبيرة تُنزّل أو تُحمّل عند التشغيل. بقي الفحص المحلي وتحليل الرسائل والـQR والصور، وتتبع التحويلات وRDAP. في الإصدار 1.16.0+19 أُوقف الاستدعاء التلقائي لـGoogle Web Risk وVirusTotal ضمن سياسة المصادر المجانية، وأُضيف PhishTank. عند ترقية إصدار أقدم، تُحذف ملفات القاعدة القديمة تلقائيًا.

## Optional remote Chromium dynamic analysis

The optional remote worker and deployment notes are in `sandbox_service/`. Read `DYNAMIC_CHROMIUM_SETUP_AR.md` before configuring it. It requires a dedicated Linux VM, HTTPS reverse proxy, host seccomp user-namespace configuration, and host-level private/reserved egress filtering; it is not enabled until the endpoint, API token, and separate consent are configured in the app.


## Unicode confusables data (UTS #39)

The domain skeleton engine keeps its existing curated compatibility map and
can be extended from the official Unicode UTS #39 `confusables.txt` file.
The generator is pinned to Unicode 18.0.0 and imports only single-code-point
sources whose complete target is printable ASCII; this is the subset needed by
the app's ASCII brand/domain skeleton matching.

To refresh the generated data when preparing a release:

```bash
python tool/update_unicode_confusables.py --version 18.0.0
```

For an offline/reproducible update, download the official file separately and use:

```bash
python tool/update_unicode_confusables.py --version 18.0.0 --input /path/to/confusables.txt
```

The script rejects a file whose embedded Unicode version does not match the
pinned version. The checked-in map currently contains a small official starter subset; it is
not the complete Unicode dataset until the generator is run against the full
source file. The manually maintained mappings remain active as a compatibility
layer. Unicode confusable matching is an indicator,
not proof of malicious intent, and localized script combinations must not be
flagged solely because they are non-ASCII.

## Threat intelligence cache

Advanced reputation lookups use `ThreatIntelRepository` to share in-flight
requests and cache completed free RDAP and PhishTank reputation results locally in the current free-only scan path; legacy Web Risk/VirusTotal functions remain unused by the scanner.
The cache key is a SHA-256 digest; raw URLs and domains are not stored.
Only clean/hit results are cached, with short source-specific TTLs. Network
errors, missing API keys, skipped providers, and unknown results are never
reused as clean verdicts. Clearing this cache does not clear API keys or scan history.
