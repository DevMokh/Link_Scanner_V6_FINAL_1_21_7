# تقرير الدفعة الأولى — Link Scanner V6 Professional Global Edition

**الإصدار:** 1.12.0+15  
**التاريخ:** 15 نوفمبر 2026  
**النطاق:** ترحيل مزود Google Threat Reputation مع الحفاظ على التوافق.

## لماذا التغيير؟

النسخة السابقة كانت تستدعي Google Safe Browsing v4 (`safebrowsing.googleapis.com/v4/threatMatches:find`). وثائق Google الحالية تصف واجهات Safe Browsing v4 بأنها Deprecated وتذكر أنها للاستخدام غير التجاري، وتوجّه الاستخدام التجاري إلى Web Risk:

- https://developers.google.com/safe-browsing/v4
- https://cloud.google.com/security/products/web-risk

اعتمدت هذه الدفعة Web Risk Lookup API (`https://webrisk.googleapis.com/v1/uris:search`). الوثائق الحالية توضح أن `uris.search` يقبل رابطًا واحدًا لكل طلب، ويقبل أنواع تهديد متعددة عبر معاملات `threatTypes` متكررة، ويعيد `threat.threatTypes` عند التطابق أو `{}` عند عدم وجود تطابق:

- https://docs.cloud.google.com/web-risk/docs/lookup-api
- https://docs.cloud.google.com/web-risk/docs/reference/rest/v1/ThreatType

## الملفات المعدلة

- `lib/services/online_intel.dart`
  - إضافة `OnlineIntel.webRisk()`.
  - طلب `MALWARE` و`SOCIAL_ENGINEERING` و`SOCIAL_ENGINEERING_EXTENDED_COVERAGE` و`UNWANTED_SOFTWARE`.
  - استخدام GET مع `uri` و`key` و`threatTypes` وفق REST API.
  - قراءة `threat.threatTypes` بدل بنية `matches` القديمة.
  - اعتبار `{}` فقط حالة عدم وجود تطابق؛ أي بنية 200 غير متوقعة تتحول إلى `error` ولا تُصنّف نظيفة.
  - عدم تمرير الطلب إلى أي تحويلة HTTP حتى لا يُعاد إرسال المفتاح الموجود في query string.
  - حد لحجم رد الخدمة إلى 256 KiB.
  - تعطيل اتباع التحويلات لهذا الطلب؛ لأن مفتاح API في query string.
  - الإبقاء على `OnlineIntel.safeBrowsing()` كاسم توافق، لكنه الآن يوجّه إلى Web Risk ولا يستدعي v4.
- `lib/services/advanced_scanner.dart`: توجيه الفحص المتقدم إلى `OnlineIntel.webRisk()`.
- `lib/widgets/intel_settings.dart`: تحديث اسم المزود وشرح تفعيل Web Risk API ومراجعة قيود المفتاح.
- `lib/screens/url_scan_screen.dart`: تحديث رسالة الموافقة ووسم المصدر.
- `lib/widgets/app_info_panel.dart`: تحديث بيان تدفق البيانات.
- `lib/services/http_util.dart`: تحديث تعليق الخدمات المعروفة.
- `lib/core/app_info.dart` و`pubspec.yaml`: رفع الإصدار إلى `1.12.0+15`.
- `lib/core/models.dart`: تحديث مثال مصدر التهديد المؤكد.
- `PRIVACY.md` و`README.md` و`CHANGELOG.md`: تحديث الإفصاح وسجل التغيير.
- `test/online_intel_test.dart`: اختبارات طلب Web Risk والاستجابة والأنواع المتعددة والأخطاء والتوافق مع الاسم القديم، مع حالة صريحة للبنية غير المتوقعة.
- `test/verdict_test.dart`: تحديث اسم المصدر في حالة الاختبار.

## التوافق وعدم حذف الميزات

- لم يتم حذف أي شاشة أو خدمة أو مسار فحص.
- تم الاحتفاظ بمفتاح التخزين القديم `cobra.key.gsb` وواجهة `gsbKey`؛ لا تضيع قيمة المفتاح المحفوظة عند الترقية.
- قد يحتاج المفتاح القديم إلى السماح بخدمة Web Risk ضمن API restrictions في Google Cloud، أو إنشاء مفتاح جديد.
- تم الاحتفاظ باسم `OnlineIntel.safeBrowsing()` للتوافق مع استدعاءات قديمة، لكن المصدر المنفذ حاليًا هو Web Risk.
- موافقة الفحص المتقدم ما زالت مطلوبة قبل إرسال الرابط الكامل إلى Google.

## ملاحظات أمان وتكلفة

- مفتاح Google Cloud يظل داخل query string لأن هذا هو شكل الاستدعاء الموضح في REST API. التطبيق يمنع اتباع التحويلات لهذا الطلب حتى لا يُرسل المفتاح إلى مضيف تحويلة.
- لا تضع مفتاحًا مقيدًا بشكل واسع؛ راجع API restrictions وقيود الاستخدام في Google Cloud.
- صفحة التسعير الحالية تذكر أن `uris.search` مجاني حتى 100,000 طلب شهريًا، وتُحسب تكلفة للطلبات الإضافية. يجب مراجعة الأسعار وحدود الحساب قبل الإطلاق لأنها قد تتغير:
  https://cloud.google.com/web-risk/pricing
- لم تتم إضافة OpenPhish Community Feed في هذه الدفعة؛ وثائق الناشر تصف Community Feed بأنه للاستخدام غير التجاري فقط. لا ينبغي تضمينه في إصدار تجاري/إعلاني دون ترخيص صالح:
  https://github.com/openphish/public_feed
  https://openphish.com/terms.html

## نتائج التحقق

| الفحص | النتيجة |
|---|---|
| Python sandbox tests | 19 passed (لا تختبر كود Dart/Web Risk) |
| Python compileall | نجح |
| YAML pubspec | صحيح |
| تطابق الإصدار بين `pubspec.yaml` و`app_info.dart` | 1.12.0+15 — مطابق |
| Bash syntax للسكربتات | نجح |
| Flutter analyze | لم يُشغّل — Flutter/Dart غير متاحين محليًا |
| Flutter tests | لم تُشغّل — Flutter/Dart غير متاحين محليًا |
| Android APK | لم يُبنَ — يحتاج CI/Flutter/Android toolchain |
| Web Risk live API | لم يُختبر بمفتاح حقيقي؛ الاختبارات تستخدم HTTP mocks |
| صياغة Dart / Flutter Tests | لم تُشغّل محليًا لغياب Flutter/Dart؛ يجب تأكيدها عبر CI |

## الخطوة التنفيذية التالية

1. شغّل GitHub Actions على commit الإصدار `1.12.0+15`، وافحص `Format, analyze, test` قبل الاعتماد.
2. بعد اجتياز CI، استخدم مفتاح Google Cloud مع تفعيل Web Risk API وقيود API مناسبة لاختبار `uris.search` على رابط اختبار غير ضار معتمد من Google.
3. أضف طبقة `ThreatIntelRepository` وذاكرة مؤقتة بنتائج ومصادر ووقت انتهاء صلاحية، مع فصل `no match` عن `error` و`not configured`.
4. قيّم كل Feed جديد حسب شروط إعادة الاستخدام التجارية والخصوصية قبل تنزيله أو تضمينه.
