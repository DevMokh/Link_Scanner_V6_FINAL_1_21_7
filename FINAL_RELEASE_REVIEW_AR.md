# تقرير مراجعة وإصلاح Link Scanner V6 — 1.21.7+31

## مصدر التشخيص
تمت مراجعة سجل GitHub Actions رقم 189 في المستودع `DevMokh/Link_Scanner_V6_FINAL_1_21_5` مباشرة.

## نتائج التشغيل 189
- نجح `dart format`.
- نجح `flutter analyze --no-fatal-infos`.
- فشلت أربعة اختبارات في `Run tests`، لذلك تم تخطي بناء APK:
  1. تشغيل RDAP وPhishTank بشكل مستقل: كان PhishTank يُعاد من كاش اختبار سابق، فظهر المضيف المتوقع مفقودًا.
  2. تعطل PhishTank مع بقاء RDAP: النتيجة القديمة النظيفة كانت تُعاد من الكاش بدل استدعاء المحاكي الذي يرجع 503.
  3. عدم تخزين نتائج الخطأ/التخطي/غير المهيأ: كانت إدخالات العملية من اختبارات سابقة تلوّث عدد الإدخالات في الاختبار الحالي.
  4. استرجاع الكاش: `DateTime.fromMillisecondsSinceEpoch` أعاد وقتًا محليًا بدل UTC.

## الإصلاحات في 1.21.7+31
1. إعادة تكوين `checkedAt` و`expiresAt` من milliseconds بوضع UTC (`isUtc: true`)؛ تم الإبقاء على هذا الإصلاح من 1.21.6.
2. جعل `resetProcessCacheForTesting()` غير متزامن، وينتظر انتهاء طابور الكتابة قبل مسح الكاش المشترك.
3. زيادة generation عند reset لمنع أي lookup بدأ قبل reset من إعادة ملء الكاش بعده.
4. جعل `setUp` في اختبارات `ThreatIntelRepository` و`FreeThreatIntelEngine` ينتظر reset قبل استبدال SharedPreferences mock.
5. تحديث `pubspec.yaml` و`app_info.dart` و`CHANGELOG.md` إلى `1.21.7+31`.

## نطاق التغييرات
التغييرات محصورة في استقرار الاختبارات وتسلسل/استرجاع بيانات الكاش. لم يتم حذف وظيفة فحص أو تغيير تصميم التطبيق أو إضافة اشتراك أو API مدفوع أو مفتاح إلزامي.

## التحقق
- تم التحقق من تطابق رقم الإصدار بين `pubspec.yaml` و`app_info.dart`.
- تم التحقق من سلامة أرشيف ZIP بعد إنشائه.
- لم تتوفر أداة Flutter/Dart في بيئة إعداد الحزمة؛ لم يتم تشغيل `dart format` أو `flutter analyze` أو `flutter test` أو `flutter build apk` على 1.21.7. يلزم تشغيل CI للتحقق النهائي. لا يُدّعى نجاح اختبارات Dart أو بناء APK قبل ظهور نتيجة خضراء.
