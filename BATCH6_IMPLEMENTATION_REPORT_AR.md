# تقرير تنفيذ الدفعة السادسة — Link Scanner V6 Professional Global

**الإصدار:** `1.17.0+20`  
**السياسة:** مجاني، الفحص المحلي يستمر دون الإنترنت، لا مفاتيح أو اشتراكات جديدة، ولا حذف لأي ميزة قديمة.

## ما تم تنفيذه

### 1) خط بيانات Unicode الرسمي في CI
- إضافة حد أدنى قابل للضبط في `tool/update_unicode_confusables.py` باستخدام `--minimum-mappings`.
- منع استبدال جدول fallback إذا كان المصدر ناقصًا أو لم ينتج العدد الأدنى من mappings.
- إضافة `kUnicodeConfusablesCount` إلى الملفات المولّدة، واختبار تطابق العدد مع طول Map.
- تحديث GitHub Actions ليحاول جلب `confusables.txt` الإصدار 18.0.0 من Unicode الرسمي مجانًا.
- لا يفشل CI إذا تعذر تحديث بيانات Unicode؛ يحتفظ بجدول fallback الموجود.
- بعد اختبارات Dart، يرفع CI ملف البيانات كـ artifact، ثم يستخدم build job نفس الملف الذي اجتاز verify لبناء APK.
- لا يحدث أي تنزيل وقت تشغيل التطبيق؛ البيانات، عند تحديثها في CI، تُضمّن داخل APK وتعمل offline.
- تضمين إشعار Unicode License V3 وإضافة `THIRD_PARTY_NOTICES.md`. الترخيص يسمح بالاستخدام والتعديل والتوزيع مجانًا مع إرفاق إشعار حقوق النشر والإذن.

**قيد مهم:** ملف ZIP الحالي لا يحتوي على الجدول الرسمي الكامل؛ محاولة التنزيل من بيئة التحرير فشلت بسبب DNS. يحتوي الملف المحلي على 3 mappings fallback فقط. اكتمال مجموعة printable-ASCII mappings يعتمد على نجاح خطوة Unicode best-effort في GitHub Actions. لا ندّعي تغطية UTS #39 كاملة قبل رؤية سجل CI وعدد mappings النهائي.

### 2) تقرير JSON آمن للمشاركة
- إضافة `ScanResult.toStructuredReport()` و`toJsonReport()`.
- يتضمن schema version، وقت الإنشاء UTC، الحكم، الدرجة، المستوى، الحالة الجزئية، بيانات المضيف، أكواد الإشارات، ونتائج الروابط المضمّنة بشكل مختصر.
- يحذف الرابط الكامل والمسار ومعاملات الاستعلام وتفاصيل الإشارات افتراضيًا لتقليل احتمال مشاركة session tokens أو reset tokens.
- إضافة زر مشاركة JSON بجوار مشاركة التقرير النصي؛ وظيفة التقرير النصي السابقة لم تتغير.
- الإدخال غير الصالح يصدر `score: null` و`risk_level: null` بدل درجة صفر قد تُفهم خطأً كحكم أمان.

### 3) اختبار تراجع لانتحال العلامات
- إضافة corpus اصطناعي من روابط `.example` لاختبار حالات انتحال علامات متعددة.
- إضافة حالات سليمة/ملتبسة لمنع انذارات خاطئة على الدومينات الرسمية، صفحات الأخبار، أسماء الطعام، الكلمات الأطول، والنص العربي العادي.
- هذه مجموعة regression صغيرة وليست قياسًا إحصائيًا عامًا للدقة أو اختبارًا على روابط حقيقية.

## الملفات الأساسية المعدلة/المضافة
- `.github/workflows/main.yml`
- `tool/update_unicode_confusables.py` و`tool/test_update_unicode_confusables.py`
- `lib/core/unicode_confusables_data.dart`
- `lib/core/models.dart`
- `lib/screens/url_scan_screen.dart`
- `lib/core/app_info.dart` و`lib/services/online_intel.dart`
- `pubspec.yaml`
- `test/structured_report_test.dart`
- `test/brand_detection_regression_test.dart`
- `test/unicode_confusables_data_test.dart`
- `README.md`, `CHANGELOG.md`, `GLOBAL_ROADMAP_AR.md`, `PRIVACY.md`, `THIRD_PARTY_NOTICES.md`

## التحقق الذي نُفذ فعليًا
- اختبارات مولّد Unicode: `9 passed`.
- اختبارات خدمة Chromium Python: `27 passed`.
- الإجمالي: `36 Python tests passed`.
- `compileall` نجح.
- صياغة YAML وShell نجحت.
- اختبار فشل تنزيل Unicode: DNS تعذر، وبصمة ملف fallback قبل/بعد متطابقة؛ أي إن محاولة التحديث لا تفسد البيانات الموجودة.
- تم فحص أرقام الإصدار: `pubspec.yaml = 1.17.0+20` و`kAppVersion/kAppBuild = 1.17.0/20`.

## ما لم يُتحقق منه بعد
- لم تتوفر Flutter أو Dart في بيئة التحرير؛ لذلك لم يتم تشغيل `dart format` أو `flutter analyze` أو `flutter test`.
- اختبارات Dart الجديدة (تقرير JSON، corpus العلامات، metadata Unicode) مضافة لكنها تنتظر GitHub Actions.
- لم يتم بناء APK أو تشغيله على جهاز Android حقيقي.
- لم يتم تأكيد نجاح تنزيل Unicode الرسمي داخل GitHub Actions؛ ملف الحزمة الحالية يستخدم fallback من 3 mappings.
- لم يتم تنفيذ PDF export؛ أُضيف JSON منظم بدون إضافة dependency جديدة.
- لم يتم بعد إنشاء benchmark كبير مستقل لقياس Precision/Recall، أو توسيع قاعدة العلامات التجارية على نطاق عالمي.

## التوافق وسياسة عدم التعطيل
- لم تُحذف أي ملفات من الإصدار `1.16.0+19`.
- لا توجد dependencies تشغيل جديدة أو APIs مدفوعة أو مفاتيح جديدة.
- فشل تنزيل Unicode لا يوقف CI أو التطبيق؛ يُحتفظ بالجدول السابق.
- مشاركة التقرير النصي القديمة مستمرة، وتصدير JSON إضافة مستقلة.
