import 'package:flutter/material.dart';

import '../core/theme.dart';
import '../services/settings_store.dart';
import 'common.dart';

/// إعدادات الفحص المتقدم ومفاتيح الخدمات الخارجية الاختيارية.
class IntelSettingsPanel extends StatefulWidget {
  const IntelSettingsPanel({super.key});

  @override
  State<IntelSettingsPanel> createState() => _IntelSettingsPanelState();
}

class _IntelSettingsPanelState extends State<IntelSettingsPanel> {
  final TextEditingController _sandboxEndpoint = TextEditingController();
  final TextEditingController _sandboxToken = TextEditingController();
  bool _hideSandboxToken = true;

  @override
  void initState() {
    super.initState();
    _sandboxEndpoint.text = SettingsStore.instance.dynamicSandboxEndpoint;
    _sandboxToken.text = SettingsStore.instance.dynamicSandboxToken;
  }

  @override
  void dispose() {
    _sandboxEndpoint.dispose();
    _sandboxToken.dispose();
    super.dispose();
  }

  Future<void> _toggleSandbox(bool value) async {
    FocusScope.of(context).unfocus();
    final endpoint = _sandboxEndpoint.text.trim();
    final token = _sandboxToken.text.trim();
    if (value && (Uri.tryParse(endpoint)?.scheme != 'https' || token.length < 32)) {
      toast(context, 'أدخل عنوان HTTPS ومفتاحًا بطول 32 حرفًا على الأقل، ثم احفظ.');
      return;
    }
    final saved = await SettingsStore.instance.setDynamicSandbox(
      enabled: value,
      endpoint: endpoint,
      token: token,
    );
    if (!mounted) return;
    if (!saved) toast(context, 'تعذر التخزين الآمن؛ الإعدادات ستظل للجلسة الحالية فقط.');
  }

  Future<void> _saveSandbox() async {
    FocusScope.of(context).unfocus();
    final endpoint = _sandboxEndpoint.text.trim();
    final token = _sandboxToken.text.trim();
    final enabled = SettingsStore.instance.dynamicSandboxEnabled;
    if (enabled && (endpoint.isEmpty || token.length < 32)) {
      toast(context, 'أدخل رابط HTTPS ومفتاح خدمة لا يقل عن 32 حرفًا، أو عطّل المحرك.');
      return;
    }
    if (endpoint.isNotEmpty && Uri.tryParse(endpoint)?.scheme != 'https') {
      toast(context, 'خدمة Chromium يجب أن تستخدم HTTPS.');
      return;
    }
    final saved = await SettingsStore.instance.setDynamicSandbox(
      enabled: enabled,
      endpoint: endpoint,
      token: token,
    );
    if (!mounted) return;
    toast(context, saved
        ? 'تم حفظ إعدادات Chromium في التخزين الآمن'
        : 'تعذر التخزين الآمن؛ الإعدادات متاحة للجلسة الحالية فقط.');
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: SettingsStore.instance,
      builder: (context, _) {
        return Panel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SectionTitle('مصادر الفحص المتقدم'),
              const Row(
                children: [
                  Icon(Icons.shield_outlined, color: C.statusSafe, size: 18),
                  SizedBox(width: 8),
                  Expanded(child: StatusBadge(label: 'NETGUARD / REDIRECT REQUEST GUARD', color: C.statusSafe, dot: false)),
                ],
              ),
              const SizedBox(height: 8),
              const Text(
                'NetGuard يتحقق من وجهات طلبات التحويلات قبل الاتصال، ويمنع العناوين المحلية والخاصة.',
                style: TextStyle(color: C.textSecondary, fontSize: 11.5, height: 1.45),
              ),
              const SizedBox(height: 8),
              const Text(
                'الفحص المتقدم اختياري ويجمع بين التحليل المحلي وتتبع التحويلات وعمر الدومين ومصدر PhishTank المجاني. تعطل أي مصدر خارجي لا يوقف بقية الفحص.',
                style: TextStyle(color: C.muted, fontSize: 12.5, height: 1.5),
              ),
              const SizedBox(height: 8),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: SettingsStore.instance.intelConsent,
                onChanged: (value) =>
                    SettingsStore.instance.setIntelConsent(value),
                title: const Text(
                  'السماح بالفحص المتقدم عبر الإنترنت',
                  style: TextStyle(
                    color: C.text,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                subtitle: const Text(
                  'عند الموافقة، يتتبع التحويلات ويرسل اسم الدومين إلى RDAP والرابط الكامل إلى PhishTank. يمكنك إيقافه لمنع الاستعلامات الخارجية؛ الفحص المحلي يظل متاحًا.',
                  style: TextStyle(color: C.muted, fontSize: 12, height: 1.45),
                ),
              ),
              const Divider(color: C.line, height: 28),
              const SectionTitle('محرك Chromium المعزول'),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: SettingsStore.instance.dynamicSandboxEnabled,
                onChanged: _toggleSandbox,
                title: const Text('تشغيل التحليل الديناميكي', style: TextStyle(color: C.text, fontSize: 14, fontWeight: FontWeight.w700)),
                subtitle: const Text(
                  'يشغّل JavaScript داخل Chromium على خادمك المعزول، وليس على الهاتف. لا يستورد Cookies أو جلسات، ولا يرسل نماذج؛ طلبات POST وما شابهها محظورة.',
                  style: TextStyle(color: C.muted, fontSize: 12, height: 1.45),
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _sandboxEndpoint,
                autocorrect: false,
                enableSuggestions: false,
                keyboardType: TextInputType.url,
                textDirection: TextDirection.ltr,
                textAlign: TextAlign.left,
                style: const TextStyle(fontFamily: 'monospace', color: C.text, fontSize: 12),
                decoration: fieldDecoration(hint: 'https://scanner.example.com/v1/analyze'),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _sandboxToken,
                obscureText: _hideSandboxToken,
                autocorrect: false,
                enableSuggestions: false,
                textDirection: TextDirection.ltr,
                textAlign: TextAlign.left,
                style: const TextStyle(fontFamily: 'monospace', color: C.text, fontSize: 12),
                decoration: fieldDecoration(hint: 'Chromium Sandbox API token'),
              ),
              Align(
                alignment: AlignmentDirectional.centerStart,
                child: TextButton.icon(
                  onPressed: () => setState(() => _hideSandboxToken = !_hideSandboxToken),
                  icon: Icon(_hideSandboxToken ? Icons.visibility_rounded : Icons.visibility_off_rounded, size: 18),
                  label: Text(_hideSandboxToken ? 'إظهار مفتاح Chromium' : 'إخفاء مفتاح Chromium'),
                  style: TextButton.styleFrom(foregroundColor: C.muted),
                ),
              ),
              FilledButton.icon(
                onPressed: _saveSandbox,
                style: filledButtonStyle(),
                icon: const Icon(Icons.save_rounded),
                label: const Text('حفظ إعدادات Chromium'),
              ),
              if (!SettingsStore.instance.dynamicSandboxSecure)
                const Padding(
                  padding: EdgeInsets.only(top: 6),
                  child: Text('تحذير: التخزين الآمن غير متاح؛ عنوان الخدمة والمفتاح لن يبقيا بعد إغلاق التطبيق.', style: TextStyle(color: C.amber, fontSize: 11.5)),
                ),
              const SizedBox(height: 8),
              const Text(
                'لا تفعّل هذا الخيار قبل نشر sandbox_service على خادم مخصص، تفعيل HTTPS، وتطبيق قواعد منع الوصول للشبكات الخاصة. سيتم إرسال الرابط الكامل إلى خادمك عند الفحص.',
                style: TextStyle(color: C.amber, fontSize: 11.5, height: 1.45),
              ),
              const Divider(color: C.line, height: 28),
              const SectionTitle('وضع المصادر المجانية'),
              const Text(
                'يستخدم الفحص التلقائي RDAP وPhishTank المجاني فقط. Google Web Risk وVirusTotal لا يتم استدعاؤهما تلقائيًا في هذا الإصدار لتجنب أي رسوم غير متوقعة أو شروط استخدام غير مناسبة. مفاتيحك القديمة، إن وجدت، لا تُرسل ولا تُستخدم، وتظل محفوظة للتوافق مع بيانات الإصدارات السابقة.',
                style: TextStyle(color: C.textSecondary, fontSize: 12, height: 1.55),
              ),
              const SizedBox(height: 8),
              const Text(
                'PhishTank لا يحتاج مفتاحًا في وضع الاستعلام المحدود المجاني، لكنه يفرض حدود طلبات متغيرة. عند بلوغ الحد، يتوقف هذا المصدر مؤقتًا وتستمر بقية وظائف التطبيق.',
                style: TextStyle(color: C.muted, fontSize: 11.5, height: 1.5),
              ),
            ],
          ),
        );
      },
    );
  }
}
