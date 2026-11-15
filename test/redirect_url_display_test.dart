import 'package:cobra_shield/services/redirect_url_display.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Redirect URL display redaction', () {
    test('hides password-reset path, query token, and fragment', () {
      const secret = 'SESSION_SECRET_ABC123';
      final shown = RedirectUrlDisplay.redact(
        'https://example.com/account/reset/$secret?token=$secret#private-$secret',
      );
      expect(shown, 'https://example.com/…?…#…');
      expect(shown, isNot(contains(secret)));
      expect(shown, isNot(contains('/account/reset')));
      expect(shown, isNot(contains('token=')));
    });

    test('never shows URL user-info credentials', () {
      final shown = RedirectUrlDisplay.redact(
        'https://username:password@example.com/private/path',
      );
      expect(shown, 'https://example.com/… [credentials hidden]');
      expect(shown, isNot(contains('username')));
      expect(shown, isNot(contains('password')));
    });

    test('keeps origin and explicit port visible', () {
      expect(
        RedirectUrlDisplay.redact('https://sub.example.com:8443/'),
        'https://sub.example.com:8443/',
      );
    });

    test('keeps IPv6 host syntax valid', () {
      expect(
        RedirectUrlDisplay.redact('https://[2001:db8::1]/private'),
        'https://[2001:db8::1]/…',
      );
    });

    test('does not echo malformed or non-web input', () {
      expect(RedirectUrlDisplay.redact('not a url with secret'), '[invalid redirect URL]');
      expect(RedirectUrlDisplay.redact('file:///tmp/secret.txt'), '[invalid redirect URL]');
    });
  });
}
