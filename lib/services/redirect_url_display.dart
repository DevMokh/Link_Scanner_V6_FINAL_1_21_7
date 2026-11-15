/// Safe display formatting for redirect URLs.
///
/// Redirect destinations can contain password-reset tokens, session identifiers,
/// email addresses, and other private values in user-info, paths, queries, or
/// fragments. The scanner still keeps the original URL internally for analysis,
/// but UI timelines should show only the origin and whether hidden components exist.
class RedirectUrlDisplay {
  RedirectUrlDisplay._();

  static String redact(String raw) {
    final uri = Uri.tryParse(raw);
    if (uri == null ||
        (uri.scheme != 'http' && uri.scheme != 'https') ||
        uri.host.isEmpty) {
      return '[invalid redirect URL]';
    }

    final out = StringBuffer()
      ..write(uri.scheme.toLowerCase())
      ..write('://')
      ..write(uri.host.contains(':') ? '[${uri.host}]' : uri.host);
    if (uri.hasPort) out.write(':${uri.port}');

    final hasPath = uri.path.isNotEmpty && uri.path != '/';
    if (hasPath) {
      out.write('/…');
    } else if (uri.path == '/') {
      out.write('/');
    }
    if (uri.hasQuery) out.write('?…');
    if (uri.hasFragment) out.write('#…');
    if (uri.userInfo.isNotEmpty) out.write(' [credentials hidden]');
    return out.toString();
  }
}
