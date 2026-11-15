// Official Unicode UTS #39 18.0.0 starter mappings.
// SPDX-License-Identifier: Unicode-3.0
// Copyright © 1991-2026 Unicode, Inc.
// Permission is hereby granted, free of charge, to any person obtaining a copy of data files and any associated documentation (the "Data Files") or software and any associated documentation (the "Software") to deal in the Data Files or Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, and/or sell copies of the Data Files or Software, and to permit persons to whom the Data Files or Software are furnished to do so, provided that either (a) this copyright and permission notice appear with all copies of the Data Files or Software, or (b) this copyright and permission notice appear in associated Documentation.
// License: https://www.unicode.org/license.txt
// Full notice: THIRD_PARTY_NOTICES.md.
// Run tool/update_unicode_confusables.py to replace this small seed subset with
// the complete printable-ASCII subset from the versioned official data file.
// Unicode data terms: https://www.unicode.org/terms_of_use.html
// Do not edit manually; retain source/version provenance when refreshing.
const String kUnicodeConfusablesVersion = '18.0.0';
const int kUnicodeConfusablesCount = 3; // Offline starter subset; CI refreshes the full ASCII-target subset when available.
const Map<int, String> kUnicodeConfusables = <int, String>{
  0x0406: 'l', // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
  0x04C0: 'l', // CYRILLIC LETTER PALOCHKA
  0x0627: 'l', // ARABIC LETTER ALEF
};
