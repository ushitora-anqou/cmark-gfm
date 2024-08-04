#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "cmark_ctype.h"
#include "utf8.h"

static const int8_t utf8proc_utf8class[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0};

static void encode_unknown(cmark_strbuf *buf) {
  static const uint8_t repl[] = {239, 191, 189};
  cmark_strbuf_put(buf, repl, 3);
}

static int utf8proc_charlen(const uint8_t *str, bufsize_t str_len) {
  int length, i;

  if (!str_len)
    return 0;

  length = utf8proc_utf8class[str[0]];

  if (!length)
    return -1;

  if (str_len >= 0 && (bufsize_t)length > str_len)
    return -str_len;

  for (i = 1; i < length; i++) {
    if ((str[i] & 0xC0) != 0x80)
      return -i;
  }

  return length;
}

// Validate a single UTF-8 character according to RFC 3629.
static int utf8proc_valid(const uint8_t *str, bufsize_t str_len) {
  int length = utf8proc_utf8class[str[0]];

  if (!length)
    return -1;

  if ((bufsize_t)length > str_len)
    return -str_len;

  switch (length) {
  case 2:
    if ((str[1] & 0xC0) != 0x80)
      return -1;
    if (str[0] < 0xC2) {
      // Overlong
      return -length;
    }
    break;

  case 3:
    if ((str[1] & 0xC0) != 0x80)
      return -1;
    if ((str[2] & 0xC0) != 0x80)
      return -2;
    if (str[0] == 0xE0) {
      if (str[1] < 0xA0) {
        // Overlong
        return -length;
      }
    } else if (str[0] == 0xED) {
      if (str[1] >= 0xA0) {
        // Surrogate
        return -length;
      }
    }
    break;

  case 4:
    if ((str[1] & 0xC0) != 0x80)
      return -1;
    if ((str[2] & 0xC0) != 0x80)
      return -2;
    if ((str[3] & 0xC0) != 0x80)
      return -3;
    if (str[0] == 0xF0) {
      if (str[1] < 0x90) {
        // Overlong
        return -length;
      }
    } else if (str[0] >= 0xF4) {
      if (str[0] > 0xF4 || str[1] >= 0x90) {
        // Above 0x10FFFF
        return -length;
      }
    }
    break;
  }

  return length;
}

void cmark_utf8proc_check(cmark_strbuf *ob, const uint8_t *line,
                          bufsize_t size) {
  bufsize_t i = 0;

  while (i < size) {
    bufsize_t org = i;
    int charlen = 0;

    while (i < size) {
      if (line[i] < 0x80 && line[i] != 0) {
        i++;
      } else if (line[i] >= 0x80) {
        charlen = utf8proc_valid(line + i, size - i);
        if (charlen < 0) {
          charlen = -charlen;
          break;
        }
        i += charlen;
      } else if (line[i] == 0) {
        // ASCII NUL is technically valid but rejected
        // for security reasons.
        charlen = 1;
        break;
      }
    }

    if (i > org) {
      cmark_strbuf_put(ob, line + org, i - org);
    }

    if (i >= size) {
      break;
    } else {
      // Invalid UTF-8
      encode_unknown(ob);
      i += charlen;
    }
  }
}

int cmark_utf8proc_iterate(const uint8_t *str, bufsize_t str_len,
                           int32_t *dst) {
  int length;
  int32_t uc = -1;

  *dst = -1;
  length = utf8proc_charlen(str, str_len);
  if (length < 0)
    return -1;

  switch (length) {
  case 1:
    uc = str[0];
    break;
  case 2:
    uc = ((str[0] & 0x1F) << 6) + (str[1] & 0x3F);
    if (uc < 0x80)
      uc = -1;
    break;
  case 3:
    uc = ((str[0] & 0x0F) << 12) + ((str[1] & 0x3F) << 6) + (str[2] & 0x3F);
    if (uc < 0x800 || (uc >= 0xD800 && uc < 0xE000))
      uc = -1;
    break;
  case 4:
    uc = ((str[0] & 0x07) << 18) + ((str[1] & 0x3F) << 12) +
         ((str[2] & 0x3F) << 6) + (str[3] & 0x3F);
    if (uc < 0x10000 || uc >= 0x110000)
      uc = -1;
    break;
  }

  if (uc < 0)
    return -1;

  *dst = uc;
  return length;
}

void cmark_utf8proc_encode_char(int32_t uc, cmark_strbuf *buf) {
  uint8_t dst[4];
  bufsize_t len = 0;

  assert(uc >= 0);

  if (uc < 0x80) {
    dst[0] = (uint8_t)(uc);
    len = 1;
  } else if (uc < 0x800) {
    dst[0] = (uint8_t)(0xC0 + (uc >> 6));
    dst[1] = 0x80 + (uc & 0x3F);
    len = 2;
  } else if (uc == 0xFFFF) {
    dst[0] = 0xFF;
    len = 1;
  } else if (uc == 0xFFFE) {
    dst[0] = 0xFE;
    len = 1;
  } else if (uc < 0x10000) {
    dst[0] = (uint8_t)(0xE0 + (uc >> 12));
    dst[1] = 0x80 + ((uc >> 6) & 0x3F);
    dst[2] = 0x80 + (uc & 0x3F);
    len = 3;
  } else if (uc < 0x110000) {
    dst[0] = (uint8_t)(0xF0 + (uc >> 18));
    dst[1] = 0x80 + ((uc >> 12) & 0x3F);
    dst[2] = 0x80 + ((uc >> 6) & 0x3F);
    dst[3] = 0x80 + (uc & 0x3F);
    len = 4;
  } else {
    encode_unknown(buf);
    return;
  }

  cmark_strbuf_put(buf, dst, len);
}

void cmark_utf8proc_case_fold(cmark_strbuf *dest, const uint8_t *str,
                              bufsize_t len) {
  int32_t c;

#define bufpush(x) cmark_utf8proc_encode_char(x, dest)

  while (len > 0) {
    bufsize_t char_len = cmark_utf8proc_iterate(str, len, &c);

    if (char_len >= 0) {
#include "case_fold_switch.inc"
    } else {
      encode_unknown(dest);
      char_len = -char_len;
    }

    str += char_len;
    len -= char_len;
  }
}

// matches anything in the Zs class, plus LF, CR, TAB, FF.
int cmark_utf8proc_is_space(int32_t uc) {
  return (uc == 9 || uc == 10 || uc == 12 || uc == 13 || uc == 32 ||
          uc == 160 || uc == 5760 || (uc >= 8192 && uc <= 8202) || uc == 8239 ||
          uc == 8287 || uc == 12288);
}

// matches anything in the P[cdefios] classes.
int cmark_utf8proc_is_punctuation(int32_t uc) {
  return (
      (uc < 128 && cmark_ispunct((char)uc)) || uc == 161 || uc == 167 ||
      uc == 171 || uc == 182 || uc == 183 || uc == 187 || uc == 191 ||
      uc == 894 || uc == 903 || (uc >= 1370 && uc <= 1375) || uc == 1417 ||
      uc == 1418 || uc == 1470 || uc == 1472 || uc == 1475 || uc == 1478 ||
      uc == 1523 || uc == 1524 || uc == 1545 || uc == 1546 || uc == 1548 ||
      uc == 1549 || uc == 1563 || uc == 1566 || uc == 1567 ||
      (uc >= 1642 && uc <= 1645) || uc == 1748 || (uc >= 1792 && uc <= 1805) ||
      (uc >= 2039 && uc <= 2041) || (uc >= 2096 && uc <= 2110) || uc == 2142 ||
      uc == 2404 || uc == 2405 || uc == 2416 || uc == 2800 || uc == 3572 ||
      uc == 3663 || uc == 3674 || uc == 3675 || (uc >= 3844 && uc <= 3858) ||
      uc == 3860 || (uc >= 3898 && uc <= 3901) || uc == 3973 ||
      (uc >= 4048 && uc <= 4052) || uc == 4057 || uc == 4058 ||
      (uc >= 4170 && uc <= 4175) || uc == 4347 || (uc >= 4960 && uc <= 4968) ||
      uc == 5120 || uc == 5741 || uc == 5742 || uc == 5787 || uc == 5788 ||
      (uc >= 5867 && uc <= 5869) || uc == 5941 || uc == 5942 ||
      (uc >= 6100 && uc <= 6102) || (uc >= 6104 && uc <= 6106) ||
      (uc >= 6144 && uc <= 6154) || uc == 6468 || uc == 6469 || uc == 6686 ||
      uc == 6687 || (uc >= 6816 && uc <= 6822) || (uc >= 6824 && uc <= 6829) ||
      (uc >= 7002 && uc <= 7008) || (uc >= 7164 && uc <= 7167) ||
      (uc >= 7227 && uc <= 7231) || uc == 7294 || uc == 7295 ||
      (uc >= 7360 && uc <= 7367) || uc == 7379 || (uc >= 8208 && uc <= 8231) ||
      (uc >= 8240 && uc <= 8259) || (uc >= 8261 && uc <= 8273) ||
      (uc >= 8275 && uc <= 8286) || uc == 8317 || uc == 8318 || uc == 8333 ||
      uc == 8334 || (uc >= 8968 && uc <= 8971) || uc == 9001 || uc == 9002 ||
      (uc >= 10088 && uc <= 10101) || uc == 10181 || uc == 10182 ||
      (uc >= 10214 && uc <= 10223) || (uc >= 10627 && uc <= 10648) ||
      (uc >= 10712 && uc <= 10715) || uc == 10748 || uc == 10749 ||
      (uc >= 11513 && uc <= 11516) || uc == 11518 || uc == 11519 ||
      uc == 11632 || (uc >= 11776 && uc <= 11822) ||
      (uc >= 11824 && uc <= 11842) || (uc >= 12289 && uc <= 12291) ||
      (uc >= 12296 && uc <= 12305) || (uc >= 12308 && uc <= 12319) ||
      uc == 12336 || uc == 12349 || uc == 12448 || uc == 12539 || uc == 42238 ||
      uc == 42239 || (uc >= 42509 && uc <= 42511) || uc == 42611 ||
      uc == 42622 || (uc >= 42738 && uc <= 42743) ||
      (uc >= 43124 && uc <= 43127) || uc == 43214 || uc == 43215 ||
      (uc >= 43256 && uc <= 43258) || uc == 43310 || uc == 43311 ||
      uc == 43359 || (uc >= 43457 && uc <= 43469) || uc == 43486 ||
      uc == 43487 || (uc >= 43612 && uc <= 43615) || uc == 43742 ||
      uc == 43743 || uc == 43760 || uc == 43761 || uc == 44011 || uc == 64830 ||
      uc == 64831 || (uc >= 65040 && uc <= 65049) ||
      (uc >= 65072 && uc <= 65106) || (uc >= 65108 && uc <= 65121) ||
      uc == 65123 || uc == 65128 || uc == 65130 || uc == 65131 ||
      (uc >= 65281 && uc <= 65283) || (uc >= 65285 && uc <= 65290) ||
      (uc >= 65292 && uc <= 65295) || uc == 65306 || uc == 65307 ||
      uc == 65311 || uc == 65312 || (uc >= 65339 && uc <= 65341) ||
      uc == 65343 || uc == 65371 || uc == 65373 ||
      (uc >= 65375 && uc <= 65381) || (uc >= 65792 && uc <= 65794) ||
      uc == 66463 || uc == 66512 || uc == 66927 || uc == 67671 || uc == 67871 ||
      uc == 67903 || (uc >= 68176 && uc <= 68184) || uc == 68223 ||
      (uc >= 68336 && uc <= 68342) || (uc >= 68409 && uc <= 68415) ||
      (uc >= 68505 && uc <= 68508) || (uc >= 69703 && uc <= 69709) ||
      uc == 69819 || uc == 69820 || (uc >= 69822 && uc <= 69825) ||
      (uc >= 69952 && uc <= 69955) || uc == 70004 || uc == 70005 ||
      (uc >= 70085 && uc <= 70088) || uc == 70093 ||
      (uc >= 70200 && uc <= 70205) || uc == 70854 ||
      (uc >= 71105 && uc <= 71113) || (uc >= 71233 && uc <= 71235) ||
      (uc >= 74864 && uc <= 74868) || uc == 92782 || uc == 92783 ||
      uc == 92917 || (uc >= 92983 && uc <= 92987) || uc == 92996 ||
      uc == 113823);
}

int cmark_utf8proc_east_asian_width(int32_t uc) {
  /* How to generate this function:

curl http://www.unicode.org/Public/UCD/latest/ucd/EastAsianWidth.txt > EastAsianWidth.txt
echo -e "A\nF\nH\nN\nNa\nW" | while read PROPERTY; do
  cat EastAsianWidth.txt | \
  egrep -v "^#" | \
  sed -r 's/^([0-9A-F]+)(\.\.([0-9A-F]+))? +; ([^ ]+).*$/\1 \3 \4/' | \
  awk -F' ' "$(echo '
BEGIN { print "if (" }
$1 != "" && $2 == "XXX" && $3 == "" { print "uc == 0x" $1 " || " }
$1 != "" && $2 != "" && $3 == "XXX" { print "(0x" $1 " <= uc && uc <= 0x" $2 ") ||" }
END { print "false) { return XXX; }" }
' | sed "s/XXX/$PROPERTY/g")"
done > foo
    */
  if (uc == 0x00A1 || uc == 0x00A4 || uc == 0x00A7 || uc == 0x00A8 ||
      uc == 0x00AA || uc == 0x00AD || uc == 0x00AE || uc == 0x00B0 ||
      uc == 0x00B1 || (0x00B2 <= uc && uc <= 0x00B3) || uc == 0x00B4 ||
      (0x00B6 <= uc && uc <= 0x00B7) || uc == 0x00B8 || uc == 0x00B9 ||
      uc == 0x00BA || (0x00BC <= uc && uc <= 0x00BE) || uc == 0x00BF ||
      uc == 0x00C6 || uc == 0x00D0 || uc == 0x00D7 || uc == 0x00D8 ||
      (0x00DE <= uc && uc <= 0x00E1) || uc == 0x00E6 ||
      (0x00E8 <= uc && uc <= 0x00EA) || (0x00EC <= uc && uc <= 0x00ED) ||
      uc == 0x00F0 || (0x00F2 <= uc && uc <= 0x00F3) || uc == 0x00F7 ||
      (0x00F8 <= uc && uc <= 0x00FA) || uc == 0x00FC || uc == 0x00FE ||
      uc == 0x0101 || uc == 0x0111 || uc == 0x0113 || uc == 0x011B ||
      (0x0126 <= uc && uc <= 0x0127) || uc == 0x012B ||
      (0x0131 <= uc && uc <= 0x0133) || uc == 0x0138 ||
      (0x013F <= uc && uc <= 0x0142) || uc == 0x0144 ||
      (0x0148 <= uc && uc <= 0x014B) || uc == 0x014D ||
      (0x0152 <= uc && uc <= 0x0153) || (0x0166 <= uc && uc <= 0x0167) ||
      uc == 0x016B || uc == 0x01CE || uc == 0x01D0 || uc == 0x01D2 ||
      uc == 0x01D4 || uc == 0x01D6 || uc == 0x01D8 || uc == 0x01DA ||
      uc == 0x01DC || uc == 0x0251 || uc == 0x0261 || uc == 0x02C4 ||
      uc == 0x02C7 || (0x02C9 <= uc && uc <= 0x02CB) || uc == 0x02CD ||
      uc == 0x02D0 || (0x02D8 <= uc && uc <= 0x02DB) || uc == 0x02DD ||
      uc == 0x02DF || (0x0300 <= uc && uc <= 0x036F) ||
      (0x0391 <= uc && uc <= 0x03A1) || (0x03A3 <= uc && uc <= 0x03A9) ||
      (0x03B1 <= uc && uc <= 0x03C1) || (0x03C3 <= uc && uc <= 0x03C9) ||
      uc == 0x0401 || (0x0410 <= uc && uc <= 0x044F) || uc == 0x0451 ||
      uc == 0x2010 || (0x2013 <= uc && uc <= 0x2015) || uc == 0x2016 ||
      uc == 0x2018 || uc == 0x2019 || uc == 0x201C || uc == 0x201D ||
      (0x2020 <= uc && uc <= 0x2022) || (0x2024 <= uc && uc <= 0x2027) ||
      uc == 0x2030 || (0x2032 <= uc && uc <= 0x2033) || uc == 0x2035 ||
      uc == 0x203B || uc == 0x203E || uc == 0x2074 || uc == 0x207F ||
      (0x2081 <= uc && uc <= 0x2084) || uc == 0x20AC || uc == 0x2103 ||
      uc == 0x2105 || uc == 0x2109 || uc == 0x2113 || uc == 0x2116 ||
      (0x2121 <= uc && uc <= 0x2122) || uc == 0x2126 || uc == 0x212B ||
      (0x2153 <= uc && uc <= 0x2154) || (0x215B <= uc && uc <= 0x215E) ||
      (0x2160 <= uc && uc <= 0x216B) || (0x2170 <= uc && uc <= 0x2179) ||
      uc == 0x2189 || (0x2190 <= uc && uc <= 0x2194) ||
      (0x2195 <= uc && uc <= 0x2199) || (0x21B8 <= uc && uc <= 0x21B9) ||
      uc == 0x21D2 || uc == 0x21D4 || uc == 0x21E7 || uc == 0x2200 ||
      (0x2202 <= uc && uc <= 0x2203) || (0x2207 <= uc && uc <= 0x2208) ||
      uc == 0x220B || uc == 0x220F || uc == 0x2211 || uc == 0x2215 ||
      uc == 0x221A || (0x221D <= uc && uc <= 0x2220) || uc == 0x2223 ||
      uc == 0x2225 || (0x2227 <= uc && uc <= 0x222C) || uc == 0x222E ||
      (0x2234 <= uc && uc <= 0x2237) || (0x223C <= uc && uc <= 0x223D) ||
      uc == 0x2248 || uc == 0x224C || uc == 0x2252 ||
      (0x2260 <= uc && uc <= 0x2261) || (0x2264 <= uc && uc <= 0x2267) ||
      (0x226A <= uc && uc <= 0x226B) || (0x226E <= uc && uc <= 0x226F) ||
      (0x2282 <= uc && uc <= 0x2283) || (0x2286 <= uc && uc <= 0x2287) ||
      uc == 0x2295 || uc == 0x2299 || uc == 0x22A5 || uc == 0x22BF ||
      uc == 0x2312 || (0x2460 <= uc && uc <= 0x249B) ||
      (0x249C <= uc && uc <= 0x24E9) || (0x24EB <= uc && uc <= 0x24FF) ||
      (0x2500 <= uc && uc <= 0x254B) || (0x2550 <= uc && uc <= 0x2573) ||
      (0x2580 <= uc && uc <= 0x258F) || (0x2592 <= uc && uc <= 0x2595) ||
      (0x25A0 <= uc && uc <= 0x25A1) || (0x25A3 <= uc && uc <= 0x25A9) ||
      (0x25B2 <= uc && uc <= 0x25B3) || uc == 0x25B6 || uc == 0x25B7 ||
      (0x25BC <= uc && uc <= 0x25BD) || uc == 0x25C0 || uc == 0x25C1 ||
      (0x25C6 <= uc && uc <= 0x25C8) || uc == 0x25CB ||
      (0x25CE <= uc && uc <= 0x25D1) || (0x25E2 <= uc && uc <= 0x25E5) ||
      uc == 0x25EF || (0x2605 <= uc && uc <= 0x2606) || uc == 0x2609 ||
      (0x260E <= uc && uc <= 0x260F) || uc == 0x261C || uc == 0x261E ||
      uc == 0x2640 || uc == 0x2642 || (0x2660 <= uc && uc <= 0x2661) ||
      (0x2663 <= uc && uc <= 0x2665) || (0x2667 <= uc && uc <= 0x266A) ||
      (0x266C <= uc && uc <= 0x266D) || uc == 0x266F ||
      (0x269E <= uc && uc <= 0x269F) || uc == 0x26BF ||
      (0x26C6 <= uc && uc <= 0x26CD) || (0x26CF <= uc && uc <= 0x26D3) ||
      (0x26D5 <= uc && uc <= 0x26E1) || uc == 0x26E3 ||
      (0x26E8 <= uc && uc <= 0x26E9) || (0x26EB <= uc && uc <= 0x26F1) ||
      uc == 0x26F4 || (0x26F6 <= uc && uc <= 0x26F9) ||
      (0x26FB <= uc && uc <= 0x26FC) || (0x26FE <= uc && uc <= 0x26FF) ||
      uc == 0x273D || (0x2776 <= uc && uc <= 0x277F) ||
      (0x2B56 <= uc && uc <= 0x2B59) || (0x3248 <= uc && uc <= 0x324F) ||
      (0xE000 <= uc && uc <= 0xF8FF) || (0xFE00 <= uc && uc <= 0xFE0F) ||
      uc == 0xFFFD || (0x1F100 <= uc && uc <= 0x1F10A) ||
      (0x1F110 <= uc && uc <= 0x1F12D) || (0x1F130 <= uc && uc <= 0x1F169) ||
      (0x1F170 <= uc && uc <= 0x1F18D) || (0x1F18F <= uc && uc <= 0x1F190) ||
      (0x1F19B <= uc && uc <= 0x1F1AC) || (0xE0100 <= uc && uc <= 0xE01EF) ||
      (0xF0000 <= uc && uc <= 0xFFFFD) || (0x100000 <= uc && uc <= 0x10FFFD) ||
      false) {
    return A;
  }
  if (uc == 0x3000 || (0xFF01 <= uc && uc <= 0xFF03) || uc == 0xFF04 ||
      (0xFF05 <= uc && uc <= 0xFF07) || uc == 0xFF08 || uc == 0xFF09 ||
      uc == 0xFF0A || uc == 0xFF0B || uc == 0xFF0C || uc == 0xFF0D ||
      (0xFF0E <= uc && uc <= 0xFF0F) || (0xFF10 <= uc && uc <= 0xFF19) ||
      (0xFF1A <= uc && uc <= 0xFF1B) || (0xFF1C <= uc && uc <= 0xFF1E) ||
      (0xFF1F <= uc && uc <= 0xFF20) || (0xFF21 <= uc && uc <= 0xFF3A) ||
      uc == 0xFF3B || uc == 0xFF3C || uc == 0xFF3D || uc == 0xFF3E ||
      uc == 0xFF3F || uc == 0xFF40 || (0xFF41 <= uc && uc <= 0xFF5A) ||
      uc == 0xFF5B || uc == 0xFF5C || uc == 0xFF5D || uc == 0xFF5E ||
      uc == 0xFF5F || uc == 0xFF60 || (0xFFE0 <= uc && uc <= 0xFFE1) ||
      uc == 0xFFE2 || uc == 0xFFE3 || uc == 0xFFE4 ||
      (0xFFE5 <= uc && uc <= 0xFFE6) || false) {
    return F;
  }
  if (uc == 0x20A9 || uc == 0xFF61 || uc == 0xFF62 || uc == 0xFF63 ||
      (0xFF64 <= uc && uc <= 0xFF65) || (0xFF66 <= uc && uc <= 0xFF6F) ||
      uc == 0xFF70 || (0xFF71 <= uc && uc <= 0xFF9D) ||
      (0xFF9E <= uc && uc <= 0xFF9F) || (0xFFA0 <= uc && uc <= 0xFFBE) ||
      (0xFFC2 <= uc && uc <= 0xFFC7) || (0xFFCA <= uc && uc <= 0xFFCF) ||
      (0xFFD2 <= uc && uc <= 0xFFD7) || (0xFFDA <= uc && uc <= 0xFFDC) ||
      uc == 0xFFE8 || (0xFFE9 <= uc && uc <= 0xFFEC) ||
      (0xFFED <= uc && uc <= 0xFFEE) || false) {
    return H;
  }
  if ((0x0000 <= uc && uc <= 0x001F) || uc == 0x007F ||
      (0x0080 <= uc && uc <= 0x009F) || uc == 0x00A0 || uc == 0x00A9 ||
      uc == 0x00AB || uc == 0x00B5 || uc == 0x00BB ||
      (0x00C0 <= uc && uc <= 0x00C5) || (0x00C7 <= uc && uc <= 0x00CF) ||
      (0x00D1 <= uc && uc <= 0x00D6) || (0x00D9 <= uc && uc <= 0x00DD) ||
      (0x00E2 <= uc && uc <= 0x00E5) || uc == 0x00E7 || uc == 0x00EB ||
      (0x00EE <= uc && uc <= 0x00EF) || uc == 0x00F1 ||
      (0x00F4 <= uc && uc <= 0x00F6) || uc == 0x00FB || uc == 0x00FD ||
      uc == 0x00FF || uc == 0x0100 || (0x0102 <= uc && uc <= 0x0110) ||
      uc == 0x0112 || (0x0114 <= uc && uc <= 0x011A) ||
      (0x011C <= uc && uc <= 0x0125) || (0x0128 <= uc && uc <= 0x012A) ||
      (0x012C <= uc && uc <= 0x0130) || (0x0134 <= uc && uc <= 0x0137) ||
      (0x0139 <= uc && uc <= 0x013E) || uc == 0x0143 ||
      (0x0145 <= uc && uc <= 0x0147) || uc == 0x014C ||
      (0x014E <= uc && uc <= 0x0151) || (0x0154 <= uc && uc <= 0x0165) ||
      (0x0168 <= uc && uc <= 0x016A) || (0x016C <= uc && uc <= 0x017F) ||
      (0x0180 <= uc && uc <= 0x01BA) || uc == 0x01BB ||
      (0x01BC <= uc && uc <= 0x01BF) || (0x01C0 <= uc && uc <= 0x01C3) ||
      (0x01C4 <= uc && uc <= 0x01CD) || uc == 0x01CF || uc == 0x01D1 ||
      uc == 0x01D3 || uc == 0x01D5 || uc == 0x01D7 || uc == 0x01D9 ||
      uc == 0x01DB || (0x01DD <= uc && uc <= 0x024F) || uc == 0x0250 ||
      (0x0252 <= uc && uc <= 0x0260) || (0x0262 <= uc && uc <= 0x0293) ||
      uc == 0x0294 || (0x0295 <= uc && uc <= 0x02AF) ||
      (0x02B0 <= uc && uc <= 0x02C1) || (0x02C2 <= uc && uc <= 0x02C3) ||
      uc == 0x02C5 || uc == 0x02C6 || uc == 0x02C8 || uc == 0x02CC ||
      (0x02CE <= uc && uc <= 0x02CF) || uc == 0x02D1 ||
      (0x02D2 <= uc && uc <= 0x02D7) || uc == 0x02DC || uc == 0x02DE ||
      (0x02E0 <= uc && uc <= 0x02E4) || (0x02E5 <= uc && uc <= 0x02EB) ||
      uc == 0x02EC || uc == 0x02ED || uc == 0x02EE ||
      (0x02EF <= uc && uc <= 0x02FF) || (0x0370 <= uc && uc <= 0x0373) ||
      uc == 0x0374 || uc == 0x0375 || (0x0376 <= uc && uc <= 0x0377) ||
      uc == 0x037A || (0x037B <= uc && uc <= 0x037D) || uc == 0x037E ||
      uc == 0x037F || (0x0384 <= uc && uc <= 0x0385) || uc == 0x0386 ||
      uc == 0x0387 || (0x0388 <= uc && uc <= 0x038A) || uc == 0x038C ||
      (0x038E <= uc && uc <= 0x0390) || (0x03AA <= uc && uc <= 0x03B0) ||
      uc == 0x03C2 || (0x03CA <= uc && uc <= 0x03F5) || uc == 0x03F6 ||
      (0x03F7 <= uc && uc <= 0x03FF) || uc == 0x0400 ||
      (0x0402 <= uc && uc <= 0x040F) || uc == 0x0450 ||
      (0x0452 <= uc && uc <= 0x0481) || uc == 0x0482 ||
      (0x0483 <= uc && uc <= 0x0487) || (0x0488 <= uc && uc <= 0x0489) ||
      (0x048A <= uc && uc <= 0x04FF) || (0x0500 <= uc && uc <= 0x052F) ||
      (0x0531 <= uc && uc <= 0x0556) || uc == 0x0559 ||
      (0x055A <= uc && uc <= 0x055F) || (0x0560 <= uc && uc <= 0x0588) ||
      uc == 0x0589 || uc == 0x058A || (0x058D <= uc && uc <= 0x058E) ||
      uc == 0x058F || (0x0591 <= uc && uc <= 0x05BD) || uc == 0x05BE ||
      uc == 0x05BF || uc == 0x05C0 || (0x05C1 <= uc && uc <= 0x05C2) ||
      uc == 0x05C3 || (0x05C4 <= uc && uc <= 0x05C5) || uc == 0x05C6 ||
      uc == 0x05C7 || (0x05D0 <= uc && uc <= 0x05EA) ||
      (0x05EF <= uc && uc <= 0x05F2) || (0x05F3 <= uc && uc <= 0x05F4) ||
      (0x0600 <= uc && uc <= 0x0605) || (0x0606 <= uc && uc <= 0x0608) ||
      (0x0609 <= uc && uc <= 0x060A) || uc == 0x060B ||
      (0x060C <= uc && uc <= 0x060D) || (0x060E <= uc && uc <= 0x060F) ||
      (0x0610 <= uc && uc <= 0x061A) || uc == 0x061B || uc == 0x061C ||
      (0x061D <= uc && uc <= 0x061F) || (0x0620 <= uc && uc <= 0x063F) ||
      uc == 0x0640 || (0x0641 <= uc && uc <= 0x064A) ||
      (0x064B <= uc && uc <= 0x065F) || (0x0660 <= uc && uc <= 0x0669) ||
      (0x066A <= uc && uc <= 0x066D) || (0x066E <= uc && uc <= 0x066F) ||
      uc == 0x0670 || (0x0671 <= uc && uc <= 0x06D3) || uc == 0x06D4 ||
      uc == 0x06D5 || (0x06D6 <= uc && uc <= 0x06DC) || uc == 0x06DD ||
      uc == 0x06DE || (0x06DF <= uc && uc <= 0x06E4) ||
      (0x06E5 <= uc && uc <= 0x06E6) || (0x06E7 <= uc && uc <= 0x06E8) ||
      uc == 0x06E9 || (0x06EA <= uc && uc <= 0x06ED) ||
      (0x06EE <= uc && uc <= 0x06EF) || (0x06F0 <= uc && uc <= 0x06F9) ||
      (0x06FA <= uc && uc <= 0x06FC) || (0x06FD <= uc && uc <= 0x06FE) ||
      uc == 0x06FF || (0x0700 <= uc && uc <= 0x070D) || uc == 0x070F ||
      uc == 0x0710 || uc == 0x0711 || (0x0712 <= uc && uc <= 0x072F) ||
      (0x0730 <= uc && uc <= 0x074A) || (0x074D <= uc && uc <= 0x074F) ||
      (0x0750 <= uc && uc <= 0x077F) || (0x0780 <= uc && uc <= 0x07A5) ||
      (0x07A6 <= uc && uc <= 0x07B0) || uc == 0x07B1 ||
      (0x07C0 <= uc && uc <= 0x07C9) || (0x07CA <= uc && uc <= 0x07EA) ||
      (0x07EB <= uc && uc <= 0x07F3) || (0x07F4 <= uc && uc <= 0x07F5) ||
      uc == 0x07F6 || (0x07F7 <= uc && uc <= 0x07F9) || uc == 0x07FA ||
      uc == 0x07FD || (0x07FE <= uc && uc <= 0x07FF) ||
      (0x0800 <= uc && uc <= 0x0815) || (0x0816 <= uc && uc <= 0x0819) ||
      uc == 0x081A || (0x081B <= uc && uc <= 0x0823) || uc == 0x0824 ||
      (0x0825 <= uc && uc <= 0x0827) || uc == 0x0828 ||
      (0x0829 <= uc && uc <= 0x082D) || (0x0830 <= uc && uc <= 0x083E) ||
      (0x0840 <= uc && uc <= 0x0858) || (0x0859 <= uc && uc <= 0x085B) ||
      uc == 0x085E || (0x0860 <= uc && uc <= 0x086A) ||
      (0x0870 <= uc && uc <= 0x0887) || uc == 0x0888 ||
      (0x0889 <= uc && uc <= 0x088E) || (0x0890 <= uc && uc <= 0x0891) ||
      (0x0898 <= uc && uc <= 0x089F) || (0x08A0 <= uc && uc <= 0x08C8) ||
      uc == 0x08C9 || (0x08CA <= uc && uc <= 0x08E1) || uc == 0x08E2 ||
      (0x08E3 <= uc && uc <= 0x08FF) || (0x0900 <= uc && uc <= 0x0902) ||
      uc == 0x0903 || (0x0904 <= uc && uc <= 0x0939) || uc == 0x093A ||
      uc == 0x093B || uc == 0x093C || uc == 0x093D ||
      (0x093E <= uc && uc <= 0x0940) || (0x0941 <= uc && uc <= 0x0948) ||
      (0x0949 <= uc && uc <= 0x094C) || uc == 0x094D ||
      (0x094E <= uc && uc <= 0x094F) || uc == 0x0950 ||
      (0x0951 <= uc && uc <= 0x0957) || (0x0958 <= uc && uc <= 0x0961) ||
      (0x0962 <= uc && uc <= 0x0963) || (0x0964 <= uc && uc <= 0x0965) ||
      (0x0966 <= uc && uc <= 0x096F) || uc == 0x0970 || uc == 0x0971 ||
      (0x0972 <= uc && uc <= 0x097F) || uc == 0x0980 || uc == 0x0981 ||
      (0x0982 <= uc && uc <= 0x0983) || (0x0985 <= uc && uc <= 0x098C) ||
      (0x098F <= uc && uc <= 0x0990) || (0x0993 <= uc && uc <= 0x09A8) ||
      (0x09AA <= uc && uc <= 0x09B0) || uc == 0x09B2 ||
      (0x09B6 <= uc && uc <= 0x09B9) || uc == 0x09BC || uc == 0x09BD ||
      (0x09BE <= uc && uc <= 0x09C0) || (0x09C1 <= uc && uc <= 0x09C4) ||
      (0x09C7 <= uc && uc <= 0x09C8) || (0x09CB <= uc && uc <= 0x09CC) ||
      uc == 0x09CD || uc == 0x09CE || uc == 0x09D7 ||
      (0x09DC <= uc && uc <= 0x09DD) || (0x09DF <= uc && uc <= 0x09E1) ||
      (0x09E2 <= uc && uc <= 0x09E3) || (0x09E6 <= uc && uc <= 0x09EF) ||
      (0x09F0 <= uc && uc <= 0x09F1) || (0x09F2 <= uc && uc <= 0x09F3) ||
      (0x09F4 <= uc && uc <= 0x09F9) || uc == 0x09FA || uc == 0x09FB ||
      uc == 0x09FC || uc == 0x09FD || uc == 0x09FE ||
      (0x0A01 <= uc && uc <= 0x0A02) || uc == 0x0A03 ||
      (0x0A05 <= uc && uc <= 0x0A0A) || (0x0A0F <= uc && uc <= 0x0A10) ||
      (0x0A13 <= uc && uc <= 0x0A28) || (0x0A2A <= uc && uc <= 0x0A30) ||
      (0x0A32 <= uc && uc <= 0x0A33) || (0x0A35 <= uc && uc <= 0x0A36) ||
      (0x0A38 <= uc && uc <= 0x0A39) || uc == 0x0A3C ||
      (0x0A3E <= uc && uc <= 0x0A40) || (0x0A41 <= uc && uc <= 0x0A42) ||
      (0x0A47 <= uc && uc <= 0x0A48) || (0x0A4B <= uc && uc <= 0x0A4D) ||
      uc == 0x0A51 || (0x0A59 <= uc && uc <= 0x0A5C) || uc == 0x0A5E ||
      (0x0A66 <= uc && uc <= 0x0A6F) || (0x0A70 <= uc && uc <= 0x0A71) ||
      (0x0A72 <= uc && uc <= 0x0A74) || uc == 0x0A75 || uc == 0x0A76 ||
      (0x0A81 <= uc && uc <= 0x0A82) || uc == 0x0A83 ||
      (0x0A85 <= uc && uc <= 0x0A8D) || (0x0A8F <= uc && uc <= 0x0A91) ||
      (0x0A93 <= uc && uc <= 0x0AA8) || (0x0AAA <= uc && uc <= 0x0AB0) ||
      (0x0AB2 <= uc && uc <= 0x0AB3) || (0x0AB5 <= uc && uc <= 0x0AB9) ||
      uc == 0x0ABC || uc == 0x0ABD || (0x0ABE <= uc && uc <= 0x0AC0) ||
      (0x0AC1 <= uc && uc <= 0x0AC5) || (0x0AC7 <= uc && uc <= 0x0AC8) ||
      uc == 0x0AC9 || (0x0ACB <= uc && uc <= 0x0ACC) || uc == 0x0ACD ||
      uc == 0x0AD0 || (0x0AE0 <= uc && uc <= 0x0AE1) ||
      (0x0AE2 <= uc && uc <= 0x0AE3) || (0x0AE6 <= uc && uc <= 0x0AEF) ||
      uc == 0x0AF0 || uc == 0x0AF1 || uc == 0x0AF9 ||
      (0x0AFA <= uc && uc <= 0x0AFF) || uc == 0x0B01 ||
      (0x0B02 <= uc && uc <= 0x0B03) || (0x0B05 <= uc && uc <= 0x0B0C) ||
      (0x0B0F <= uc && uc <= 0x0B10) || (0x0B13 <= uc && uc <= 0x0B28) ||
      (0x0B2A <= uc && uc <= 0x0B30) || (0x0B32 <= uc && uc <= 0x0B33) ||
      (0x0B35 <= uc && uc <= 0x0B39) || uc == 0x0B3C || uc == 0x0B3D ||
      uc == 0x0B3E || uc == 0x0B3F || uc == 0x0B40 ||
      (0x0B41 <= uc && uc <= 0x0B44) || (0x0B47 <= uc && uc <= 0x0B48) ||
      (0x0B4B <= uc && uc <= 0x0B4C) || uc == 0x0B4D ||
      (0x0B55 <= uc && uc <= 0x0B56) || uc == 0x0B57 ||
      (0x0B5C <= uc && uc <= 0x0B5D) || (0x0B5F <= uc && uc <= 0x0B61) ||
      (0x0B62 <= uc && uc <= 0x0B63) || (0x0B66 <= uc && uc <= 0x0B6F) ||
      uc == 0x0B70 || uc == 0x0B71 || (0x0B72 <= uc && uc <= 0x0B77) ||
      uc == 0x0B82 || uc == 0x0B83 || (0x0B85 <= uc && uc <= 0x0B8A) ||
      (0x0B8E <= uc && uc <= 0x0B90) || (0x0B92 <= uc && uc <= 0x0B95) ||
      (0x0B99 <= uc && uc <= 0x0B9A) || uc == 0x0B9C ||
      (0x0B9E <= uc && uc <= 0x0B9F) || (0x0BA3 <= uc && uc <= 0x0BA4) ||
      (0x0BA8 <= uc && uc <= 0x0BAA) || (0x0BAE <= uc && uc <= 0x0BB9) ||
      (0x0BBE <= uc && uc <= 0x0BBF) || uc == 0x0BC0 ||
      (0x0BC1 <= uc && uc <= 0x0BC2) || (0x0BC6 <= uc && uc <= 0x0BC8) ||
      (0x0BCA <= uc && uc <= 0x0BCC) || uc == 0x0BCD || uc == 0x0BD0 ||
      uc == 0x0BD7 || (0x0BE6 <= uc && uc <= 0x0BEF) ||
      (0x0BF0 <= uc && uc <= 0x0BF2) || (0x0BF3 <= uc && uc <= 0x0BF8) ||
      uc == 0x0BF9 || uc == 0x0BFA || uc == 0x0C00 ||
      (0x0C01 <= uc && uc <= 0x0C03) || uc == 0x0C04 ||
      (0x0C05 <= uc && uc <= 0x0C0C) || (0x0C0E <= uc && uc <= 0x0C10) ||
      (0x0C12 <= uc && uc <= 0x0C28) || (0x0C2A <= uc && uc <= 0x0C39) ||
      uc == 0x0C3C || uc == 0x0C3D || (0x0C3E <= uc && uc <= 0x0C40) ||
      (0x0C41 <= uc && uc <= 0x0C44) || (0x0C46 <= uc && uc <= 0x0C48) ||
      (0x0C4A <= uc && uc <= 0x0C4D) || (0x0C55 <= uc && uc <= 0x0C56) ||
      (0x0C58 <= uc && uc <= 0x0C5A) || uc == 0x0C5D ||
      (0x0C60 <= uc && uc <= 0x0C61) || (0x0C62 <= uc && uc <= 0x0C63) ||
      (0x0C66 <= uc && uc <= 0x0C6F) || uc == 0x0C77 ||
      (0x0C78 <= uc && uc <= 0x0C7E) || uc == 0x0C7F || uc == 0x0C80 ||
      uc == 0x0C81 || (0x0C82 <= uc && uc <= 0x0C83) || uc == 0x0C84 ||
      (0x0C85 <= uc && uc <= 0x0C8C) || (0x0C8E <= uc && uc <= 0x0C90) ||
      (0x0C92 <= uc && uc <= 0x0CA8) || (0x0CAA <= uc && uc <= 0x0CB3) ||
      (0x0CB5 <= uc && uc <= 0x0CB9) || uc == 0x0CBC || uc == 0x0CBD ||
      uc == 0x0CBE || uc == 0x0CBF || (0x0CC0 <= uc && uc <= 0x0CC4) ||
      uc == 0x0CC6 || (0x0CC7 <= uc && uc <= 0x0CC8) ||
      (0x0CCA <= uc && uc <= 0x0CCB) || (0x0CCC <= uc && uc <= 0x0CCD) ||
      (0x0CD5 <= uc && uc <= 0x0CD6) || (0x0CDD <= uc && uc <= 0x0CDE) ||
      (0x0CE0 <= uc && uc <= 0x0CE1) || (0x0CE2 <= uc && uc <= 0x0CE3) ||
      (0x0CE6 <= uc && uc <= 0x0CEF) || (0x0CF1 <= uc && uc <= 0x0CF2) ||
      uc == 0x0CF3 || (0x0D00 <= uc && uc <= 0x0D01) ||
      (0x0D02 <= uc && uc <= 0x0D03) || (0x0D04 <= uc && uc <= 0x0D0C) ||
      (0x0D0E <= uc && uc <= 0x0D10) || (0x0D12 <= uc && uc <= 0x0D3A) ||
      (0x0D3B <= uc && uc <= 0x0D3C) || uc == 0x0D3D ||
      (0x0D3E <= uc && uc <= 0x0D40) || (0x0D41 <= uc && uc <= 0x0D44) ||
      (0x0D46 <= uc && uc <= 0x0D48) || (0x0D4A <= uc && uc <= 0x0D4C) ||
      uc == 0x0D4D || uc == 0x0D4E || uc == 0x0D4F ||
      (0x0D54 <= uc && uc <= 0x0D56) || uc == 0x0D57 ||
      (0x0D58 <= uc && uc <= 0x0D5E) || (0x0D5F <= uc && uc <= 0x0D61) ||
      (0x0D62 <= uc && uc <= 0x0D63) || (0x0D66 <= uc && uc <= 0x0D6F) ||
      (0x0D70 <= uc && uc <= 0x0D78) || uc == 0x0D79 ||
      (0x0D7A <= uc && uc <= 0x0D7F) || uc == 0x0D81 ||
      (0x0D82 <= uc && uc <= 0x0D83) || (0x0D85 <= uc && uc <= 0x0D96) ||
      (0x0D9A <= uc && uc <= 0x0DB1) || (0x0DB3 <= uc && uc <= 0x0DBB) ||
      uc == 0x0DBD || (0x0DC0 <= uc && uc <= 0x0DC6) || uc == 0x0DCA ||
      (0x0DCF <= uc && uc <= 0x0DD1) || (0x0DD2 <= uc && uc <= 0x0DD4) ||
      uc == 0x0DD6 || (0x0DD8 <= uc && uc <= 0x0DDF) ||
      (0x0DE6 <= uc && uc <= 0x0DEF) || (0x0DF2 <= uc && uc <= 0x0DF3) ||
      uc == 0x0DF4 || (0x0E01 <= uc && uc <= 0x0E30) || uc == 0x0E31 ||
      (0x0E32 <= uc && uc <= 0x0E33) || (0x0E34 <= uc && uc <= 0x0E3A) ||
      uc == 0x0E3F || (0x0E40 <= uc && uc <= 0x0E45) || uc == 0x0E46 ||
      (0x0E47 <= uc && uc <= 0x0E4E) || uc == 0x0E4F ||
      (0x0E50 <= uc && uc <= 0x0E59) || (0x0E5A <= uc && uc <= 0x0E5B) ||
      (0x0E81 <= uc && uc <= 0x0E82) || uc == 0x0E84 ||
      (0x0E86 <= uc && uc <= 0x0E8A) || (0x0E8C <= uc && uc <= 0x0EA3) ||
      uc == 0x0EA5 || (0x0EA7 <= uc && uc <= 0x0EB0) || uc == 0x0EB1 ||
      (0x0EB2 <= uc && uc <= 0x0EB3) || (0x0EB4 <= uc && uc <= 0x0EBC) ||
      uc == 0x0EBD || (0x0EC0 <= uc && uc <= 0x0EC4) || uc == 0x0EC6 ||
      (0x0EC8 <= uc && uc <= 0x0ECE) || (0x0ED0 <= uc && uc <= 0x0ED9) ||
      (0x0EDC <= uc && uc <= 0x0EDF) || uc == 0x0F00 ||
      (0x0F01 <= uc && uc <= 0x0F03) || (0x0F04 <= uc && uc <= 0x0F12) ||
      uc == 0x0F13 || uc == 0x0F14 || (0x0F15 <= uc && uc <= 0x0F17) ||
      (0x0F18 <= uc && uc <= 0x0F19) || (0x0F1A <= uc && uc <= 0x0F1F) ||
      (0x0F20 <= uc && uc <= 0x0F29) || (0x0F2A <= uc && uc <= 0x0F33) ||
      uc == 0x0F34 || uc == 0x0F35 || uc == 0x0F36 || uc == 0x0F37 ||
      uc == 0x0F38 || uc == 0x0F39 || uc == 0x0F3A || uc == 0x0F3B ||
      uc == 0x0F3C || uc == 0x0F3D || (0x0F3E <= uc && uc <= 0x0F3F) ||
      (0x0F40 <= uc && uc <= 0x0F47) || (0x0F49 <= uc && uc <= 0x0F6C) ||
      (0x0F71 <= uc && uc <= 0x0F7E) || uc == 0x0F7F ||
      (0x0F80 <= uc && uc <= 0x0F84) || uc == 0x0F85 ||
      (0x0F86 <= uc && uc <= 0x0F87) || (0x0F88 <= uc && uc <= 0x0F8C) ||
      (0x0F8D <= uc && uc <= 0x0F97) || (0x0F99 <= uc && uc <= 0x0FBC) ||
      (0x0FBE <= uc && uc <= 0x0FC5) || uc == 0x0FC6 ||
      (0x0FC7 <= uc && uc <= 0x0FCC) || (0x0FCE <= uc && uc <= 0x0FCF) ||
      (0x0FD0 <= uc && uc <= 0x0FD4) || (0x0FD5 <= uc && uc <= 0x0FD8) ||
      (0x0FD9 <= uc && uc <= 0x0FDA) || (0x1000 <= uc && uc <= 0x102A) ||
      (0x102B <= uc && uc <= 0x102C) || (0x102D <= uc && uc <= 0x1030) ||
      uc == 0x1031 || (0x1032 <= uc && uc <= 0x1037) || uc == 0x1038 ||
      (0x1039 <= uc && uc <= 0x103A) || (0x103B <= uc && uc <= 0x103C) ||
      (0x103D <= uc && uc <= 0x103E) || uc == 0x103F ||
      (0x1040 <= uc && uc <= 0x1049) || (0x104A <= uc && uc <= 0x104F) ||
      (0x1050 <= uc && uc <= 0x1055) || (0x1056 <= uc && uc <= 0x1057) ||
      (0x1058 <= uc && uc <= 0x1059) || (0x105A <= uc && uc <= 0x105D) ||
      (0x105E <= uc && uc <= 0x1060) || uc == 0x1061 ||
      (0x1062 <= uc && uc <= 0x1064) || (0x1065 <= uc && uc <= 0x1066) ||
      (0x1067 <= uc && uc <= 0x106D) || (0x106E <= uc && uc <= 0x1070) ||
      (0x1071 <= uc && uc <= 0x1074) || (0x1075 <= uc && uc <= 0x1081) ||
      uc == 0x1082 || (0x1083 <= uc && uc <= 0x1084) ||
      (0x1085 <= uc && uc <= 0x1086) || (0x1087 <= uc && uc <= 0x108C) ||
      uc == 0x108D || uc == 0x108E || uc == 0x108F ||
      (0x1090 <= uc && uc <= 0x1099) || (0x109A <= uc && uc <= 0x109C) ||
      uc == 0x109D || (0x109E <= uc && uc <= 0x109F) ||
      (0x10A0 <= uc && uc <= 0x10C5) || uc == 0x10C7 || uc == 0x10CD ||
      (0x10D0 <= uc && uc <= 0x10FA) || uc == 0x10FB || uc == 0x10FC ||
      (0x10FD <= uc && uc <= 0x10FF) || (0x1160 <= uc && uc <= 0x11FF) ||
      (0x1200 <= uc && uc <= 0x1248) || (0x124A <= uc && uc <= 0x124D) ||
      (0x1250 <= uc && uc <= 0x1256) || uc == 0x1258 ||
      (0x125A <= uc && uc <= 0x125D) || (0x1260 <= uc && uc <= 0x1288) ||
      (0x128A <= uc && uc <= 0x128D) || (0x1290 <= uc && uc <= 0x12B0) ||
      (0x12B2 <= uc && uc <= 0x12B5) || (0x12B8 <= uc && uc <= 0x12BE) ||
      uc == 0x12C0 || (0x12C2 <= uc && uc <= 0x12C5) ||
      (0x12C8 <= uc && uc <= 0x12D6) || (0x12D8 <= uc && uc <= 0x1310) ||
      (0x1312 <= uc && uc <= 0x1315) || (0x1318 <= uc && uc <= 0x135A) ||
      (0x135D <= uc && uc <= 0x135F) || (0x1360 <= uc && uc <= 0x1368) ||
      (0x1369 <= uc && uc <= 0x137C) || (0x1380 <= uc && uc <= 0x138F) ||
      (0x1390 <= uc && uc <= 0x1399) || (0x13A0 <= uc && uc <= 0x13F5) ||
      (0x13F8 <= uc && uc <= 0x13FD) || uc == 0x1400 ||
      (0x1401 <= uc && uc <= 0x166C) || uc == 0x166D || uc == 0x166E ||
      (0x166F <= uc && uc <= 0x167F) || uc == 0x1680 ||
      (0x1681 <= uc && uc <= 0x169A) || uc == 0x169B || uc == 0x169C ||
      (0x16A0 <= uc && uc <= 0x16EA) || (0x16EB <= uc && uc <= 0x16ED) ||
      (0x16EE <= uc && uc <= 0x16F0) || (0x16F1 <= uc && uc <= 0x16F8) ||
      (0x1700 <= uc && uc <= 0x1711) || (0x1712 <= uc && uc <= 0x1714) ||
      uc == 0x1715 || uc == 0x171F || (0x1720 <= uc && uc <= 0x1731) ||
      (0x1732 <= uc && uc <= 0x1733) || uc == 0x1734 ||
      (0x1735 <= uc && uc <= 0x1736) || (0x1740 <= uc && uc <= 0x1751) ||
      (0x1752 <= uc && uc <= 0x1753) || (0x1760 <= uc && uc <= 0x176C) ||
      (0x176E <= uc && uc <= 0x1770) || (0x1772 <= uc && uc <= 0x1773) ||
      (0x1780 <= uc && uc <= 0x17B3) || (0x17B4 <= uc && uc <= 0x17B5) ||
      uc == 0x17B6 || (0x17B7 <= uc && uc <= 0x17BD) ||
      (0x17BE <= uc && uc <= 0x17C5) || uc == 0x17C6 ||
      (0x17C7 <= uc && uc <= 0x17C8) || (0x17C9 <= uc && uc <= 0x17D3) ||
      (0x17D4 <= uc && uc <= 0x17D6) || uc == 0x17D7 ||
      (0x17D8 <= uc && uc <= 0x17DA) || uc == 0x17DB || uc == 0x17DC ||
      uc == 0x17DD || (0x17E0 <= uc && uc <= 0x17E9) ||
      (0x17F0 <= uc && uc <= 0x17F9) || (0x1800 <= uc && uc <= 0x1805) ||
      uc == 0x1806 || (0x1807 <= uc && uc <= 0x180A) ||
      (0x180B <= uc && uc <= 0x180D) || uc == 0x180E || uc == 0x180F ||
      (0x1810 <= uc && uc <= 0x1819) || (0x1820 <= uc && uc <= 0x1842) ||
      uc == 0x1843 || (0x1844 <= uc && uc <= 0x1878) ||
      (0x1880 <= uc && uc <= 0x1884) || (0x1885 <= uc && uc <= 0x1886) ||
      (0x1887 <= uc && uc <= 0x18A8) || uc == 0x18A9 || uc == 0x18AA ||
      (0x18B0 <= uc && uc <= 0x18F5) || (0x1900 <= uc && uc <= 0x191E) ||
      (0x1920 <= uc && uc <= 0x1922) || (0x1923 <= uc && uc <= 0x1926) ||
      (0x1927 <= uc && uc <= 0x1928) || (0x1929 <= uc && uc <= 0x192B) ||
      (0x1930 <= uc && uc <= 0x1931) || uc == 0x1932 ||
      (0x1933 <= uc && uc <= 0x1938) || (0x1939 <= uc && uc <= 0x193B) ||
      uc == 0x1940 || (0x1944 <= uc && uc <= 0x1945) ||
      (0x1946 <= uc && uc <= 0x194F) || (0x1950 <= uc && uc <= 0x196D) ||
      (0x1970 <= uc && uc <= 0x1974) || (0x1980 <= uc && uc <= 0x19AB) ||
      (0x19B0 <= uc && uc <= 0x19C9) || (0x19D0 <= uc && uc <= 0x19D9) ||
      uc == 0x19DA || (0x19DE <= uc && uc <= 0x19DF) ||
      (0x19E0 <= uc && uc <= 0x19FF) || (0x1A00 <= uc && uc <= 0x1A16) ||
      (0x1A17 <= uc && uc <= 0x1A18) || (0x1A19 <= uc && uc <= 0x1A1A) ||
      uc == 0x1A1B || (0x1A1E <= uc && uc <= 0x1A1F) ||
      (0x1A20 <= uc && uc <= 0x1A54) || uc == 0x1A55 || uc == 0x1A56 ||
      uc == 0x1A57 || (0x1A58 <= uc && uc <= 0x1A5E) || uc == 0x1A60 ||
      uc == 0x1A61 || uc == 0x1A62 || (0x1A63 <= uc && uc <= 0x1A64) ||
      (0x1A65 <= uc && uc <= 0x1A6C) || (0x1A6D <= uc && uc <= 0x1A72) ||
      (0x1A73 <= uc && uc <= 0x1A7C) || uc == 0x1A7F ||
      (0x1A80 <= uc && uc <= 0x1A89) || (0x1A90 <= uc && uc <= 0x1A99) ||
      (0x1AA0 <= uc && uc <= 0x1AA6) || uc == 0x1AA7 ||
      (0x1AA8 <= uc && uc <= 0x1AAD) || (0x1AB0 <= uc && uc <= 0x1ABD) ||
      uc == 0x1ABE || (0x1ABF <= uc && uc <= 0x1ACE) ||
      (0x1B00 <= uc && uc <= 0x1B03) || uc == 0x1B04 ||
      (0x1B05 <= uc && uc <= 0x1B33) || uc == 0x1B34 || uc == 0x1B35 ||
      (0x1B36 <= uc && uc <= 0x1B3A) || uc == 0x1B3B || uc == 0x1B3C ||
      (0x1B3D <= uc && uc <= 0x1B41) || uc == 0x1B42 ||
      (0x1B43 <= uc && uc <= 0x1B44) || (0x1B45 <= uc && uc <= 0x1B4C) ||
      (0x1B50 <= uc && uc <= 0x1B59) || (0x1B5A <= uc && uc <= 0x1B60) ||
      (0x1B61 <= uc && uc <= 0x1B6A) || (0x1B6B <= uc && uc <= 0x1B73) ||
      (0x1B74 <= uc && uc <= 0x1B7C) || (0x1B7D <= uc && uc <= 0x1B7E) ||
      (0x1B80 <= uc && uc <= 0x1B81) || uc == 0x1B82 ||
      (0x1B83 <= uc && uc <= 0x1BA0) || uc == 0x1BA1 ||
      (0x1BA2 <= uc && uc <= 0x1BA5) || (0x1BA6 <= uc && uc <= 0x1BA7) ||
      (0x1BA8 <= uc && uc <= 0x1BA9) || uc == 0x1BAA ||
      (0x1BAB <= uc && uc <= 0x1BAD) || (0x1BAE <= uc && uc <= 0x1BAF) ||
      (0x1BB0 <= uc && uc <= 0x1BB9) || (0x1BBA <= uc && uc <= 0x1BBF) ||
      (0x1BC0 <= uc && uc <= 0x1BE5) || uc == 0x1BE6 || uc == 0x1BE7 ||
      (0x1BE8 <= uc && uc <= 0x1BE9) || (0x1BEA <= uc && uc <= 0x1BEC) ||
      uc == 0x1BED || uc == 0x1BEE || (0x1BEF <= uc && uc <= 0x1BF1) ||
      (0x1BF2 <= uc && uc <= 0x1BF3) || (0x1BFC <= uc && uc <= 0x1BFF) ||
      (0x1C00 <= uc && uc <= 0x1C23) || (0x1C24 <= uc && uc <= 0x1C2B) ||
      (0x1C2C <= uc && uc <= 0x1C33) || (0x1C34 <= uc && uc <= 0x1C35) ||
      (0x1C36 <= uc && uc <= 0x1C37) || (0x1C3B <= uc && uc <= 0x1C3F) ||
      (0x1C40 <= uc && uc <= 0x1C49) || (0x1C4D <= uc && uc <= 0x1C4F) ||
      (0x1C50 <= uc && uc <= 0x1C59) || (0x1C5A <= uc && uc <= 0x1C77) ||
      (0x1C78 <= uc && uc <= 0x1C7D) || (0x1C7E <= uc && uc <= 0x1C7F) ||
      (0x1C80 <= uc && uc <= 0x1C88) || (0x1C90 <= uc && uc <= 0x1CBA) ||
      (0x1CBD <= uc && uc <= 0x1CBF) || (0x1CC0 <= uc && uc <= 0x1CC7) ||
      (0x1CD0 <= uc && uc <= 0x1CD2) || uc == 0x1CD3 ||
      (0x1CD4 <= uc && uc <= 0x1CE0) || uc == 0x1CE1 ||
      (0x1CE2 <= uc && uc <= 0x1CE8) || (0x1CE9 <= uc && uc <= 0x1CEC) ||
      uc == 0x1CED || (0x1CEE <= uc && uc <= 0x1CF3) || uc == 0x1CF4 ||
      (0x1CF5 <= uc && uc <= 0x1CF6) || uc == 0x1CF7 ||
      (0x1CF8 <= uc && uc <= 0x1CF9) || uc == 0x1CFA ||
      (0x1D00 <= uc && uc <= 0x1D2B) || (0x1D2C <= uc && uc <= 0x1D6A) ||
      (0x1D6B <= uc && uc <= 0x1D77) || uc == 0x1D78 ||
      (0x1D79 <= uc && uc <= 0x1D7F) || (0x1D80 <= uc && uc <= 0x1D9A) ||
      (0x1D9B <= uc && uc <= 0x1DBF) || (0x1DC0 <= uc && uc <= 0x1DFF) ||
      (0x1E00 <= uc && uc <= 0x1EFF) || (0x1F00 <= uc && uc <= 0x1F15) ||
      (0x1F18 <= uc && uc <= 0x1F1D) || (0x1F20 <= uc && uc <= 0x1F45) ||
      (0x1F48 <= uc && uc <= 0x1F4D) || (0x1F50 <= uc && uc <= 0x1F57) ||
      uc == 0x1F59 || uc == 0x1F5B || uc == 0x1F5D ||
      (0x1F5F <= uc && uc <= 0x1F7D) || (0x1F80 <= uc && uc <= 0x1FB4) ||
      (0x1FB6 <= uc && uc <= 0x1FBC) || uc == 0x1FBD || uc == 0x1FBE ||
      (0x1FBF <= uc && uc <= 0x1FC1) || (0x1FC2 <= uc && uc <= 0x1FC4) ||
      (0x1FC6 <= uc && uc <= 0x1FCC) || (0x1FCD <= uc && uc <= 0x1FCF) ||
      (0x1FD0 <= uc && uc <= 0x1FD3) || (0x1FD6 <= uc && uc <= 0x1FDB) ||
      (0x1FDD <= uc && uc <= 0x1FDF) || (0x1FE0 <= uc && uc <= 0x1FEC) ||
      (0x1FED <= uc && uc <= 0x1FEF) || (0x1FF2 <= uc && uc <= 0x1FF4) ||
      (0x1FF6 <= uc && uc <= 0x1FFC) || (0x1FFD <= uc && uc <= 0x1FFE) ||
      (0x2000 <= uc && uc <= 0x200A) || (0x200B <= uc && uc <= 0x200F) ||
      (0x2011 <= uc && uc <= 0x2012) || uc == 0x2017 || uc == 0x201A ||
      uc == 0x201B || uc == 0x201E || uc == 0x201F || uc == 0x2023 ||
      uc == 0x2028 || uc == 0x2029 || (0x202A <= uc && uc <= 0x202E) ||
      uc == 0x202F || uc == 0x2031 || uc == 0x2034 ||
      (0x2036 <= uc && uc <= 0x2038) || uc == 0x2039 || uc == 0x203A ||
      (0x203C <= uc && uc <= 0x203D) || (0x203F <= uc && uc <= 0x2040) ||
      (0x2041 <= uc && uc <= 0x2043) || uc == 0x2044 || uc == 0x2045 ||
      uc == 0x2046 || (0x2047 <= uc && uc <= 0x2051) || uc == 0x2052 ||
      uc == 0x2053 || uc == 0x2054 || (0x2055 <= uc && uc <= 0x205E) ||
      uc == 0x205F || (0x2060 <= uc && uc <= 0x2064) ||
      (0x2066 <= uc && uc <= 0x206F) || uc == 0x2070 || uc == 0x2071 ||
      (0x2075 <= uc && uc <= 0x2079) || (0x207A <= uc && uc <= 0x207C) ||
      uc == 0x207D || uc == 0x207E || uc == 0x2080 ||
      (0x2085 <= uc && uc <= 0x2089) || (0x208A <= uc && uc <= 0x208C) ||
      uc == 0x208D || uc == 0x208E || (0x2090 <= uc && uc <= 0x209C) ||
      (0x20A0 <= uc && uc <= 0x20A8) || (0x20AA <= uc && uc <= 0x20AB) ||
      (0x20AD <= uc && uc <= 0x20C0) || (0x20D0 <= uc && uc <= 0x20DC) ||
      (0x20DD <= uc && uc <= 0x20E0) || uc == 0x20E1 ||
      (0x20E2 <= uc && uc <= 0x20E4) || (0x20E5 <= uc && uc <= 0x20F0) ||
      (0x2100 <= uc && uc <= 0x2101) || uc == 0x2102 || uc == 0x2104 ||
      uc == 0x2106 || uc == 0x2107 || uc == 0x2108 ||
      (0x210A <= uc && uc <= 0x2112) || uc == 0x2114 || uc == 0x2115 ||
      uc == 0x2117 || uc == 0x2118 || (0x2119 <= uc && uc <= 0x211D) ||
      (0x211E <= uc && uc <= 0x2120) || uc == 0x2123 || uc == 0x2124 ||
      uc == 0x2125 || uc == 0x2127 || uc == 0x2128 || uc == 0x2129 ||
      uc == 0x212A || (0x212C <= uc && uc <= 0x212D) || uc == 0x212E ||
      (0x212F <= uc && uc <= 0x2134) || (0x2135 <= uc && uc <= 0x2138) ||
      uc == 0x2139 || (0x213A <= uc && uc <= 0x213B) ||
      (0x213C <= uc && uc <= 0x213F) || (0x2140 <= uc && uc <= 0x2144) ||
      (0x2145 <= uc && uc <= 0x2149) || uc == 0x214A || uc == 0x214B ||
      (0x214C <= uc && uc <= 0x214D) || uc == 0x214E || uc == 0x214F ||
      (0x2150 <= uc && uc <= 0x2152) || (0x2155 <= uc && uc <= 0x215A) ||
      uc == 0x215F || (0x216C <= uc && uc <= 0x216F) ||
      (0x217A <= uc && uc <= 0x2182) || (0x2183 <= uc && uc <= 0x2184) ||
      (0x2185 <= uc && uc <= 0x2188) || (0x218A <= uc && uc <= 0x218B) ||
      (0x219A <= uc && uc <= 0x219B) || (0x219C <= uc && uc <= 0x219F) ||
      uc == 0x21A0 || (0x21A1 <= uc && uc <= 0x21A2) || uc == 0x21A3 ||
      (0x21A4 <= uc && uc <= 0x21A5) || uc == 0x21A6 ||
      (0x21A7 <= uc && uc <= 0x21AD) || uc == 0x21AE ||
      (0x21AF <= uc && uc <= 0x21B7) || (0x21BA <= uc && uc <= 0x21CD) ||
      (0x21CE <= uc && uc <= 0x21CF) || (0x21D0 <= uc && uc <= 0x21D1) ||
      uc == 0x21D3 || (0x21D5 <= uc && uc <= 0x21E6) ||
      (0x21E8 <= uc && uc <= 0x21F3) || (0x21F4 <= uc && uc <= 0x21FF) ||
      uc == 0x2201 || (0x2204 <= uc && uc <= 0x2206) ||
      (0x2209 <= uc && uc <= 0x220A) || (0x220C <= uc && uc <= 0x220E) ||
      uc == 0x2210 || (0x2212 <= uc && uc <= 0x2214) ||
      (0x2216 <= uc && uc <= 0x2219) || (0x221B <= uc && uc <= 0x221C) ||
      (0x2221 <= uc && uc <= 0x2222) || uc == 0x2224 || uc == 0x2226 ||
      uc == 0x222D || (0x222F <= uc && uc <= 0x2233) ||
      (0x2238 <= uc && uc <= 0x223B) || (0x223E <= uc && uc <= 0x2247) ||
      (0x2249 <= uc && uc <= 0x224B) || (0x224D <= uc && uc <= 0x2251) ||
      (0x2253 <= uc && uc <= 0x225F) || (0x2262 <= uc && uc <= 0x2263) ||
      (0x2268 <= uc && uc <= 0x2269) || (0x226C <= uc && uc <= 0x226D) ||
      (0x2270 <= uc && uc <= 0x2281) || (0x2284 <= uc && uc <= 0x2285) ||
      (0x2288 <= uc && uc <= 0x2294) || (0x2296 <= uc && uc <= 0x2298) ||
      (0x229A <= uc && uc <= 0x22A4) || (0x22A6 <= uc && uc <= 0x22BE) ||
      (0x22C0 <= uc && uc <= 0x22FF) || (0x2300 <= uc && uc <= 0x2307) ||
      uc == 0x2308 || uc == 0x2309 || uc == 0x230A || uc == 0x230B ||
      (0x230C <= uc && uc <= 0x2311) || (0x2313 <= uc && uc <= 0x2319) ||
      (0x231C <= uc && uc <= 0x231F) || (0x2320 <= uc && uc <= 0x2321) ||
      (0x2322 <= uc && uc <= 0x2328) || (0x232B <= uc && uc <= 0x237B) ||
      uc == 0x237C || (0x237D <= uc && uc <= 0x239A) ||
      (0x239B <= uc && uc <= 0x23B3) || (0x23B4 <= uc && uc <= 0x23DB) ||
      (0x23DC <= uc && uc <= 0x23E1) || (0x23E2 <= uc && uc <= 0x23E8) ||
      (0x23ED <= uc && uc <= 0x23EF) || (0x23F1 <= uc && uc <= 0x23F2) ||
      (0x23F4 <= uc && uc <= 0x23FF) || (0x2400 <= uc && uc <= 0x2426) ||
      (0x2440 <= uc && uc <= 0x244A) || uc == 0x24EA ||
      (0x254C <= uc && uc <= 0x254F) || (0x2574 <= uc && uc <= 0x257F) ||
      (0x2590 <= uc && uc <= 0x2591) || (0x2596 <= uc && uc <= 0x259F) ||
      uc == 0x25A2 || (0x25AA <= uc && uc <= 0x25B1) ||
      (0x25B4 <= uc && uc <= 0x25B5) || (0x25B8 <= uc && uc <= 0x25BB) ||
      (0x25BE <= uc && uc <= 0x25BF) || (0x25C2 <= uc && uc <= 0x25C5) ||
      (0x25C9 <= uc && uc <= 0x25CA) || (0x25CC <= uc && uc <= 0x25CD) ||
      (0x25D2 <= uc && uc <= 0x25E1) || (0x25E6 <= uc && uc <= 0x25EE) ||
      (0x25F0 <= uc && uc <= 0x25F7) || (0x25F8 <= uc && uc <= 0x25FC) ||
      uc == 0x25FF || (0x2600 <= uc && uc <= 0x2604) ||
      (0x2607 <= uc && uc <= 0x2608) || (0x260A <= uc && uc <= 0x260D) ||
      (0x2610 <= uc && uc <= 0x2613) || (0x2616 <= uc && uc <= 0x261B) ||
      uc == 0x261D || (0x261F <= uc && uc <= 0x263F) || uc == 0x2641 ||
      (0x2643 <= uc && uc <= 0x2647) || (0x2654 <= uc && uc <= 0x265F) ||
      uc == 0x2662 || uc == 0x2666 || uc == 0x266B || uc == 0x266E ||
      (0x2670 <= uc && uc <= 0x267E) || (0x2680 <= uc && uc <= 0x2692) ||
      (0x2694 <= uc && uc <= 0x269D) || uc == 0x26A0 ||
      (0x26A2 <= uc && uc <= 0x26A9) || (0x26AC <= uc && uc <= 0x26BC) ||
      (0x26C0 <= uc && uc <= 0x26C3) || uc == 0x26E2 ||
      (0x26E4 <= uc && uc <= 0x26E7) || (0x2700 <= uc && uc <= 0x2704) ||
      (0x2706 <= uc && uc <= 0x2709) || (0x270C <= uc && uc <= 0x2727) ||
      (0x2729 <= uc && uc <= 0x273C) || (0x273E <= uc && uc <= 0x274B) ||
      uc == 0x274D || (0x274F <= uc && uc <= 0x2752) || uc == 0x2756 ||
      (0x2758 <= uc && uc <= 0x2767) || uc == 0x2768 || uc == 0x2769 ||
      uc == 0x276A || uc == 0x276B || uc == 0x276C || uc == 0x276D ||
      uc == 0x276E || uc == 0x276F || uc == 0x2770 || uc == 0x2771 ||
      uc == 0x2772 || uc == 0x2773 || uc == 0x2774 || uc == 0x2775 ||
      (0x2780 <= uc && uc <= 0x2793) || uc == 0x2794 ||
      (0x2798 <= uc && uc <= 0x27AF) || (0x27B1 <= uc && uc <= 0x27BE) ||
      (0x27C0 <= uc && uc <= 0x27C4) || uc == 0x27C5 || uc == 0x27C6 ||
      (0x27C7 <= uc && uc <= 0x27E5) || uc == 0x27EE || uc == 0x27EF ||
      (0x27F0 <= uc && uc <= 0x27FF) || (0x2800 <= uc && uc <= 0x28FF) ||
      (0x2900 <= uc && uc <= 0x297F) || (0x2980 <= uc && uc <= 0x2982) ||
      uc == 0x2983 || uc == 0x2984 || uc == 0x2987 || uc == 0x2988 ||
      uc == 0x2989 || uc == 0x298A || uc == 0x298B || uc == 0x298C ||
      uc == 0x298D || uc == 0x298E || uc == 0x298F || uc == 0x2990 ||
      uc == 0x2991 || uc == 0x2992 || uc == 0x2993 || uc == 0x2994 ||
      uc == 0x2995 || uc == 0x2996 || uc == 0x2997 || uc == 0x2998 ||
      (0x2999 <= uc && uc <= 0x29D7) || uc == 0x29D8 || uc == 0x29D9 ||
      uc == 0x29DA || uc == 0x29DB || (0x29DC <= uc && uc <= 0x29FB) ||
      uc == 0x29FC || uc == 0x29FD || (0x29FE <= uc && uc <= 0x29FF) ||
      (0x2A00 <= uc && uc <= 0x2AFF) || (0x2B00 <= uc && uc <= 0x2B1A) ||
      (0x2B1D <= uc && uc <= 0x2B2F) || (0x2B30 <= uc && uc <= 0x2B44) ||
      (0x2B45 <= uc && uc <= 0x2B46) || (0x2B47 <= uc && uc <= 0x2B4C) ||
      (0x2B4D <= uc && uc <= 0x2B4F) || (0x2B51 <= uc && uc <= 0x2B54) ||
      (0x2B5A <= uc && uc <= 0x2B73) || (0x2B76 <= uc && uc <= 0x2B95) ||
      (0x2B97 <= uc && uc <= 0x2BFF) || (0x2C00 <= uc && uc <= 0x2C5F) ||
      (0x2C60 <= uc && uc <= 0x2C7B) || (0x2C7C <= uc && uc <= 0x2C7D) ||
      (0x2C7E <= uc && uc <= 0x2C7F) || (0x2C80 <= uc && uc <= 0x2CE4) ||
      (0x2CE5 <= uc && uc <= 0x2CEA) || (0x2CEB <= uc && uc <= 0x2CEE) ||
      (0x2CEF <= uc && uc <= 0x2CF1) || (0x2CF2 <= uc && uc <= 0x2CF3) ||
      (0x2CF9 <= uc && uc <= 0x2CFC) || uc == 0x2CFD ||
      (0x2CFE <= uc && uc <= 0x2CFF) || (0x2D00 <= uc && uc <= 0x2D25) ||
      uc == 0x2D27 || uc == 0x2D2D || (0x2D30 <= uc && uc <= 0x2D67) ||
      uc == 0x2D6F || uc == 0x2D70 || uc == 0x2D7F ||
      (0x2D80 <= uc && uc <= 0x2D96) || (0x2DA0 <= uc && uc <= 0x2DA6) ||
      (0x2DA8 <= uc && uc <= 0x2DAE) || (0x2DB0 <= uc && uc <= 0x2DB6) ||
      (0x2DB8 <= uc && uc <= 0x2DBE) || (0x2DC0 <= uc && uc <= 0x2DC6) ||
      (0x2DC8 <= uc && uc <= 0x2DCE) || (0x2DD0 <= uc && uc <= 0x2DD6) ||
      (0x2DD8 <= uc && uc <= 0x2DDE) || (0x2DE0 <= uc && uc <= 0x2DFF) ||
      (0x2E00 <= uc && uc <= 0x2E01) || uc == 0x2E02 || uc == 0x2E03 ||
      uc == 0x2E04 || uc == 0x2E05 || (0x2E06 <= uc && uc <= 0x2E08) ||
      uc == 0x2E09 || uc == 0x2E0A || uc == 0x2E0B || uc == 0x2E0C ||
      uc == 0x2E0D || (0x2E0E <= uc && uc <= 0x2E16) || uc == 0x2E17 ||
      (0x2E18 <= uc && uc <= 0x2E19) || uc == 0x2E1A || uc == 0x2E1B ||
      uc == 0x2E1C || uc == 0x2E1D || (0x2E1E <= uc && uc <= 0x2E1F) ||
      uc == 0x2E20 || uc == 0x2E21 || uc == 0x2E22 || uc == 0x2E23 ||
      uc == 0x2E24 || uc == 0x2E25 || uc == 0x2E26 || uc == 0x2E27 ||
      uc == 0x2E28 || uc == 0x2E29 || (0x2E2A <= uc && uc <= 0x2E2E) ||
      uc == 0x2E2F || (0x2E30 <= uc && uc <= 0x2E39) ||
      (0x2E3A <= uc && uc <= 0x2E3B) || (0x2E3C <= uc && uc <= 0x2E3F) ||
      uc == 0x2E40 || uc == 0x2E41 || uc == 0x2E42 ||
      (0x2E43 <= uc && uc <= 0x2E4F) || (0x2E50 <= uc && uc <= 0x2E51) ||
      (0x2E52 <= uc && uc <= 0x2E54) || uc == 0x2E55 || uc == 0x2E56 ||
      uc == 0x2E57 || uc == 0x2E58 || uc == 0x2E59 || uc == 0x2E5A ||
      uc == 0x2E5B || uc == 0x2E5C || uc == 0x2E5D || uc == 0x303F ||
      (0x4DC0 <= uc && uc <= 0x4DFF) || (0xA4D0 <= uc && uc <= 0xA4F7) ||
      (0xA4F8 <= uc && uc <= 0xA4FD) || (0xA4FE <= uc && uc <= 0xA4FF) ||
      (0xA500 <= uc && uc <= 0xA60B) || uc == 0xA60C ||
      (0xA60D <= uc && uc <= 0xA60F) || (0xA610 <= uc && uc <= 0xA61F) ||
      (0xA620 <= uc && uc <= 0xA629) || (0xA62A <= uc && uc <= 0xA62B) ||
      (0xA640 <= uc && uc <= 0xA66D) || uc == 0xA66E || uc == 0xA66F ||
      (0xA670 <= uc && uc <= 0xA672) || uc == 0xA673 ||
      (0xA674 <= uc && uc <= 0xA67D) || uc == 0xA67E || uc == 0xA67F ||
      (0xA680 <= uc && uc <= 0xA69B) || (0xA69C <= uc && uc <= 0xA69D) ||
      (0xA69E <= uc && uc <= 0xA69F) || (0xA6A0 <= uc && uc <= 0xA6E5) ||
      (0xA6E6 <= uc && uc <= 0xA6EF) || (0xA6F0 <= uc && uc <= 0xA6F1) ||
      (0xA6F2 <= uc && uc <= 0xA6F7) || (0xA700 <= uc && uc <= 0xA716) ||
      (0xA717 <= uc && uc <= 0xA71F) || (0xA720 <= uc && uc <= 0xA721) ||
      (0xA722 <= uc && uc <= 0xA76F) || uc == 0xA770 ||
      (0xA771 <= uc && uc <= 0xA787) || uc == 0xA788 ||
      (0xA789 <= uc && uc <= 0xA78A) || (0xA78B <= uc && uc <= 0xA78E) ||
      uc == 0xA78F || (0xA790 <= uc && uc <= 0xA7CA) ||
      (0xA7D0 <= uc && uc <= 0xA7D1) || uc == 0xA7D3 ||
      (0xA7D5 <= uc && uc <= 0xA7D9) || (0xA7F2 <= uc && uc <= 0xA7F4) ||
      (0xA7F5 <= uc && uc <= 0xA7F6) || uc == 0xA7F7 ||
      (0xA7F8 <= uc && uc <= 0xA7F9) || uc == 0xA7FA ||
      (0xA7FB <= uc && uc <= 0xA7FF) || (0xA800 <= uc && uc <= 0xA801) ||
      uc == 0xA802 || (0xA803 <= uc && uc <= 0xA805) || uc == 0xA806 ||
      (0xA807 <= uc && uc <= 0xA80A) || uc == 0xA80B ||
      (0xA80C <= uc && uc <= 0xA822) || (0xA823 <= uc && uc <= 0xA824) ||
      (0xA825 <= uc && uc <= 0xA826) || uc == 0xA827 ||
      (0xA828 <= uc && uc <= 0xA82B) || uc == 0xA82C ||
      (0xA830 <= uc && uc <= 0xA835) || (0xA836 <= uc && uc <= 0xA837) ||
      uc == 0xA838 || uc == 0xA839 || (0xA840 <= uc && uc <= 0xA873) ||
      (0xA874 <= uc && uc <= 0xA877) || (0xA880 <= uc && uc <= 0xA881) ||
      (0xA882 <= uc && uc <= 0xA8B3) || (0xA8B4 <= uc && uc <= 0xA8C3) ||
      (0xA8C4 <= uc && uc <= 0xA8C5) || (0xA8CE <= uc && uc <= 0xA8CF) ||
      (0xA8D0 <= uc && uc <= 0xA8D9) || (0xA8E0 <= uc && uc <= 0xA8F1) ||
      (0xA8F2 <= uc && uc <= 0xA8F7) || (0xA8F8 <= uc && uc <= 0xA8FA) ||
      uc == 0xA8FB || uc == 0xA8FC || (0xA8FD <= uc && uc <= 0xA8FE) ||
      uc == 0xA8FF || (0xA900 <= uc && uc <= 0xA909) ||
      (0xA90A <= uc && uc <= 0xA925) || (0xA926 <= uc && uc <= 0xA92D) ||
      (0xA92E <= uc && uc <= 0xA92F) || (0xA930 <= uc && uc <= 0xA946) ||
      (0xA947 <= uc && uc <= 0xA951) || (0xA952 <= uc && uc <= 0xA953) ||
      uc == 0xA95F || (0xA980 <= uc && uc <= 0xA982) || uc == 0xA983 ||
      (0xA984 <= uc && uc <= 0xA9B2) || uc == 0xA9B3 ||
      (0xA9B4 <= uc && uc <= 0xA9B5) || (0xA9B6 <= uc && uc <= 0xA9B9) ||
      (0xA9BA <= uc && uc <= 0xA9BB) || (0xA9BC <= uc && uc <= 0xA9BD) ||
      (0xA9BE <= uc && uc <= 0xA9C0) || (0xA9C1 <= uc && uc <= 0xA9CD) ||
      uc == 0xA9CF || (0xA9D0 <= uc && uc <= 0xA9D9) ||
      (0xA9DE <= uc && uc <= 0xA9DF) || (0xA9E0 <= uc && uc <= 0xA9E4) ||
      uc == 0xA9E5 || uc == 0xA9E6 || (0xA9E7 <= uc && uc <= 0xA9EF) ||
      (0xA9F0 <= uc && uc <= 0xA9F9) || (0xA9FA <= uc && uc <= 0xA9FE) ||
      (0xAA00 <= uc && uc <= 0xAA28) || (0xAA29 <= uc && uc <= 0xAA2E) ||
      (0xAA2F <= uc && uc <= 0xAA30) || (0xAA31 <= uc && uc <= 0xAA32) ||
      (0xAA33 <= uc && uc <= 0xAA34) || (0xAA35 <= uc && uc <= 0xAA36) ||
      (0xAA40 <= uc && uc <= 0xAA42) || uc == 0xAA43 ||
      (0xAA44 <= uc && uc <= 0xAA4B) || uc == 0xAA4C || uc == 0xAA4D ||
      (0xAA50 <= uc && uc <= 0xAA59) || (0xAA5C <= uc && uc <= 0xAA5F) ||
      (0xAA60 <= uc && uc <= 0xAA6F) || uc == 0xAA70 ||
      (0xAA71 <= uc && uc <= 0xAA76) || (0xAA77 <= uc && uc <= 0xAA79) ||
      uc == 0xAA7A || uc == 0xAA7B || uc == 0xAA7C || uc == 0xAA7D ||
      (0xAA7E <= uc && uc <= 0xAA7F) || (0xAA80 <= uc && uc <= 0xAAAF) ||
      uc == 0xAAB0 || uc == 0xAAB1 || (0xAAB2 <= uc && uc <= 0xAAB4) ||
      (0xAAB5 <= uc && uc <= 0xAAB6) || (0xAAB7 <= uc && uc <= 0xAAB8) ||
      (0xAAB9 <= uc && uc <= 0xAABD) || (0xAABE <= uc && uc <= 0xAABF) ||
      uc == 0xAAC0 || uc == 0xAAC1 || uc == 0xAAC2 ||
      (0xAADB <= uc && uc <= 0xAADC) || uc == 0xAADD ||
      (0xAADE <= uc && uc <= 0xAADF) || (0xAAE0 <= uc && uc <= 0xAAEA) ||
      uc == 0xAAEB || (0xAAEC <= uc && uc <= 0xAAED) ||
      (0xAAEE <= uc && uc <= 0xAAEF) || (0xAAF0 <= uc && uc <= 0xAAF1) ||
      uc == 0xAAF2 || (0xAAF3 <= uc && uc <= 0xAAF4) || uc == 0xAAF5 ||
      uc == 0xAAF6 || (0xAB01 <= uc && uc <= 0xAB06) ||
      (0xAB09 <= uc && uc <= 0xAB0E) || (0xAB11 <= uc && uc <= 0xAB16) ||
      (0xAB20 <= uc && uc <= 0xAB26) || (0xAB28 <= uc && uc <= 0xAB2E) ||
      (0xAB30 <= uc && uc <= 0xAB5A) || uc == 0xAB5B ||
      (0xAB5C <= uc && uc <= 0xAB5F) || (0xAB60 <= uc && uc <= 0xAB68) ||
      uc == 0xAB69 || (0xAB6A <= uc && uc <= 0xAB6B) ||
      (0xAB70 <= uc && uc <= 0xABBF) || (0xABC0 <= uc && uc <= 0xABE2) ||
      (0xABE3 <= uc && uc <= 0xABE4) || uc == 0xABE5 ||
      (0xABE6 <= uc && uc <= 0xABE7) || uc == 0xABE8 ||
      (0xABE9 <= uc && uc <= 0xABEA) || uc == 0xABEB || uc == 0xABEC ||
      uc == 0xABED || (0xABF0 <= uc && uc <= 0xABF9) ||
      (0xD7B0 <= uc && uc <= 0xD7C6) || (0xD7CB <= uc && uc <= 0xD7FB) ||
      (0xD800 <= uc && uc <= 0xDB7F) || (0xDB80 <= uc && uc <= 0xDBFF) ||
      (0xDC00 <= uc && uc <= 0xDFFF) || (0xFB00 <= uc && uc <= 0xFB06) ||
      (0xFB13 <= uc && uc <= 0xFB17) || uc == 0xFB1D || uc == 0xFB1E ||
      (0xFB1F <= uc && uc <= 0xFB28) || uc == 0xFB29 ||
      (0xFB2A <= uc && uc <= 0xFB36) || (0xFB38 <= uc && uc <= 0xFB3C) ||
      uc == 0xFB3E || (0xFB40 <= uc && uc <= 0xFB41) ||
      (0xFB43 <= uc && uc <= 0xFB44) || (0xFB46 <= uc && uc <= 0xFB4F) ||
      (0xFB50 <= uc && uc <= 0xFBB1) || (0xFBB2 <= uc && uc <= 0xFBC2) ||
      (0xFBD3 <= uc && uc <= 0xFD3D) || uc == 0xFD3E || uc == 0xFD3F ||
      (0xFD40 <= uc && uc <= 0xFD4F) || (0xFD50 <= uc && uc <= 0xFD8F) ||
      (0xFD92 <= uc && uc <= 0xFDC7) || uc == 0xFDCF ||
      (0xFDF0 <= uc && uc <= 0xFDFB) || uc == 0xFDFC ||
      (0xFDFD <= uc && uc <= 0xFDFF) || (0xFE20 <= uc && uc <= 0xFE2F) ||
      (0xFE70 <= uc && uc <= 0xFE74) || (0xFE76 <= uc && uc <= 0xFEFC) ||
      uc == 0xFEFF || (0xFFF9 <= uc && uc <= 0xFFFB) || uc == 0xFFFC ||
      (0x10000 <= uc && uc <= 0x1000B) || (0x1000D <= uc && uc <= 0x10026) ||
      (0x10028 <= uc && uc <= 0x1003A) || (0x1003C <= uc && uc <= 0x1003D) ||
      (0x1003F <= uc && uc <= 0x1004D) || (0x10050 <= uc && uc <= 0x1005D) ||
      (0x10080 <= uc && uc <= 0x100FA) || (0x10100 <= uc && uc <= 0x10102) ||
      (0x10107 <= uc && uc <= 0x10133) || (0x10137 <= uc && uc <= 0x1013F) ||
      (0x10140 <= uc && uc <= 0x10174) || (0x10175 <= uc && uc <= 0x10178) ||
      (0x10179 <= uc && uc <= 0x10189) || (0x1018A <= uc && uc <= 0x1018B) ||
      (0x1018C <= uc && uc <= 0x1018E) || (0x10190 <= uc && uc <= 0x1019C) ||
      uc == 0x101A0 || (0x101D0 <= uc && uc <= 0x101FC) || uc == 0x101FD ||
      (0x10280 <= uc && uc <= 0x1029C) || (0x102A0 <= uc && uc <= 0x102D0) ||
      uc == 0x102E0 || (0x102E1 <= uc && uc <= 0x102FB) ||
      (0x10300 <= uc && uc <= 0x1031F) || (0x10320 <= uc && uc <= 0x10323) ||
      (0x1032D <= uc && uc <= 0x1032F) || (0x10330 <= uc && uc <= 0x10340) ||
      uc == 0x10341 || (0x10342 <= uc && uc <= 0x10349) || uc == 0x1034A ||
      (0x10350 <= uc && uc <= 0x10375) || (0x10376 <= uc && uc <= 0x1037A) ||
      (0x10380 <= uc && uc <= 0x1039D) || uc == 0x1039F ||
      (0x103A0 <= uc && uc <= 0x103C3) || (0x103C8 <= uc && uc <= 0x103CF) ||
      uc == 0x103D0 || (0x103D1 <= uc && uc <= 0x103D5) ||
      (0x10400 <= uc && uc <= 0x1044F) || (0x10450 <= uc && uc <= 0x1047F) ||
      (0x10480 <= uc && uc <= 0x1049D) || (0x104A0 <= uc && uc <= 0x104A9) ||
      (0x104B0 <= uc && uc <= 0x104D3) || (0x104D8 <= uc && uc <= 0x104FB) ||
      (0x10500 <= uc && uc <= 0x10527) || (0x10530 <= uc && uc <= 0x10563) ||
      uc == 0x1056F || (0x10570 <= uc && uc <= 0x1057A) ||
      (0x1057C <= uc && uc <= 0x1058A) || (0x1058C <= uc && uc <= 0x10592) ||
      (0x10594 <= uc && uc <= 0x10595) || (0x10597 <= uc && uc <= 0x105A1) ||
      (0x105A3 <= uc && uc <= 0x105B1) || (0x105B3 <= uc && uc <= 0x105B9) ||
      (0x105BB <= uc && uc <= 0x105BC) || (0x10600 <= uc && uc <= 0x10736) ||
      (0x10740 <= uc && uc <= 0x10755) || (0x10760 <= uc && uc <= 0x10767) ||
      (0x10780 <= uc && uc <= 0x10785) || (0x10787 <= uc && uc <= 0x107B0) ||
      (0x107B2 <= uc && uc <= 0x107BA) || (0x10800 <= uc && uc <= 0x10805) ||
      uc == 0x10808 || (0x1080A <= uc && uc <= 0x10835) ||
      (0x10837 <= uc && uc <= 0x10838) || uc == 0x1083C || uc == 0x1083F ||
      (0x10840 <= uc && uc <= 0x10855) || uc == 0x10857 ||
      (0x10858 <= uc && uc <= 0x1085F) || (0x10860 <= uc && uc <= 0x10876) ||
      (0x10877 <= uc && uc <= 0x10878) || (0x10879 <= uc && uc <= 0x1087F) ||
      (0x10880 <= uc && uc <= 0x1089E) || (0x108A7 <= uc && uc <= 0x108AF) ||
      (0x108E0 <= uc && uc <= 0x108F2) || (0x108F4 <= uc && uc <= 0x108F5) ||
      (0x108FB <= uc && uc <= 0x108FF) || (0x10900 <= uc && uc <= 0x10915) ||
      (0x10916 <= uc && uc <= 0x1091B) || uc == 0x1091F ||
      (0x10920 <= uc && uc <= 0x10939) || uc == 0x1093F ||
      (0x10980 <= uc && uc <= 0x1099F) || (0x109A0 <= uc && uc <= 0x109B7) ||
      (0x109BC <= uc && uc <= 0x109BD) || (0x109BE <= uc && uc <= 0x109BF) ||
      (0x109C0 <= uc && uc <= 0x109CF) || (0x109D2 <= uc && uc <= 0x109FF) ||
      uc == 0x10A00 || (0x10A01 <= uc && uc <= 0x10A03) ||
      (0x10A05 <= uc && uc <= 0x10A06) || (0x10A0C <= uc && uc <= 0x10A0F) ||
      (0x10A10 <= uc && uc <= 0x10A13) || (0x10A15 <= uc && uc <= 0x10A17) ||
      (0x10A19 <= uc && uc <= 0x10A35) || (0x10A38 <= uc && uc <= 0x10A3A) ||
      uc == 0x10A3F || (0x10A40 <= uc && uc <= 0x10A48) ||
      (0x10A50 <= uc && uc <= 0x10A58) || (0x10A60 <= uc && uc <= 0x10A7C) ||
      (0x10A7D <= uc && uc <= 0x10A7E) || uc == 0x10A7F ||
      (0x10A80 <= uc && uc <= 0x10A9C) || (0x10A9D <= uc && uc <= 0x10A9F) ||
      (0x10AC0 <= uc && uc <= 0x10AC7) || uc == 0x10AC8 ||
      (0x10AC9 <= uc && uc <= 0x10AE4) || (0x10AE5 <= uc && uc <= 0x10AE6) ||
      (0x10AEB <= uc && uc <= 0x10AEF) || (0x10AF0 <= uc && uc <= 0x10AF6) ||
      (0x10B00 <= uc && uc <= 0x10B35) || (0x10B39 <= uc && uc <= 0x10B3F) ||
      (0x10B40 <= uc && uc <= 0x10B55) || (0x10B58 <= uc && uc <= 0x10B5F) ||
      (0x10B60 <= uc && uc <= 0x10B72) || (0x10B78 <= uc && uc <= 0x10B7F) ||
      (0x10B80 <= uc && uc <= 0x10B91) || (0x10B99 <= uc && uc <= 0x10B9C) ||
      (0x10BA9 <= uc && uc <= 0x10BAF) || (0x10C00 <= uc && uc <= 0x10C48) ||
      (0x10C80 <= uc && uc <= 0x10CB2) || (0x10CC0 <= uc && uc <= 0x10CF2) ||
      (0x10CFA <= uc && uc <= 0x10CFF) || (0x10D00 <= uc && uc <= 0x10D23) ||
      (0x10D24 <= uc && uc <= 0x10D27) || (0x10D30 <= uc && uc <= 0x10D39) ||
      (0x10E60 <= uc && uc <= 0x10E7E) || (0x10E80 <= uc && uc <= 0x10EA9) ||
      (0x10EAB <= uc && uc <= 0x10EAC) || uc == 0x10EAD ||
      (0x10EB0 <= uc && uc <= 0x10EB1) || (0x10EFD <= uc && uc <= 0x10EFF) ||
      (0x10F00 <= uc && uc <= 0x10F1C) || (0x10F1D <= uc && uc <= 0x10F26) ||
      uc == 0x10F27 || (0x10F30 <= uc && uc <= 0x10F45) ||
      (0x10F46 <= uc && uc <= 0x10F50) || (0x10F51 <= uc && uc <= 0x10F54) ||
      (0x10F55 <= uc && uc <= 0x10F59) || (0x10F70 <= uc && uc <= 0x10F81) ||
      (0x10F82 <= uc && uc <= 0x10F85) || (0x10F86 <= uc && uc <= 0x10F89) ||
      (0x10FB0 <= uc && uc <= 0x10FC4) || (0x10FC5 <= uc && uc <= 0x10FCB) ||
      (0x10FE0 <= uc && uc <= 0x10FF6) || uc == 0x11000 || uc == 0x11001 ||
      uc == 0x11002 || (0x11003 <= uc && uc <= 0x11037) ||
      (0x11038 <= uc && uc <= 0x11046) || (0x11047 <= uc && uc <= 0x1104D) ||
      (0x11052 <= uc && uc <= 0x11065) || (0x11066 <= uc && uc <= 0x1106F) ||
      uc == 0x11070 || (0x11071 <= uc && uc <= 0x11072) ||
      (0x11073 <= uc && uc <= 0x11074) || uc == 0x11075 || uc == 0x1107F ||
      (0x11080 <= uc && uc <= 0x11081) || uc == 0x11082 ||
      (0x11083 <= uc && uc <= 0x110AF) || (0x110B0 <= uc && uc <= 0x110B2) ||
      (0x110B3 <= uc && uc <= 0x110B6) || (0x110B7 <= uc && uc <= 0x110B8) ||
      (0x110B9 <= uc && uc <= 0x110BA) || (0x110BB <= uc && uc <= 0x110BC) ||
      uc == 0x110BD || (0x110BE <= uc && uc <= 0x110C1) || uc == 0x110C2 ||
      uc == 0x110CD || (0x110D0 <= uc && uc <= 0x110E8) ||
      (0x110F0 <= uc && uc <= 0x110F9) || (0x11100 <= uc && uc <= 0x11102) ||
      (0x11103 <= uc && uc <= 0x11126) || (0x11127 <= uc && uc <= 0x1112B) ||
      uc == 0x1112C || (0x1112D <= uc && uc <= 0x11134) ||
      (0x11136 <= uc && uc <= 0x1113F) || (0x11140 <= uc && uc <= 0x11143) ||
      uc == 0x11144 || (0x11145 <= uc && uc <= 0x11146) || uc == 0x11147 ||
      (0x11150 <= uc && uc <= 0x11172) || uc == 0x11173 ||
      (0x11174 <= uc && uc <= 0x11175) || uc == 0x11176 ||
      (0x11180 <= uc && uc <= 0x11181) || uc == 0x11182 ||
      (0x11183 <= uc && uc <= 0x111B2) || (0x111B3 <= uc && uc <= 0x111B5) ||
      (0x111B6 <= uc && uc <= 0x111BE) || (0x111BF <= uc && uc <= 0x111C0) ||
      (0x111C1 <= uc && uc <= 0x111C4) || (0x111C5 <= uc && uc <= 0x111C8) ||
      (0x111C9 <= uc && uc <= 0x111CC) || uc == 0x111CD || uc == 0x111CE ||
      uc == 0x111CF || (0x111D0 <= uc && uc <= 0x111D9) || uc == 0x111DA ||
      uc == 0x111DB || uc == 0x111DC || (0x111DD <= uc && uc <= 0x111DF) ||
      (0x111E1 <= uc && uc <= 0x111F4) || (0x11200 <= uc && uc <= 0x11211) ||
      (0x11213 <= uc && uc <= 0x1122B) || (0x1122C <= uc && uc <= 0x1122E) ||
      (0x1122F <= uc && uc <= 0x11231) || (0x11232 <= uc && uc <= 0x11233) ||
      uc == 0x11234 || uc == 0x11235 || (0x11236 <= uc && uc <= 0x11237) ||
      (0x11238 <= uc && uc <= 0x1123D) || uc == 0x1123E ||
      (0x1123F <= uc && uc <= 0x11240) || uc == 0x11241 ||
      (0x11280 <= uc && uc <= 0x11286) || uc == 0x11288 ||
      (0x1128A <= uc && uc <= 0x1128D) || (0x1128F <= uc && uc <= 0x1129D) ||
      (0x1129F <= uc && uc <= 0x112A8) || uc == 0x112A9 ||
      (0x112B0 <= uc && uc <= 0x112DE) || uc == 0x112DF ||
      (0x112E0 <= uc && uc <= 0x112E2) || (0x112E3 <= uc && uc <= 0x112EA) ||
      (0x112F0 <= uc && uc <= 0x112F9) || (0x11300 <= uc && uc <= 0x11301) ||
      (0x11302 <= uc && uc <= 0x11303) || (0x11305 <= uc && uc <= 0x1130C) ||
      (0x1130F <= uc && uc <= 0x11310) || (0x11313 <= uc && uc <= 0x11328) ||
      (0x1132A <= uc && uc <= 0x11330) || (0x11332 <= uc && uc <= 0x11333) ||
      (0x11335 <= uc && uc <= 0x11339) || (0x1133B <= uc && uc <= 0x1133C) ||
      uc == 0x1133D || (0x1133E <= uc && uc <= 0x1133F) || uc == 0x11340 ||
      (0x11341 <= uc && uc <= 0x11344) || (0x11347 <= uc && uc <= 0x11348) ||
      (0x1134B <= uc && uc <= 0x1134D) || uc == 0x11350 || uc == 0x11357 ||
      (0x1135D <= uc && uc <= 0x11361) || (0x11362 <= uc && uc <= 0x11363) ||
      (0x11366 <= uc && uc <= 0x1136C) || (0x11370 <= uc && uc <= 0x11374) ||
      (0x11400 <= uc && uc <= 0x11434) || (0x11435 <= uc && uc <= 0x11437) ||
      (0x11438 <= uc && uc <= 0x1143F) || (0x11440 <= uc && uc <= 0x11441) ||
      (0x11442 <= uc && uc <= 0x11444) || uc == 0x11445 || uc == 0x11446 ||
      (0x11447 <= uc && uc <= 0x1144A) || (0x1144B <= uc && uc <= 0x1144F) ||
      (0x11450 <= uc && uc <= 0x11459) || (0x1145A <= uc && uc <= 0x1145B) ||
      uc == 0x1145D || uc == 0x1145E || (0x1145F <= uc && uc <= 0x11461) ||
      (0x11480 <= uc && uc <= 0x114AF) || (0x114B0 <= uc && uc <= 0x114B2) ||
      (0x114B3 <= uc && uc <= 0x114B8) || uc == 0x114B9 || uc == 0x114BA ||
      (0x114BB <= uc && uc <= 0x114BE) || (0x114BF <= uc && uc <= 0x114C0) ||
      uc == 0x114C1 || (0x114C2 <= uc && uc <= 0x114C3) ||
      (0x114C4 <= uc && uc <= 0x114C5) || uc == 0x114C6 || uc == 0x114C7 ||
      (0x114D0 <= uc && uc <= 0x114D9) || (0x11580 <= uc && uc <= 0x115AE) ||
      (0x115AF <= uc && uc <= 0x115B1) || (0x115B2 <= uc && uc <= 0x115B5) ||
      (0x115B8 <= uc && uc <= 0x115BB) || (0x115BC <= uc && uc <= 0x115BD) ||
      uc == 0x115BE || (0x115BF <= uc && uc <= 0x115C0) ||
      (0x115C1 <= uc && uc <= 0x115D7) || (0x115D8 <= uc && uc <= 0x115DB) ||
      (0x115DC <= uc && uc <= 0x115DD) || (0x11600 <= uc && uc <= 0x1162F) ||
      (0x11630 <= uc && uc <= 0x11632) || (0x11633 <= uc && uc <= 0x1163A) ||
      (0x1163B <= uc && uc <= 0x1163C) || uc == 0x1163D || uc == 0x1163E ||
      (0x1163F <= uc && uc <= 0x11640) || (0x11641 <= uc && uc <= 0x11643) ||
      uc == 0x11644 || (0x11650 <= uc && uc <= 0x11659) ||
      (0x11660 <= uc && uc <= 0x1166C) || (0x11680 <= uc && uc <= 0x116AA) ||
      uc == 0x116AB || uc == 0x116AC || uc == 0x116AD ||
      (0x116AE <= uc && uc <= 0x116AF) || (0x116B0 <= uc && uc <= 0x116B5) ||
      uc == 0x116B6 || uc == 0x116B7 || uc == 0x116B8 || uc == 0x116B9 ||
      (0x116C0 <= uc && uc <= 0x116C9) || (0x11700 <= uc && uc <= 0x1171A) ||
      (0x1171D <= uc && uc <= 0x1171F) || (0x11720 <= uc && uc <= 0x11721) ||
      (0x11722 <= uc && uc <= 0x11725) || uc == 0x11726 ||
      (0x11727 <= uc && uc <= 0x1172B) || (0x11730 <= uc && uc <= 0x11739) ||
      (0x1173A <= uc && uc <= 0x1173B) || (0x1173C <= uc && uc <= 0x1173E) ||
      uc == 0x1173F || (0x11740 <= uc && uc <= 0x11746) ||
      (0x11800 <= uc && uc <= 0x1182B) || (0x1182C <= uc && uc <= 0x1182E) ||
      (0x1182F <= uc && uc <= 0x11837) || uc == 0x11838 ||
      (0x11839 <= uc && uc <= 0x1183A) || uc == 0x1183B ||
      (0x118A0 <= uc && uc <= 0x118DF) || (0x118E0 <= uc && uc <= 0x118E9) ||
      (0x118EA <= uc && uc <= 0x118F2) || uc == 0x118FF ||
      (0x11900 <= uc && uc <= 0x11906) || uc == 0x11909 ||
      (0x1190C <= uc && uc <= 0x11913) || (0x11915 <= uc && uc <= 0x11916) ||
      (0x11918 <= uc && uc <= 0x1192F) || (0x11930 <= uc && uc <= 0x11935) ||
      (0x11937 <= uc && uc <= 0x11938) || (0x1193B <= uc && uc <= 0x1193C) ||
      uc == 0x1193D || uc == 0x1193E || uc == 0x1193F || uc == 0x11940 ||
      uc == 0x11941 || uc == 0x11942 || uc == 0x11943 ||
      (0x11944 <= uc && uc <= 0x11946) || (0x11950 <= uc && uc <= 0x11959) ||
      (0x119A0 <= uc && uc <= 0x119A7) || (0x119AA <= uc && uc <= 0x119D0) ||
      (0x119D1 <= uc && uc <= 0x119D3) || (0x119D4 <= uc && uc <= 0x119D7) ||
      (0x119DA <= uc && uc <= 0x119DB) || (0x119DC <= uc && uc <= 0x119DF) ||
      uc == 0x119E0 || uc == 0x119E1 || uc == 0x119E2 || uc == 0x119E3 ||
      uc == 0x119E4 || uc == 0x11A00 || (0x11A01 <= uc && uc <= 0x11A0A) ||
      (0x11A0B <= uc && uc <= 0x11A32) || (0x11A33 <= uc && uc <= 0x11A38) ||
      uc == 0x11A39 || uc == 0x11A3A || (0x11A3B <= uc && uc <= 0x11A3E) ||
      (0x11A3F <= uc && uc <= 0x11A46) || uc == 0x11A47 || uc == 0x11A50 ||
      (0x11A51 <= uc && uc <= 0x11A56) || (0x11A57 <= uc && uc <= 0x11A58) ||
      (0x11A59 <= uc && uc <= 0x11A5B) || (0x11A5C <= uc && uc <= 0x11A89) ||
      (0x11A8A <= uc && uc <= 0x11A96) || uc == 0x11A97 ||
      (0x11A98 <= uc && uc <= 0x11A99) || (0x11A9A <= uc && uc <= 0x11A9C) ||
      uc == 0x11A9D || (0x11A9E <= uc && uc <= 0x11AA2) ||
      (0x11AB0 <= uc && uc <= 0x11ABF) || (0x11AC0 <= uc && uc <= 0x11AF8) ||
      (0x11B00 <= uc && uc <= 0x11B09) || (0x11C00 <= uc && uc <= 0x11C08) ||
      (0x11C0A <= uc && uc <= 0x11C2E) || uc == 0x11C2F ||
      (0x11C30 <= uc && uc <= 0x11C36) || (0x11C38 <= uc && uc <= 0x11C3D) ||
      uc == 0x11C3E || uc == 0x11C3F || uc == 0x11C40 ||
      (0x11C41 <= uc && uc <= 0x11C45) || (0x11C50 <= uc && uc <= 0x11C59) ||
      (0x11C5A <= uc && uc <= 0x11C6C) || (0x11C70 <= uc && uc <= 0x11C71) ||
      (0x11C72 <= uc && uc <= 0x11C8F) || (0x11C92 <= uc && uc <= 0x11CA7) ||
      uc == 0x11CA9 || (0x11CAA <= uc && uc <= 0x11CB0) || uc == 0x11CB1 ||
      (0x11CB2 <= uc && uc <= 0x11CB3) || uc == 0x11CB4 ||
      (0x11CB5 <= uc && uc <= 0x11CB6) || (0x11D00 <= uc && uc <= 0x11D06) ||
      (0x11D08 <= uc && uc <= 0x11D09) || (0x11D0B <= uc && uc <= 0x11D30) ||
      (0x11D31 <= uc && uc <= 0x11D36) || uc == 0x11D3A ||
      (0x11D3C <= uc && uc <= 0x11D3D) || (0x11D3F <= uc && uc <= 0x11D45) ||
      uc == 0x11D46 || uc == 0x11D47 || (0x11D50 <= uc && uc <= 0x11D59) ||
      (0x11D60 <= uc && uc <= 0x11D65) || (0x11D67 <= uc && uc <= 0x11D68) ||
      (0x11D6A <= uc && uc <= 0x11D89) || (0x11D8A <= uc && uc <= 0x11D8E) ||
      (0x11D90 <= uc && uc <= 0x11D91) || (0x11D93 <= uc && uc <= 0x11D94) ||
      uc == 0x11D95 || uc == 0x11D96 || uc == 0x11D97 || uc == 0x11D98 ||
      (0x11DA0 <= uc && uc <= 0x11DA9) || (0x11EE0 <= uc && uc <= 0x11EF2) ||
      (0x11EF3 <= uc && uc <= 0x11EF4) || (0x11EF5 <= uc && uc <= 0x11EF6) ||
      (0x11EF7 <= uc && uc <= 0x11EF8) || (0x11F00 <= uc && uc <= 0x11F01) ||
      uc == 0x11F02 || uc == 0x11F03 || (0x11F04 <= uc && uc <= 0x11F10) ||
      (0x11F12 <= uc && uc <= 0x11F33) || (0x11F34 <= uc && uc <= 0x11F35) ||
      (0x11F36 <= uc && uc <= 0x11F3A) || (0x11F3E <= uc && uc <= 0x11F3F) ||
      uc == 0x11F40 || uc == 0x11F41 || uc == 0x11F42 ||
      (0x11F43 <= uc && uc <= 0x11F4F) || (0x11F50 <= uc && uc <= 0x11F59) ||
      uc == 0x11FB0 || (0x11FC0 <= uc && uc <= 0x11FD4) ||
      (0x11FD5 <= uc && uc <= 0x11FDC) || (0x11FDD <= uc && uc <= 0x11FE0) ||
      (0x11FE1 <= uc && uc <= 0x11FF1) || uc == 0x11FFF ||
      (0x12000 <= uc && uc <= 0x12399) || (0x12400 <= uc && uc <= 0x1246E) ||
      (0x12470 <= uc && uc <= 0x12474) || (0x12480 <= uc && uc <= 0x12543) ||
      (0x12F90 <= uc && uc <= 0x12FF0) || (0x12FF1 <= uc && uc <= 0x12FF2) ||
      (0x13000 <= uc && uc <= 0x1342F) || (0x13430 <= uc && uc <= 0x1343F) ||
      uc == 0x13440 || (0x13441 <= uc && uc <= 0x13446) ||
      (0x13447 <= uc && uc <= 0x13455) || (0x14400 <= uc && uc <= 0x14646) ||
      (0x16800 <= uc && uc <= 0x16A38) || (0x16A40 <= uc && uc <= 0x16A5E) ||
      (0x16A60 <= uc && uc <= 0x16A69) || (0x16A6E <= uc && uc <= 0x16A6F) ||
      (0x16A70 <= uc && uc <= 0x16ABE) || (0x16AC0 <= uc && uc <= 0x16AC9) ||
      (0x16AD0 <= uc && uc <= 0x16AED) || (0x16AF0 <= uc && uc <= 0x16AF4) ||
      uc == 0x16AF5 || (0x16B00 <= uc && uc <= 0x16B2F) ||
      (0x16B30 <= uc && uc <= 0x16B36) || (0x16B37 <= uc && uc <= 0x16B3B) ||
      (0x16B3C <= uc && uc <= 0x16B3F) || (0x16B40 <= uc && uc <= 0x16B43) ||
      uc == 0x16B44 || uc == 0x16B45 || (0x16B50 <= uc && uc <= 0x16B59) ||
      (0x16B5B <= uc && uc <= 0x16B61) || (0x16B63 <= uc && uc <= 0x16B77) ||
      (0x16B7D <= uc && uc <= 0x16B8F) || (0x16E40 <= uc && uc <= 0x16E7F) ||
      (0x16E80 <= uc && uc <= 0x16E96) || (0x16E97 <= uc && uc <= 0x16E9A) ||
      (0x16F00 <= uc && uc <= 0x16F4A) || uc == 0x16F4F || uc == 0x16F50 ||
      (0x16F51 <= uc && uc <= 0x16F87) || (0x16F8F <= uc && uc <= 0x16F92) ||
      (0x16F93 <= uc && uc <= 0x16F9F) || (0x1BC00 <= uc && uc <= 0x1BC6A) ||
      (0x1BC70 <= uc && uc <= 0x1BC7C) || (0x1BC80 <= uc && uc <= 0x1BC88) ||
      (0x1BC90 <= uc && uc <= 0x1BC99) || uc == 0x1BC9C ||
      (0x1BC9D <= uc && uc <= 0x1BC9E) || uc == 0x1BC9F ||
      (0x1BCA0 <= uc && uc <= 0x1BCA3) || (0x1CF00 <= uc && uc <= 0x1CF2D) ||
      (0x1CF30 <= uc && uc <= 0x1CF46) || (0x1CF50 <= uc && uc <= 0x1CFC3) ||
      (0x1D000 <= uc && uc <= 0x1D0F5) || (0x1D100 <= uc && uc <= 0x1D126) ||
      (0x1D129 <= uc && uc <= 0x1D164) || (0x1D165 <= uc && uc <= 0x1D166) ||
      (0x1D167 <= uc && uc <= 0x1D169) || (0x1D16A <= uc && uc <= 0x1D16C) ||
      (0x1D16D <= uc && uc <= 0x1D172) || (0x1D173 <= uc && uc <= 0x1D17A) ||
      (0x1D17B <= uc && uc <= 0x1D182) || (0x1D183 <= uc && uc <= 0x1D184) ||
      (0x1D185 <= uc && uc <= 0x1D18B) || (0x1D18C <= uc && uc <= 0x1D1A9) ||
      (0x1D1AA <= uc && uc <= 0x1D1AD) || (0x1D1AE <= uc && uc <= 0x1D1EA) ||
      (0x1D200 <= uc && uc <= 0x1D241) || (0x1D242 <= uc && uc <= 0x1D244) ||
      uc == 0x1D245 || (0x1D2C0 <= uc && uc <= 0x1D2D3) ||
      (0x1D2E0 <= uc && uc <= 0x1D2F3) || (0x1D300 <= uc && uc <= 0x1D356) ||
      (0x1D360 <= uc && uc <= 0x1D378) || (0x1D400 <= uc && uc <= 0x1D454) ||
      (0x1D456 <= uc && uc <= 0x1D49C) || (0x1D49E <= uc && uc <= 0x1D49F) ||
      uc == 0x1D4A2 || (0x1D4A5 <= uc && uc <= 0x1D4A6) ||
      (0x1D4A9 <= uc && uc <= 0x1D4AC) || (0x1D4AE <= uc && uc <= 0x1D4B9) ||
      uc == 0x1D4BB || (0x1D4BD <= uc && uc <= 0x1D4C3) ||
      (0x1D4C5 <= uc && uc <= 0x1D505) || (0x1D507 <= uc && uc <= 0x1D50A) ||
      (0x1D50D <= uc && uc <= 0x1D514) || (0x1D516 <= uc && uc <= 0x1D51C) ||
      (0x1D51E <= uc && uc <= 0x1D539) || (0x1D53B <= uc && uc <= 0x1D53E) ||
      (0x1D540 <= uc && uc <= 0x1D544) || uc == 0x1D546 ||
      (0x1D54A <= uc && uc <= 0x1D550) || (0x1D552 <= uc && uc <= 0x1D6A5) ||
      (0x1D6A8 <= uc && uc <= 0x1D6C0) || uc == 0x1D6C1 ||
      (0x1D6C2 <= uc && uc <= 0x1D6DA) || uc == 0x1D6DB ||
      (0x1D6DC <= uc && uc <= 0x1D6FA) || uc == 0x1D6FB ||
      (0x1D6FC <= uc && uc <= 0x1D714) || uc == 0x1D715 ||
      (0x1D716 <= uc && uc <= 0x1D734) || uc == 0x1D735 ||
      (0x1D736 <= uc && uc <= 0x1D74E) || uc == 0x1D74F ||
      (0x1D750 <= uc && uc <= 0x1D76E) || uc == 0x1D76F ||
      (0x1D770 <= uc && uc <= 0x1D788) || uc == 0x1D789 ||
      (0x1D78A <= uc && uc <= 0x1D7A8) || uc == 0x1D7A9 ||
      (0x1D7AA <= uc && uc <= 0x1D7C2) || uc == 0x1D7C3 ||
      (0x1D7C4 <= uc && uc <= 0x1D7CB) || (0x1D7CE <= uc && uc <= 0x1D7FF) ||
      (0x1D800 <= uc && uc <= 0x1D9FF) || (0x1DA00 <= uc && uc <= 0x1DA36) ||
      (0x1DA37 <= uc && uc <= 0x1DA3A) || (0x1DA3B <= uc && uc <= 0x1DA6C) ||
      (0x1DA6D <= uc && uc <= 0x1DA74) || uc == 0x1DA75 ||
      (0x1DA76 <= uc && uc <= 0x1DA83) || uc == 0x1DA84 ||
      (0x1DA85 <= uc && uc <= 0x1DA86) || (0x1DA87 <= uc && uc <= 0x1DA8B) ||
      (0x1DA9B <= uc && uc <= 0x1DA9F) || (0x1DAA1 <= uc && uc <= 0x1DAAF) ||
      (0x1DF00 <= uc && uc <= 0x1DF09) || uc == 0x1DF0A ||
      (0x1DF0B <= uc && uc <= 0x1DF1E) || (0x1DF25 <= uc && uc <= 0x1DF2A) ||
      (0x1E000 <= uc && uc <= 0x1E006) || (0x1E008 <= uc && uc <= 0x1E018) ||
      (0x1E01B <= uc && uc <= 0x1E021) || (0x1E023 <= uc && uc <= 0x1E024) ||
      (0x1E026 <= uc && uc <= 0x1E02A) || (0x1E030 <= uc && uc <= 0x1E06D) ||
      uc == 0x1E08F || (0x1E100 <= uc && uc <= 0x1E12C) ||
      (0x1E130 <= uc && uc <= 0x1E136) || (0x1E137 <= uc && uc <= 0x1E13D) ||
      (0x1E140 <= uc && uc <= 0x1E149) || uc == 0x1E14E || uc == 0x1E14F ||
      (0x1E290 <= uc && uc <= 0x1E2AD) || uc == 0x1E2AE ||
      (0x1E2C0 <= uc && uc <= 0x1E2EB) || (0x1E2EC <= uc && uc <= 0x1E2EF) ||
      (0x1E2F0 <= uc && uc <= 0x1E2F9) || uc == 0x1E2FF ||
      (0x1E4D0 <= uc && uc <= 0x1E4EA) || uc == 0x1E4EB ||
      (0x1E4EC <= uc && uc <= 0x1E4EF) || (0x1E4F0 <= uc && uc <= 0x1E4F9) ||
      (0x1E7E0 <= uc && uc <= 0x1E7E6) || (0x1E7E8 <= uc && uc <= 0x1E7EB) ||
      (0x1E7ED <= uc && uc <= 0x1E7EE) || (0x1E7F0 <= uc && uc <= 0x1E7FE) ||
      (0x1E800 <= uc && uc <= 0x1E8C4) || (0x1E8C7 <= uc && uc <= 0x1E8CF) ||
      (0x1E8D0 <= uc && uc <= 0x1E8D6) || (0x1E900 <= uc && uc <= 0x1E943) ||
      (0x1E944 <= uc && uc <= 0x1E94A) || uc == 0x1E94B ||
      (0x1E950 <= uc && uc <= 0x1E959) || (0x1E95E <= uc && uc <= 0x1E95F) ||
      (0x1EC71 <= uc && uc <= 0x1ECAB) || uc == 0x1ECAC ||
      (0x1ECAD <= uc && uc <= 0x1ECAF) || uc == 0x1ECB0 ||
      (0x1ECB1 <= uc && uc <= 0x1ECB4) || (0x1ED01 <= uc && uc <= 0x1ED2D) ||
      uc == 0x1ED2E || (0x1ED2F <= uc && uc <= 0x1ED3D) ||
      (0x1EE00 <= uc && uc <= 0x1EE03) || (0x1EE05 <= uc && uc <= 0x1EE1F) ||
      (0x1EE21 <= uc && uc <= 0x1EE22) || uc == 0x1EE24 || uc == 0x1EE27 ||
      (0x1EE29 <= uc && uc <= 0x1EE32) || (0x1EE34 <= uc && uc <= 0x1EE37) ||
      uc == 0x1EE39 || uc == 0x1EE3B || uc == 0x1EE42 || uc == 0x1EE47 ||
      uc == 0x1EE49 || uc == 0x1EE4B || (0x1EE4D <= uc && uc <= 0x1EE4F) ||
      (0x1EE51 <= uc && uc <= 0x1EE52) || uc == 0x1EE54 || uc == 0x1EE57 ||
      uc == 0x1EE59 || uc == 0x1EE5B || uc == 0x1EE5D || uc == 0x1EE5F ||
      (0x1EE61 <= uc && uc <= 0x1EE62) || uc == 0x1EE64 ||
      (0x1EE67 <= uc && uc <= 0x1EE6A) || (0x1EE6C <= uc && uc <= 0x1EE72) ||
      (0x1EE74 <= uc && uc <= 0x1EE77) || (0x1EE79 <= uc && uc <= 0x1EE7C) ||
      uc == 0x1EE7E || (0x1EE80 <= uc && uc <= 0x1EE89) ||
      (0x1EE8B <= uc && uc <= 0x1EE9B) || (0x1EEA1 <= uc && uc <= 0x1EEA3) ||
      (0x1EEA5 <= uc && uc <= 0x1EEA9) || (0x1EEAB <= uc && uc <= 0x1EEBB) ||
      (0x1EEF0 <= uc && uc <= 0x1EEF1) || (0x1F000 <= uc && uc <= 0x1F003) ||
      (0x1F005 <= uc && uc <= 0x1F02B) || (0x1F030 <= uc && uc <= 0x1F093) ||
      (0x1F0A0 <= uc && uc <= 0x1F0AE) || (0x1F0B1 <= uc && uc <= 0x1F0BF) ||
      (0x1F0C1 <= uc && uc <= 0x1F0CE) || (0x1F0D1 <= uc && uc <= 0x1F0F5) ||
      (0x1F10B <= uc && uc <= 0x1F10C) || (0x1F10D <= uc && uc <= 0x1F10F) ||
      (0x1F12E <= uc && uc <= 0x1F12F) || (0x1F16A <= uc && uc <= 0x1F16F) ||
      uc == 0x1F1AD || (0x1F1E6 <= uc && uc <= 0x1F1FF) ||
      (0x1F321 <= uc && uc <= 0x1F32C) || uc == 0x1F336 || uc == 0x1F37D ||
      (0x1F394 <= uc && uc <= 0x1F39F) || (0x1F3CB <= uc && uc <= 0x1F3CE) ||
      (0x1F3D4 <= uc && uc <= 0x1F3DF) || (0x1F3F1 <= uc && uc <= 0x1F3F3) ||
      (0x1F3F5 <= uc && uc <= 0x1F3F7) || uc == 0x1F43F || uc == 0x1F441 ||
      (0x1F4FD <= uc && uc <= 0x1F4FE) || (0x1F53E <= uc && uc <= 0x1F54A) ||
      uc == 0x1F54F || (0x1F568 <= uc && uc <= 0x1F579) ||
      (0x1F57B <= uc && uc <= 0x1F594) || (0x1F597 <= uc && uc <= 0x1F5A3) ||
      (0x1F5A5 <= uc && uc <= 0x1F5FA) || (0x1F650 <= uc && uc <= 0x1F67F) ||
      (0x1F6C6 <= uc && uc <= 0x1F6CB) || (0x1F6CD <= uc && uc <= 0x1F6CF) ||
      (0x1F6D3 <= uc && uc <= 0x1F6D4) || (0x1F6E0 <= uc && uc <= 0x1F6EA) ||
      (0x1F6F0 <= uc && uc <= 0x1F6F3) || (0x1F700 <= uc && uc <= 0x1F776) ||
      (0x1F77B <= uc && uc <= 0x1F77F) || (0x1F780 <= uc && uc <= 0x1F7D9) ||
      (0x1F800 <= uc && uc <= 0x1F80B) || (0x1F810 <= uc && uc <= 0x1F847) ||
      (0x1F850 <= uc && uc <= 0x1F859) || (0x1F860 <= uc && uc <= 0x1F887) ||
      (0x1F890 <= uc && uc <= 0x1F8AD) || (0x1F8B0 <= uc && uc <= 0x1F8B1) ||
      (0x1F900 <= uc && uc <= 0x1F90B) || uc == 0x1F93B || uc == 0x1F946 ||
      (0x1FA00 <= uc && uc <= 0x1FA53) || (0x1FA60 <= uc && uc <= 0x1FA6D) ||
      (0x1FB00 <= uc && uc <= 0x1FB92) || (0x1FB94 <= uc && uc <= 0x1FBCA) ||
      (0x1FBF0 <= uc && uc <= 0x1FBF9) || uc == 0xE0001 ||
      (0xE0020 <= uc && uc <= 0xE007F) || false) {
    return N;
  }
  if (uc == 0x0020 || (0x0021 <= uc && uc <= 0x0023) || uc == 0x0024 ||
      (0x0025 <= uc && uc <= 0x0027) || uc == 0x0028 || uc == 0x0029 ||
      uc == 0x002A || uc == 0x002B || uc == 0x002C || uc == 0x002D ||
      (0x002E <= uc && uc <= 0x002F) || (0x0030 <= uc && uc <= 0x0039) ||
      (0x003A <= uc && uc <= 0x003B) || (0x003C <= uc && uc <= 0x003E) ||
      (0x003F <= uc && uc <= 0x0040) || (0x0041 <= uc && uc <= 0x005A) ||
      uc == 0x005B || uc == 0x005C || uc == 0x005D || uc == 0x005E ||
      uc == 0x005F || uc == 0x0060 || (0x0061 <= uc && uc <= 0x007A) ||
      uc == 0x007B || uc == 0x007C || uc == 0x007D || uc == 0x007E ||
      (0x00A2 <= uc && uc <= 0x00A3) || uc == 0x00A5 || uc == 0x00A6 ||
      uc == 0x00AC || uc == 0x00AF || uc == 0x27E6 || uc == 0x27E7 ||
      uc == 0x27E8 || uc == 0x27E9 || uc == 0x27EA || uc == 0x27EB ||
      uc == 0x27EC || uc == 0x27ED || uc == 0x2985 || uc == 0x2986 || false) {
    return Na;
  }
  if ((0x1100 <= uc && uc <= 0x115F) || (0x231A <= uc && uc <= 0x231B) ||
      uc == 0x2329 || uc == 0x232A || (0x23E9 <= uc && uc <= 0x23EC) ||
      uc == 0x23F0 || uc == 0x23F3 || (0x25FD <= uc && uc <= 0x25FE) ||
      (0x2614 <= uc && uc <= 0x2615) || (0x2648 <= uc && uc <= 0x2653) ||
      uc == 0x267F || uc == 0x2693 || uc == 0x26A1 ||
      (0x26AA <= uc && uc <= 0x26AB) || (0x26BD <= uc && uc <= 0x26BE) ||
      (0x26C4 <= uc && uc <= 0x26C5) || uc == 0x26CE || uc == 0x26D4 ||
      uc == 0x26EA || (0x26F2 <= uc && uc <= 0x26F3) || uc == 0x26F5 ||
      uc == 0x26FA || uc == 0x26FD || uc == 0x2705 ||
      (0x270A <= uc && uc <= 0x270B) || uc == 0x2728 || uc == 0x274C ||
      uc == 0x274E || (0x2753 <= uc && uc <= 0x2755) || uc == 0x2757 ||
      (0x2795 <= uc && uc <= 0x2797) || uc == 0x27B0 || uc == 0x27BF ||
      (0x2B1B <= uc && uc <= 0x2B1C) || uc == 0x2B50 || uc == 0x2B55 ||
      (0x2E80 <= uc && uc <= 0x2E99) || (0x2E9B <= uc && uc <= 0x2EF3) ||
      (0x2F00 <= uc && uc <= 0x2FD5) || (0x2FF0 <= uc && uc <= 0x2FFF) ||
      (0x3001 <= uc && uc <= 0x3003) || uc == 0x3004 || uc == 0x3005 ||
      uc == 0x3006 || uc == 0x3007 || uc == 0x3008 || uc == 0x3009 ||
      uc == 0x300A || uc == 0x300B || uc == 0x300C || uc == 0x300D ||
      uc == 0x300E || uc == 0x300F || uc == 0x3010 || uc == 0x3011 ||
      (0x3012 <= uc && uc <= 0x3013) || uc == 0x3014 || uc == 0x3015 ||
      uc == 0x3016 || uc == 0x3017 || uc == 0x3018 || uc == 0x3019 ||
      uc == 0x301A || uc == 0x301B || uc == 0x301C || uc == 0x301D ||
      (0x301E <= uc && uc <= 0x301F) || uc == 0x3020 ||
      (0x3021 <= uc && uc <= 0x3029) || (0x302A <= uc && uc <= 0x302D) ||
      (0x302E <= uc && uc <= 0x302F) || uc == 0x3030 ||
      (0x3031 <= uc && uc <= 0x3035) || (0x3036 <= uc && uc <= 0x3037) ||
      (0x3038 <= uc && uc <= 0x303A) || uc == 0x303B || uc == 0x303C ||
      uc == 0x303D || uc == 0x303E || (0x3041 <= uc && uc <= 0x3096) ||
      (0x3099 <= uc && uc <= 0x309A) || (0x309B <= uc && uc <= 0x309C) ||
      (0x309D <= uc && uc <= 0x309E) || uc == 0x309F || uc == 0x30A0 ||
      (0x30A1 <= uc && uc <= 0x30FA) || uc == 0x30FB ||
      (0x30FC <= uc && uc <= 0x30FE) || uc == 0x30FF ||
      (0x3105 <= uc && uc <= 0x312F) || (0x3131 <= uc && uc <= 0x318E) ||
      (0x3190 <= uc && uc <= 0x3191) || (0x3192 <= uc && uc <= 0x3195) ||
      (0x3196 <= uc && uc <= 0x319F) || (0x31A0 <= uc && uc <= 0x31BF) ||
      (0x31C0 <= uc && uc <= 0x31E3) || uc == 0x31EF ||
      (0x31F0 <= uc && uc <= 0x31FF) || (0x3200 <= uc && uc <= 0x321E) ||
      (0x3220 <= uc && uc <= 0x3229) || (0x322A <= uc && uc <= 0x3247) ||
      uc == 0x3250 || (0x3251 <= uc && uc <= 0x325F) ||
      (0x3260 <= uc && uc <= 0x327F) || (0x3280 <= uc && uc <= 0x3289) ||
      (0x328A <= uc && uc <= 0x32B0) || (0x32B1 <= uc && uc <= 0x32BF) ||
      (0x32C0 <= uc && uc <= 0x32FF) || (0x3300 <= uc && uc <= 0x33FF) ||
      (0x3400 <= uc && uc <= 0x4DBF) || (0x4E00 <= uc && uc <= 0x9FFF) ||
      (0xA000 <= uc && uc <= 0xA014) || uc == 0xA015 ||
      (0xA016 <= uc && uc <= 0xA48C) || (0xA490 <= uc && uc <= 0xA4C6) ||
      (0xA960 <= uc && uc <= 0xA97C) || (0xAC00 <= uc && uc <= 0xD7A3) ||
      (0xF900 <= uc && uc <= 0xFA6D) || (0xFA6E <= uc && uc <= 0xFA6F) ||
      (0xFA70 <= uc && uc <= 0xFAD9) || (0xFADA <= uc && uc <= 0xFAFF) ||
      (0xFE10 <= uc && uc <= 0xFE16) || uc == 0xFE17 || uc == 0xFE18 ||
      uc == 0xFE19 || uc == 0xFE30 || (0xFE31 <= uc && uc <= 0xFE32) ||
      (0xFE33 <= uc && uc <= 0xFE34) || uc == 0xFE35 || uc == 0xFE36 ||
      uc == 0xFE37 || uc == 0xFE38 || uc == 0xFE39 || uc == 0xFE3A ||
      uc == 0xFE3B || uc == 0xFE3C || uc == 0xFE3D || uc == 0xFE3E ||
      uc == 0xFE3F || uc == 0xFE40 || uc == 0xFE41 || uc == 0xFE42 ||
      uc == 0xFE43 || uc == 0xFE44 || (0xFE45 <= uc && uc <= 0xFE46) ||
      uc == 0xFE47 || uc == 0xFE48 || (0xFE49 <= uc && uc <= 0xFE4C) ||
      (0xFE4D <= uc && uc <= 0xFE4F) || (0xFE50 <= uc && uc <= 0xFE52) ||
      (0xFE54 <= uc && uc <= 0xFE57) || uc == 0xFE58 || uc == 0xFE59 ||
      uc == 0xFE5A || uc == 0xFE5B || uc == 0xFE5C || uc == 0xFE5D ||
      uc == 0xFE5E || (0xFE5F <= uc && uc <= 0xFE61) || uc == 0xFE62 ||
      uc == 0xFE63 || (0xFE64 <= uc && uc <= 0xFE66) || uc == 0xFE68 ||
      uc == 0xFE69 || (0xFE6A <= uc && uc <= 0xFE6B) ||
      (0x16FE0 <= uc && uc <= 0x16FE1) || uc == 0x16FE2 || uc == 0x16FE3 ||
      uc == 0x16FE4 || (0x16FF0 <= uc && uc <= 0x16FF1) ||
      (0x17000 <= uc && uc <= 0x187F7) || (0x18800 <= uc && uc <= 0x18AFF) ||
      (0x18B00 <= uc && uc <= 0x18CD5) || (0x18D00 <= uc && uc <= 0x18D08) ||
      (0x1AFF0 <= uc && uc <= 0x1AFF3) || (0x1AFF5 <= uc && uc <= 0x1AFFB) ||
      (0x1AFFD <= uc && uc <= 0x1AFFE) || (0x1B000 <= uc && uc <= 0x1B0FF) ||
      (0x1B100 <= uc && uc <= 0x1B122) || uc == 0x1B132 ||
      (0x1B150 <= uc && uc <= 0x1B152) || uc == 0x1B155 ||
      (0x1B164 <= uc && uc <= 0x1B167) || (0x1B170 <= uc && uc <= 0x1B2FB) ||
      uc == 0x1F004 || uc == 0x1F0CF || uc == 0x1F18E ||
      (0x1F191 <= uc && uc <= 0x1F19A) || (0x1F200 <= uc && uc <= 0x1F202) ||
      (0x1F210 <= uc && uc <= 0x1F23B) || (0x1F240 <= uc && uc <= 0x1F248) ||
      (0x1F250 <= uc && uc <= 0x1F251) || (0x1F260 <= uc && uc <= 0x1F265) ||
      (0x1F300 <= uc && uc <= 0x1F320) || (0x1F32D <= uc && uc <= 0x1F335) ||
      (0x1F337 <= uc && uc <= 0x1F37C) || (0x1F37E <= uc && uc <= 0x1F393) ||
      (0x1F3A0 <= uc && uc <= 0x1F3CA) || (0x1F3CF <= uc && uc <= 0x1F3D3) ||
      (0x1F3E0 <= uc && uc <= 0x1F3F0) || uc == 0x1F3F4 ||
      (0x1F3F8 <= uc && uc <= 0x1F3FA) || (0x1F3FB <= uc && uc <= 0x1F3FF) ||
      (0x1F400 <= uc && uc <= 0x1F43E) || uc == 0x1F440 ||
      (0x1F442 <= uc && uc <= 0x1F4FC) || (0x1F4FF <= uc && uc <= 0x1F53D) ||
      (0x1F54B <= uc && uc <= 0x1F54E) || (0x1F550 <= uc && uc <= 0x1F567) ||
      uc == 0x1F57A || (0x1F595 <= uc && uc <= 0x1F596) || uc == 0x1F5A4 ||
      (0x1F5FB <= uc && uc <= 0x1F5FF) || (0x1F600 <= uc && uc <= 0x1F64F) ||
      (0x1F680 <= uc && uc <= 0x1F6C5) || uc == 0x1F6CC ||
      (0x1F6D0 <= uc && uc <= 0x1F6D2) || (0x1F6D5 <= uc && uc <= 0x1F6D7) ||
      (0x1F6DC <= uc && uc <= 0x1F6DF) || (0x1F6EB <= uc && uc <= 0x1F6EC) ||
      (0x1F6F4 <= uc && uc <= 0x1F6FC) || (0x1F7E0 <= uc && uc <= 0x1F7EB) ||
      uc == 0x1F7F0 || (0x1F90C <= uc && uc <= 0x1F93A) ||
      (0x1F93C <= uc && uc <= 0x1F945) || (0x1F947 <= uc && uc <= 0x1F9FF) ||
      (0x1FA70 <= uc && uc <= 0x1FA7C) || (0x1FA80 <= uc && uc <= 0x1FA88) ||
      (0x1FA90 <= uc && uc <= 0x1FABD) || (0x1FABF <= uc && uc <= 0x1FAC5) ||
      (0x1FACE <= uc && uc <= 0x1FADB) || (0x1FAE0 <= uc && uc <= 0x1FAE8) ||
      (0x1FAF0 <= uc && uc <= 0x1FAF8) || (0x20000 <= uc && uc <= 0x2A6DF) ||
      (0x2A6E0 <= uc && uc <= 0x2A6FF) || (0x2A700 <= uc && uc <= 0x2B739) ||
      (0x2B73A <= uc && uc <= 0x2B73F) || (0x2B740 <= uc && uc <= 0x2B81D) ||
      (0x2B81E <= uc && uc <= 0x2B81F) || (0x2B820 <= uc && uc <= 0x2CEA1) ||
      (0x2CEA2 <= uc && uc <= 0x2CEAF) || (0x2CEB0 <= uc && uc <= 0x2EBE0) ||
      (0x2EBE1 <= uc && uc <= 0x2EBEF) || (0x2EBF0 <= uc && uc <= 0x2EE5D) ||
      (0x2EE5E <= uc && uc <= 0x2F7FF) || (0x2F800 <= uc && uc <= 0x2FA1D) ||
      (0x2FA1E <= uc && uc <= 0x2FA1F) || (0x2FA20 <= uc && uc <= 0x2FFFD) ||
      (0x30000 <= uc && uc <= 0x3134A) || (0x3134B <= uc && uc <= 0x3134F) ||
      (0x31350 <= uc && uc <= 0x323AF) || (0x323B0 <= uc && uc <= 0x3FFFD) ||
      false) {
    return W;
  }

  return UNK;
}
