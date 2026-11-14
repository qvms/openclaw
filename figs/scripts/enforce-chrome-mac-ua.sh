#!/usr/bin/env bash
# enforce-chrome-mac-ua.sh — O-scripts
# Law: every outbound HTTP User-Agent MUST be Chrome on Mac.
# Banned in any UA (case-insensitive): osmedeus, vigolium, nuclei, ffuf, httpx, amass,
#   katana, projectdiscovery, and other scanner/tool brands (see BANNED_RE).
#
# Usage:
#   source enforce-chrome-mac-ua.sh        # export UA env vars into this shell (no shell options changed)
#   ./enforce-chrome-mac-ua.sh export      # print export lines
#   ./enforce-chrome-mac-ua.sh print       # print bare UA
#   ./enforce-chrome-mac-ua.sh header      # print "User-Agent: ..."
#   ./enforce-chrome-mac-ua.sh check [UA]  # exit 0 if OK, 1 if banned/bad
#   ./enforce-chrome-mac-ua.sh audit PATH...   # list UA lines with banned brands / non-Chrome-Mac UA strings
#   ./enforce-chrome-mac-ua.sh rewrite PATH... # replace tool-branded UA strings in yaml/yml/sh in place
#
# Env override (optional): CHROME_MAC_UA='Mozilla/5.0 ...'  (still validated; banned tokens always fail)
# Strict mode (set -euo pipefail) is applied only when executed, never when sourced.

DEFAULT_UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'

BANNED_RE='osmedeus|vigolium|nuclei|ffuf|httpx|amass|katana|subfinder|naabu|projectdiscovery|burpsuite|zap[- ]?proxy|sqlmap|nikto|wpscan|dirbuster|gobuster|feroxbuster|masscan|nmap|zgrab|aquatone|gowitness|python-requests|curl/|wget/|go-http-client'

# Files that document the law itself are skipped by audit/rewrite.
SELF_SKIP='enforce-chrome-mac-ua.sh|ua-chrome-mac.yaml'

ua_value() { printf '%s' "${CHROME_MAC_UA:-$DEFAULT_UA}"; }
ua_header() { printf 'User-Agent: %s' "$(ua_value)"; }

ua_ok() {
  local u="${1:-$(ua_value)}"
  printf '%s' "$u" | grep -qiE 'Macintosh' || { echo "UA reject: not Macintosh: $u" >&2; return 1; }
  printf '%s' "$u" | grep -qiE 'Chrome/[0-9]' || { echo "UA reject: not Chrome: $u" >&2; return 1; }
  if printf '%s' "$u" | grep -qiE "$BANNED_RE"; then
    echo "UA reject: banned tool brand in UA: $u" >&2
    return 1
  fi
  return 0
}

do_export() {
  ua_ok || return 1
  local u; u="$(ua_value)"
  export HTTP_USER_AGENT="$u" USER_AGENT="$u" OSM_USER_AGENT="$u" CHROME_MAC_UA="$u"
}

cmd_export_print() {
  ua_ok || return 1
  local u; u="$(ua_value)"
  printf 'export HTTP_USER_AGENT=%q\n' "$u"
  printf 'export USER_AGENT=%q\n' "$u"
  printf 'export OSM_USER_AGENT=%q\n' "$u"
  printf 'export CHROME_MAC_UA=%q\n' "$u"
}

_files() {
  find "$@" -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.sh' -o -name '*.md' -o -name '*.json' -o -name '*.txt' -o -name '*.conf' \) \
    -print0 2>/dev/null
}

# A line is a UA violation when either:
#  (a) it holds a Mozilla/ UA string that carries a banned brand or a "(compatible; ...)" tool stub, or
#  (b) it names a user-agent key/header (User-Agent, user_agent, useragent, -A, --user-agent) AND a banned brand.
_viol_re_a="Mozilla/[0-9.]+ *\\([^)]*(compatible;|${BANNED_RE})"
_viol_re_b="(user[-_ ]?agent|--user-agent|useragent).*(${BANNED_RE})"

cmd_audit() {
  local found=0 f hits
  [[ $# -ge 1 ]] || { echo "usage: $0 audit PATH..." >&2; return 2; }
  while IFS= read -r -d '' f; do
    case "$(basename "$f")" in $(echo "$SELF_SKIP" | sed 's/|/|*/g;s/^/*/')) continue;; esac
    hits="$(grep -nEi "$_viol_re_a|$_viol_re_b" "$f" 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
      echo "BANNED_UA $f"
      printf '%s\n' "$hits" | head -20
      found=1
    fi
  done < <(_files "$@")
  [[ $found -eq 0 ]] && echo "audit OK: no tool-branded UA under: $*"
  return $found
}

cmd_rewrite() {
  local f ua n=0 before after
  ua_ok || return 1
  [[ $# -ge 1 ]] || { echo "usage: $0 rewrite PATH..." >&2; return 2; }
  ua="$(ua_value)"
  while IFS= read -r -d '' f; do
    case "$(basename "$f")" in enforce-chrome-mac-ua.sh|ua-chrome-mac.yaml) continue;; esac
    case "$f" in *.yaml|*.yml|*.sh) ;; *) continue;; esac
    grep -qEi "$_viol_re_a|$_viol_re_b" "$f" 2>/dev/null || continue
    before="$(cksum <"$f")"
    # Replace every Mozilla/x (…) UA string that has "compatible;" or a banned brand with the canonical UA.
    UA="$ua" BANNED="$BANNED_RE" perl -0pi -e '
      my $b = $ENV{BANNED};
      s{Mozilla/[0-9.]+ *\((?:[^)]*(?:compatible;|$b)[^)]*)\)(?:[^"\x27\n]*(?:$b)[^"\x27\n]*)?}{$ENV{UA}}gi;
    ' "$f"
    after="$(cksum <"$f")"
    if [[ "$before" != "$after" ]]; then
      echo "rewrote $f"; n=$((n+1))
    fi
    if grep -qEi "$_viol_re_a|$_viol_re_b" "$f" 2>/dev/null; then
      echo "manual $f (banned UA token remains; fix by hand)"
    fi
  done < <(_files "$@")
  echo "rewrite done: $n file(s) changed"
}

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

main() {
  set -euo pipefail
  local cmd="${1:-}"
  case "$cmd" in
    ""|source) do_export ;;
    export) cmd_export_print ;;
    print|ua) ua_ok; ua_value; printf '\n' ;;
    header) ua_ok; ua_header; printf '\n' ;;
    check) shift || true; ua_ok "${1:-$(ua_value)}" ;;
    audit) shift; cmd_audit "$@" ;;
    rewrite) shift; cmd_rewrite "$@" ;;
    -h|--help|help) usage ;;
    *) echo "unknown command: $cmd" >&2; usage >&2; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  do_export || true   # sourced: export only; never alter caller's shell options or exit it
else
  main "$@"
fi
