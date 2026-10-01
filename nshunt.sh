#!/bin/sh
grep -q "$(printf '\r')" "$0" && printf '%s\n' "ERROR: $0 has Windows line endings. Fix: tr -d '\\r' < $0 > /tmp/nshunt-fixed.sh ; sh /tmp/nshunt-fixed.sh" && exit 2
# nshunt.sh - quick NetScaler compromise hunt. Prints findings only.
#
# Usage:  sh nshunt.sh        (read-only; changes nothing on the box)
#
# The output is shown on screen and saved to ./results-nshunt.txt (another
# file: NSHUNT_OUT=/path/file). Only that file and a temp dir are written.
#
#   COMPROMISE  signs that the box was (or may have been) compromised
#   ATTEMPT     attack attempts found in the logs still on the box - an
#               attempt is NOT a success; only COMPROMISE findings are
#               signs of success
#   REVIEW      unusual, needs a human look - often legitimate
#
# Exit code: 0 = no findings, 1 = findings, 2 = scan incomplete (unreadable
# logs or a check that crashed) or the report could not be saved - never
# trust "no findings" with exit 2.

VERSION=1.5

# Save everything to the results file: run the script again as a child and
# copy its output to the screen and the file, keeping its exit code.
if [ -z "${NSHUNT_CHILD:-}" ]; then
	OUT=${NSHUNT_OUT:-./results-nshunt.txt}
	case "$OUT" in /*) ;; *) OUT=$(pwd)/${OUT#./} ;; esac
	if ( : > "$OUT" ) 2>/dev/null; then
		st=$(mktemp /tmp/nshunt-rc.XXXXXX) || exit 2
		{ NSHUNT_CHILD=1 sh "$0" "$@" 2>&1; echo $? > "$st"; } | tee "$OUT"
		tst=$?   # tee's status: the report file could not be written (disk full ...)
		rc=$(cat "$st"); rm -f "$st"
		if [ "$tst" -ne 0 ] || [ ! -s "$OUT" ]; then
			echo "ERROR: the report could not be saved to $OUT - copy the output above." >&2
			exit 2
		fi
		echo "Saved to: $OUT"
		exit "${rc:-2}"
	fi
	echo "NOTE: cannot write $OUT - output is shown on screen only." >&2
fi

R=${NSHUNT_ROOT:-}   # test hook: prefix for all paths
WEB="/var/netscaler/logon /var/netscaler/gui /netscaler/ns_gui /var/vpn"

T=$(mktemp -d /tmp/nshunt.XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
: > "$T/count"
# Every filesystem error lands here; any line means the scan is incomplete.
E="$T/scanerr"; : > "$E"

dirs() { for d in $1; do [ -d "$R$d" ] && printf '%s\n' "$R$d"; done; }
# when <file> -> "2020-01-11 16:05" (ls -T works on every NetScaler; stat may be missing)
when() { ls -ldT "$1" 2>/dev/null | awk '{ m = (index("JanFebMarAprMayJunJulAugSepOctNovDec", $6) + 2) / 3
	printf "%s-%02d-%02d %s\n", $9, m, $7, substr($8, 1, 5) }'; }
# shown <path>: the path for display, line breaks in names made visible
shown() { printf '%s' "$1" | tr '\n\r\t' '???'; }
# list: stdin paths -> "date  path"
list() { while IFS= read -r f; do printf '%s  %s\n' "$(when "$f")" "${f#$R}"; done | sort; }
# finding <level> <title> <file>: print only if the file has lines
finding() {
	[ -s "$3" ] || return 0
	echo "$1" >> "$T/count"
	echo ""
	echo "[$1] $2"
	sed 's/^/       /' "$3"
}
# Date helpers for awk programs: mins(y,m,d,h,mi) -> minutes since year 0 (UTC
# when the input is UTC), mon("Sep") -> 9, nowmins() -> current UTC time.
AWKTIME='
function dfc(y, m, d,   era, yoe, doy) { y -= (m <= 2); era = int(y / 400); yoe = y - era * 400
	doy = int((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5) + d - 1
	return era * 146097 + yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy }
function mins(y, m, d, h, mi) { return (dfc(y, m, d) * 24 + h) * 60 + mi }
function mon(s) { return (index("JanFebMarAprMayJunJulAugSepOctNovDec", s) + 2) / 3 }
'
NOW=$(date -u +%Y%m%d%H%M)

# alogs: every web access log (httpaccess.log, httpaccess-vpn.log, ...) and rotation, unzipped
alogs() {
	for f in "$R"/var/log/httpaccess*.log "$R"/var/log/httpaccess*.log.*; do
		[ -f "$f" ] || continue
		case "$f" in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac
	done 2>/dev/null
}
# logs [name]: every rotation of /var/log/<name> (default ns.log), unzipped
logs() {
	for f in "$R/var/log/${1:-ns.log}" "$R/var/log/${1:-ns.log}".*; do
		[ -f "$f" ] || continue
		case "$f" in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac
	done 2>/dev/null
}

echo "NetScaler quick hunt $VERSION - $(hostname) - $(date '+%Y-%m-%d %H:%M')"

# Running build: the booted firmware file (/flash/ns-14.1-73.37.nc) - the
# header of the saved ns.conf lags behind until "save ns config" after an
# upgrade, so it is only the fallback. The file's date is the install date.
KF=${NSHUNT_BOOTFILE:-}
[ -z "$KF" ] && [ -z "$R" ] && KF=$(sysctl -n kern.bootfile 2>/dev/null)
BUILD=$(printf '%s\n' "$KF" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+)\.([0-9]+).*/\1 \2 \3/p')
[ -z "$BUILD" ] && BUILD=$(head -1 "$R/flash/nsconfig/ns.conf" 2>/dev/null |
	sed -nE 's/^#NS([0-9]+\.[0-9]+) Build ([0-9]+)\.([0-9]+).*/\1 \2 \3/p')
FIXED=unknown; BINST=""
# last boot (UTC); NSHUNT_BOOTSEC is the test hook
bs=${NSHUNT_BOOTSEC:-}
[ -z "$bs" ] && [ -z "$R" ] && bs=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ sec = \([0-9]*\),.*/\1/p')
BOOTED=""; [ -n "$bs" ] && BOOTED="$(date -u -r "$bs" '+%Y-%m-%d %H:%M' 2>/dev/null) UTC"
[ "$BOOTED" = " UTC" ] && BOOTED=""
if [ -n "$BUILD" ]; then
	# shellcheck disable=SC2086
	set -- $BUILD; REL=$1; BMA=$2; BMI=$3
	ge() { [ "$BMA" -gt "$1" ] || { [ "$BMA" -eq "$1" ] && [ "$BMI" -ge "$2" ]; }; }
	# CTX697096: 14.1-73.37, 13.1-64.23 (released as 64.24), 13.1 FIPS/NDcPP
	# 13.1-37.279; 14.1 FIPS uses its own numbering; older releases get no fix
	case "$REL" in
	14.1) if [ "$BMA" -eq 37 ]; then FIXED=unknown; elif ge 73 37; then FIXED=yes; else FIXED=no; fi ;;
	13.1) if [ "$BMA" -eq 37 ]; then { ge 37 279 && FIXED=yes; } || FIXED=no
	      elif ge 64 23; then FIXED=yes; else FIXED=no; fi ;;
	*)    FIXED=no ;;
	esac
	# Install date in UTC (the attack times are UTC): the booted firmware file,
	# else the folder the upgrade unpacked this build into (build-14.1-73.37_nc_64)
	[ -n "$KF" ] && [ -f "$R$KF" ] && BINST=$(TZ=UTC0 when "$R$KF")
	if [ -z "$BINST" ]; then
		d=$(ls -dt "$R"/var/nsinstall/*"$REL-$BMA.$BMI"* 2>/dev/null | head -1)
		[ -n "$d" ] && BINST=$(TZ=UTC0 when "$d")
	fi
	[ -n "$BINST" ] && BINST="$BINST UTC"
	case "$FIXED" in
	yes) echo "Build: $REL-$BMA.$BMI - includes the fix for CVE-2026-88771/88772${BINST:+ (installed $BINST)}"
	     [ -n "$BOOTED" ] && echo "       running since the last boot, $BOOTED" ;;
	no)  echo "Build: $REL-$BMA.$BMI - VULNERABLE to CVE-2026-88771/88772 - upgrade now (fixed: 14.1-73.37, 13.1-64.24)" ;;
	*)   echo "Build: $REL-$BMA.$BMI - fix status unknown (FIPS numbering?) - compare with the Citrix bulletin CTX697096" ;;
	esac
else
	echo "Build: unknown - check with \"show ns version\" (fixed: 14.1-73.37, 13.1-64.24)"
fi

# A corrupt or unreadable log must not look like "no findings": test every
# log up front and report the scan as incomplete if any cannot be read.
: > "$T/badlogs"
for f in "$R"/var/log/ns.log "$R"/var/log/ns.log.* "$R"/var/log/messages "$R"/var/log/messages.* \
	"$R"/var/log/httpaccess*.log "$R"/var/log/httpaccess*.log.* "$R"/var/log/httperror*.log "$R"/var/log/httperror*.log.* \
	"$R"/var/log/sh.log "$R"/var/log/sh.log.* "$R"/var/log/bash.log "$R"/var/log/bash.log.*; do
	[ -f "$f" ] || continue
	case "$f" in
	*.gz) gzip -t "$f" 2>/dev/null || echo "${f#$R}" >> "$T/badlogs" ;;
	*)    [ -r "$f" ] || echo "${f#$R}" >> "$T/badlogs" ;;
	esac
done

# --- 1. CVE-2019-19781 ("Shitrix") bookmark / template files ---------------
(
	touch -t 202001100000 "$T/a"; touch -t 202002010000 "$T/b"
	: > "$T/f"; : > "$T/f2"
	if [ -d "$R/var/vpn/bookmark" ]; then
		# A glob, not find | read: NetScaler names some bookmark files
		# bm_prefix_<base64 of the user>, and that base64 can end in a line break.
		for f in "$R"/var/vpn/bookmark/*.xml "$R"/var/vpn/bookmark/*/*.xml; do
			[ -f "$f" ] || continue
			why=""
			case "${f##*/}" in pwnpzi*) why="exploit file name" ;; esac
			grep -q '\[%' "$f" 2>>"$E" && why="${why:+$why, }contains template code"
			# ls/find only know the modification time, not when a file was created
			inwave=""; [ -n "$(find "$f" -newer "$T/a" ! -newer "$T/b")" ] && inwave=1
			if grep -q '^<user username="[^"]*" */>$' "$f" 2>>"$E"; then kind="empty bookmark stub"
			else kind="contains bookmarks"; fi
			if [ -n "$why" ]; then
				printf '%s  %s  (%s)\n' "$(when "$f")" "$(shown "${f#$R}")" "$why" >> "$T/f"
			elif [ -n "$inwave" ]; then
				printf '%s  %s  (%s)\n' "$(when "$f")" "$(shown "${f#$R}")" "$kind" >> "$T/f2"
			fi
		done
		sort -o "$T/f" "$T/f"; sort -o "$T/f2" "$T/f2"
	fi
	[ -d "$R/netscaler/portal/templates" ] &&
		find "$R/netscaler/portal/templates" -type f -user nobody 2>>"$E" | list >> "$T/f"
	finding COMPROMISE "CVE-2019-19781 exploit files: this box was exploited (Jan 2020 wave)" "$T/f"
	finding REVIEW "Bookmarks last modified during the Jan 2020 exploitation wave - random names and empty stubs point to the exploit, real user names may be legit" "$T/f2"
) || { echo "[SKIPPED] check 1 (CVE-2019-19781 (Shitrix) bookmark / template files) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 2. Shell commands injected through the VPN login (2026 attacks) -------
(
	# Failed logins carry the client IP. The same payload is also logged as
	# "sending login req to aaad for <...>"; those lines have no IP but catch
	# attempts that never produced a LOGIN_FAILED line.
	logs | grep -E 'LOGIN_FAILED|sending login req to aaad for <' |
		grep -E 'pitboss|NSPPE[[:space:]]*(;|%3B)|missed too many heartbeats|`|\$\{IFS\}|%24%7BIFS|\$\(|\|[ ]*sh' |
	awk '{
		d = ""; if (match($0, /[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
			s = substr($0, RSTART, RLENGTH)
			d = substr(s, 7, 4) "-" substr(s, 1, 2) "-" substr(s, 4, 2) " " substr(s, 12, 5)
		}
		if (/LOGIN_FAILED/) {
			ip = "?"; if (match($0, /Client_ip [0-9a-fA-F.:]+/)) ip = substr($0, RSTART + 10, RLENGTH - 10)
			u = $0; sub(/.*LOGIN_FAILED [0-9]+ [0-9]+ : +User /, "", u); sub(/ - Client_ip.*/, "", u)
			lf[u] = 1; print ip "\t" d "\t" u
		} else {
			u = $0; sub(/.*sending login req to aaad for </, "", u); sub(/>, factor.*/, "", u)
			n++; ad[n] = d; au[n] = u
		}
	}
	END { for (i = 1; i <= n; i++) if (!(au[i] in lf)) print "no IP logged\t" ad[i] "\t" au[i] }' |
		sort -t "$(printf '\t')" -k2 > "$T/att"

	if [ -s "$T/att" ]; then
		# With a fixed build, mark attempts from before its install: only those
		# could have run (ISO dates compare as strings).
		inst=""; [ "$FIXED" = yes ] && inst=$(printf '%s' "$BINST" | cut -c1-16)
		awk -F '\t' -v inst="$inst" '
		!($1 in n) { order[++k] = $1; first[$1] = $2 }
		{ n[$1]++; last[$1] = $2; if (!seen[$1 SUBSEP $3]++) p[$1] = p[$1] "\n  tried: " substr($3, 1, 110)
		  if (inst != "" && $2 != "" && $2 < inst) before[$1] = 1 }
		END { for (i = 1; i <= k; i++) { ip = order[i]
			printf "%-16s %d attempt(s)  %s .. %s UTC%s%s\n", ip, n[ip], first[ip], last[ip],
				(before[ip] ? "  <- BEFORE the fixed build was installed" : ""), p[ip] } }' "$T/att" > "$T/f"
		: > "$T/injections"
		grep -q 'BEFORE the fixed build' "$T/f" && : > "$T/before-fix"

		# Files the attacker tried to create in web folders: do they exist now?
		cut -f3 "$T/att" | grep -oE '/(var/netscaler/(logon|gui)|netscaler/ns_gui|var/vpn)/[^] `;$|>"<'"'"'()[]+' |
			sort -u > "$T/drop"
		: > "$T/exists"; : > "$T/dl"; : > "$T/dlunk"
		if [ -s "$T/drop" ]; then
			# URL each file would be served under (logon -> /logon/..., GUI -> /...)
			sed -n -e 's|^/var/netscaler/logon/|/logon/|p' -e 's|^/netscaler/ns_gui/|/|p' \
				-e 's|^/var/netscaler/gui/|/|p' "$T/drop" > "$T/dropurl"
			# one pass over the access logs; only lines naming one of those URLs
			: > "$T/hits"
			[ -s "$T/dropurl" ] && alogs | grep -F -f "$T/dropurl" > "$T/hits"
			echo "Files the attacks tried to create:" >> "$T/f"
			while IFS= read -r p; do
				if [ -e "$R$p" ]; then
					echo "  EXISTS: $p" >> "$T/f"; echo "$(when "$R$p")  $p" >> "$T/exists"
				else
					echo "  not present now (never created, or removed since): $p" >> "$T/f"
				fi
				u=$(printf '%s\n' "$p" | sed -n -e 's|^/var/netscaler/logon/|/logon/|p' \
					-e 's|^/netscaler/ns_gui/|/|p' -e 's|^/var/netscaler/gui/|/|p')
				[ -n "$u" ] || continue
				# first attempt (UTC) whose payload names this file
				first=$(awk -F '\t' -v p="$p" 'index($3, p) && $2 != "" { print $2 }' "$T/att" | sort | head -1)
				# "GET /url HTTP/1.1" status size - count statuses. A 2xx only
				# counts if it came after the first attempt: the same name may
				# have been served long before (an old file, another admin).
				awk -v u="$u" -v first="$first" "$AWKTIME"'
					BEGIN { fa = -1; if (first != "") fa = mins(substr(first, 1, 4) + 0, substr(first, 6, 2) + 0,
						substr(first, 9, 2) + 0, substr(first, 12, 2) + 0, substr(first, 15, 2) + 0) }
					match($0, /"[A-Z]+ [^ "]+ [^"]*" [0-9]+ [0-9-]+/) {
						split(substr($0, RSTART, RLENGTH), a, " "); path = a[2]; sub(/\?.*/, "", path)
						if (path != u) next
						if (!(a[4] in n)) order[++k] = a[4]
						n[a[4]]++
						if (a[4] ~ /^2/) { d = ""; t = -1
							if (match($0, /\[[0-9]+\/[A-Za-z]+\/[0-9]+:[0-9]+:[0-9]+:[0-9]+ [-+][0-9]+\]/)) {
								d = substr($0, RSTART + 1, RLENGTH - 2); split(d, x, /[\/: ]/)
								off = substr(x[7], 2, 2) * 60 + substr(x[7], 4, 2); if (substr(x[7], 1, 1) == "-") off = -off
								if (mon(x[2]) >= 1) t = mins(x[3] + 0, mon(x[2]), x[1] + 0, x[4] + 0, x[5] + 0) - off
							}
							line = d "  " $1 "  status " a[4] ", " a[5] " bytes  " u
							if (fa < 0 || t < 0) print "UNK\t" line
							else if (t >= fa) print "DL\t" line
							else old++
						}
					}
					END { if (k) { s = ""; for (i = 1; i <= k; i++) s = s (i > 1 ? ", " : "") "status " order[i] " x" n[order[i]]
						print "SUM\t    web requests for " u ": " s (old ? " (" old " success(es) BEFORE the first attempt - not from this attack)" : "") }
						else print "SUM\t    no web requests for " u " in the access logs still on the box" }' "$T/hits" > "$T/req"
				awk 'sub(/^SUM\t/, "")' "$T/req" >> "$T/f"
				awk 'sub(/^DL\t/, "")' "$T/req" >> "$T/dl"
				awk 'sub(/^UNK\t/, "")' "$T/req" >> "$T/dlunk"
			done < "$T/drop"
		fi
		cut -f3 "$T/att" | grep -oE 'https?://[^ `;$|"<>'"'"'()]+|(^|[^0-9./])[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+[^ `;$|"<>'"'"'(){]*' |
			sed 's|^[^0-9h]||' | sort -u > "$T/url"
		if [ -s "$T/url" ]; then
			echo "Check firewall logs for connections from the NetScaler to:" >> "$T/f"
			sed 's/^/  /' "$T/url" >> "$T/f"
		fi
		# Everything else these IPs did on the web server (recon, downloads)
		cut -f1 "$T/att" | grep -vE '^(\?|no IP logged)$' | sort -u > "$T/ips"
		if [ -s "$T/ips" ]; then
			alogs | awk '
				NR == FNR { want[$1] = 1; order[++k] = $1; next }
				($1 in want) && match($0, /"[A-Z]+ [^ "]+ [^"]*" [0-9]+ [0-9-]+/) {
					split(substr($0, RSTART, RLENGTH), a, " "); ip = $1; st = a[4]; path = a[2]; sub(/\?.*/, "", path)
					n[ip]++; if (!((ip, st) in c)) sts[ip] = sts[ip] " " st; c[ip, st]++
					if (st ~ /^2/ && !((ip, path) in ok)) { ok[ip, path] = 1; if (m[ip]++ < 5) oks[ip] = oks[ip] "\n    " st " " path }
				}
				END { for (i = 1; i <= k; i++) { ip = order[i]; if (!n[ip]) continue
					j = split(substr(sts[ip], 2), L, " "); s = ""
					for (x = 1; x <= j; x++) s = s (x > 1 ? ", " : "") L[x] " x" c[ip, L[x]]
					printf "  %-16s %d request(s): %s%s%s\n", ip, n[ip], s, (m[ip] ? "\n    answered 2xx (login page loads and login posts are normal, anything else is not):" : ""), oks[ip]
					if (m[ip] > 5) printf "    ... %d more\n", m[ip] - 5 } }' "$T/ips" - > "$T/web"
			if [ -s "$T/web" ]; then
				echo "Web requests from these IPs (access logs still on the box):" >> "$T/f"
				cat "$T/web" >> "$T/f"
			fi
		fi
		finding ATTEMPT "Shell commands sent in the VPN login name (command injection)" "$T/f"
		finding COMPROMISE "A file the attackers tried to create EXISTS - the attack may have worked" "$T/exists"
		finding COMPROMISE "A file the attackers tried to create was served (2xx) AFTER the attempt - the attack probably worked; check size and client" "$T/dl"
		finding REVIEW "A file the attackers tried to create was served (2xx), but the times could not be compared - check whether it was after the attempt" "$T/dlunk"
	fi
) || { echo "[SKIPPED] check 2 (Shell commands injected through the VPN login (2026 attacks)) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 2b. Injected commands copied into /var/log/messages ------------------
(
	# The vulnerable daily check also reads /var/log/messages, so the payload
	# text lands there too. Admin CLI commands (shell_command=) are not attacks,
	# and copies of ns.log lines (some boxes log those here too) are in check 2.
	logs messages | grep -v 'shell_command=' | grep -v -E -- '-PPE-[0-9]+ : default ' |
		grep -E 'died[[:space:]]+NSPPE[[:space:]]*(;|%3B)|missed too many heartbeats[^"]*(;|%3B)|\$\{IFS\}|%24%7BIFS%7D' |
		cut -c1-200 > "$T/m"
	head -10 "$T/m" > "$T/f"
	n=$(wc -l < "$T/m" | tr -d ' '); [ "$n" -gt 10 ] && echo "... $((n - 10)) more" >> "$T/f"
	finding ATTEMPT "Injected commands in /var/log/messages (fake packet engine messages)" "$T/f"
) || { echo "[SKIPPED] check 2b (Injected commands in /var/log/messages) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 3. Blocked path-traversal probes carrying commands --------------------
(
	logs | grep 'Path traversal detected' | grep -iE 'curl|wget|%3b|;|\|' |
	awk '{ ip = "?"; if (match($0, /Source: [0-9a-fA-F.:]+:[0-9]+/)) { ip = substr($0, RSTART + 8, RLENGTH - 8); sub(/:[0-9]+$/, "", ip) }
		n[ip]++ } END { for (ip in n) printf "%-16s %d probe(s), blocked by the NetScaler\n", ip, n[ip] }' | sort > "$T/f"
	finding ATTEMPT "Path-traversal probes carrying commands (blocked)" "$T/f"
) || { echo "[SKIPPED] check 3 (Blocked path-traversal probes carrying commands) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 4. Web shells ---------------------------------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB")
	: > "$T/f"
	if [ $# -gt 0 ]; then
		find "$@" -type f \( -name '*.php' -o -name '*.php?' -o -name '*.phtml' -o -name '*.pl' \
			-o -name '*.py' -o -name '*.sh' \) ! -path '*/admin_ui/*' ! -name 'eula_upgrade.pl' 2>>"$E" | list > "$T/f"
		grep -rlIE '<\?(php|=)' "$@" 2>>"$E" | grep -v -e '/admin_ui/' -e '\.php$' | list >> "$T/f"
	fi
	# webshell calls where no PHP or scripts belong (renamed .ctxs.receiver copies)
	# shellcheck disable=SC2046
	set -- $(dirs "/var/netscaler/logon/LogonPoint/custom /var/vpn")
	[ $# -gt 0 ] && grep -rlE 'passthru[[:space:]]*\(|NSC_TASS' "$@" 2>>"$E" | list >> "$T/f"
	sort -u -o "$T/f" "$T/f"
	finding COMPROMISE "Script or PHP code in a web folder (possible web shell)" "$T/f"
) || { echo "[SKIPPED] check 4 (Web shells) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 5. Files the web server created outside the bookmark store ------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/var/netscaler/logon /var/netscaler/gui /netscaler/ns_gui")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f -user nobody 2>>"$E" | list > "$T/f"
	finding COMPROMISE "Files owned by 'nobody' in web folders (written by the web server)" "$T/f"
) || { echo "[SKIPPED] check 5 (Files the web server created outside the bookmark store) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 6. Hidden files in web folders ----------------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB")
	: > "$T/f"
	: > "$T/f2"
	if [ $# -gt 0 ]; then
		find "$@" -type f -name '.*' ! -path '*/admin_ui/*' ! -name '.ctxs.receiver' 2>>"$E" | list > "$T/f"
		# published web shell name (GreyNoise, CVE-2026-88771)
		find "$@" -name '.ctxs.receiver' 2>>"$E" | list > "$T/f2"
	fi
	finding COMPROMISE "Known web shell file .ctxs.receiver (2026 attacks)" "$T/f2"
	finding REVIEW "Hidden files in web folders" "$T/f"
) || { echo "[SKIPPED] check 6 (Hidden files in web folders) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 7. Credential stealers in login-page JavaScript / HTML ----------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/var/netscaler/logon /netscaler/ns_gui/vpn /var/netscaler/gui/vpn")
	: > "$T/f"
	if [ $# -gt 0 ]; then
		find "$@" -type f -name '*.js' ! -path '*/localization/*' ! -name 'strings*' ! -name '*culture*' 2>>"$E" |
		while IFS= read -r f; do
			# Whole file, not just the end: take every external URL with 300
			# characters of context and flag it only if a capture/send primitive
			# sits next to it. Stock Citrix code talks to localhost or relative
			# paths; libraries mention w3.org namespace URLs.
			# RS=\001 makes the whole file one record, so a call split over
			# several lines is still seen together with its URL.
			host=$(LC_ALL=C awk 'BEGIN { RS = "\001" } {
				rest = $0; off = 0
				while (match(rest, /https?:\/\/[A-Za-z0-9.-]+/)) {
					pos = off + RSTART; len = RLENGTH
					h = tolower(substr($0, pos, len)); sub(/^https?:\/\//, "", h)
					off = pos + len - 1; rest = substr($0, off + 1)
					if (h ~ /^(localhost|127\.0\.0\.1|(www\.)?w3\.org)$/) continue
					st = pos - 300; if (st < 1) st = 1
					ctx = tolower(substr($0, st, len + 600))
					if (ctx ~ /passw|atob\(|btoa\(|sendbeacon|new image|fetch\(|xmlhttprequest|\.src *=/) { print h; exit }
				}
			}' "$f" 2>>"$E")
			if [ -n "$host" ]; then
				printf '%s  %s  (sends data to %s - open the file and search for it)\n' "$(when "$f")" "${f#$R}" "$host"
			fi
		done > "$T/f"
		find "$@" -type f \( -name '*.html' -o -name '*.htm' \) \
			-exec grep -lE "<script[^>]+src=[\"']?https?://" {} + 2>>"$E" | list |
			sed 's/$/  (loads a script from an external site)/' >> "$T/f"
	fi
	finding REVIEW "Login page code that may steal passwords - open these files and look" "$T/f"
) || { echo "[SKIPPED] check 7 (Credential stealers in login-page JavaScript / HTML) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 8. Unknown setuid/setgid programs -------------------------------------
(
	: > "$T/f"
	# shellcheck disable=SC2046
	set -- $(dirs "/ /var /flash")
	[ $# -gt 0 ] && find "$@" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>>"$E" |
		sed "s|^$R||" | sort -u |
		grep -v -E '^/(bin|sbin|usr/bin|usr/sbin|usr/libexec|usr/local/bin|usr/local/sbin)/|^/netscaler/(ping6?|traceroute6?)$|^/var/configd_devno$|^/var/run/.*\.pid$' |
		while IFS= read -r f; do printf '%s  %s\n' "$(when "$R$f")" "$f"; done > "$T/f"
	finding COMPROMISE "Unknown setuid/setgid programs (possible root backdoor)" "$T/f"
) || { echo "[SKIPPED] check 8 (Unknown setuid/setgid programs) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 9. User crontabs ------------------------------------------------------
(
	: > "$T/f"
	[ -d "$R/var/cron/tabs" ] && find "$R/var/cron/tabs" -type f 2>>"$E" | list > "$T/f"
	# system crontab lines that download from anywhere but the box itself
	[ -f "$R/etc/crontab" ] && grep -nE 'curl|wget|fetch[[:space:]]' "$R/etc/crontab" 2>>"$E" | grep -v '^[0-9]*:[[:space:]]*#' |
		grep -vE '(curl|wget|fetch)[^|;&]*[[:space:]]"?(https?://)?(localhost|127\.0\.0\.1)([:/"[:space:]]|$)' |
		sed 's|^|/etc/crontab:|' >> "$T/f"
	finding REVIEW "Crontabs that run user jobs or downloads (attackers use these to come back)" "$T/f"
) || { echo "[SKIPPED] check 9 (User crontabs) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 10. Unknown programs in temp folders ----------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/tmp /var/tmp /var/nstmp")
	: > "$T/f"; : > "$T/f3"
	[ $# -gt 0 ] && find "$@" -type f \( -perm -0100 -o -name '*.so' -o -name '*.php' -o -name '*.pl' -o -name '*.py' \) 2>>"$E" |
		sed "s|^$R||" |
		grep -v -E '^/var/tmp/(Fortville_Silicom_Intel|Mellanox|par-[^/]*)/|^/var/tmp/sum$|^/var/tmp/ns_system_backup\.pl$|^/tmp/nshunt\.' |
		# NetScaler Console Security Advisory scan scripts
		grep -v -E '^/var/tmp/(CVE-[0-9]{4}-[0-9]+-detection|[a-z_]+_vulnerability_dete[t]?ction)\.py$' |
		while IFS= read -r f; do
			# Code run from a decoded payload or from web request input: a web
			# shell or loader. A bare eval()/exec() call alone proves neither.
			if grep -qE '(eval|exec|assert|system|shell_exec|passthru|popen)[[:space:]]*\([^)]*(base64_decode|b64decode|\$_(GET|POST|REQUEST|COOKIE|SERVER))|(base64_decode|b64decode)[[:space:]]*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)' "$R$f" 2>/dev/null; then
				printf '%s  %s\n' "$(when "$R$f")" "$f" >> "$T/f3"; continue
			fi
			# The admin GUI (CodeIgniter) logs to log-YYYY-MM-DD.php files that
			# start with a "no direct access" guard - a log, not a program.
			case "${f##*/}" in log-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].php)
				head -1 "$R$f" 2>/dev/null | grep -q "defined('BASEPATH')\|defined(\"BASEPATH\")\|defined('SYSPATH')" && continue ;;
			esac
			if grep -qE 'eval[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|base64_decode[[:space:]]*\(|b64decode[[:space:]]*\(' "$R$f" 2>/dev/null; then
				printf '%s  %s  (runs dynamic code - look at it)\n' "$(when "$R$f")" "$f"
			else
				printf '%s  %s\n' "$(when "$R$f")" "$f"
			fi
		done | sort |
		# many files with the same name pattern (dates, numbers): one line each
		awk '{ k = $3; gsub(/[0-9]/, "#", k); if (!(k in n)) { first[k] = $1 " " $2; order[++m] = k }
			line[k, ++n[k]] = $0; last[k] = $1 " " $2 }
			END { for (i = 1; i <= m; i++) { k = order[i]
				if (n[k] > 3) printf "%s .. %s  %s  (%d files)\n", first[k], last[k], k, n[k]
				else for (j = 1; j <= n[k]; j++) print line[k, j] } }' > "$T/f"
	finding REVIEW "Programs in temp folders" "$T/f"
	[ -f "$T/f3" ] && sort -o "$T/f3" "$T/f3"
	finding COMPROMISE "Scripts in temp folders that run decoded payloads or web request input (loader / web shell)" "$T/f3"
) || { echo "[SKIPPED] check 10 (Unknown programs in temp folders) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 11. Web server config: PHP handlers and aliases (WHIPSHOT) ------------
(
	for c in /etc/httpd.conf /flash/nsconfig/httpd.conf /nsconfig/httpd.conf; do
		[ -f "$R$c" ] || continue
		# /nsconfig is normally a link to /flash/nsconfig: read it once
		[ "$c" = /nsconfig/httpd.conf ] && [ -f "$R/flash/nsconfig/httpd.conf" ] && continue
		awk -v f="$c" '
			# phponly(<files...> header): its pattern names only php/phtml
			# Accepted: <Files *.php>, <Files *.phtml> and regexes like \.php$,
			# \.(php|phtml)$, ^.+\.php5$ - nothing else (".*" is a catch-all).
			function phponly(s) {
				sub(/^[ \t]*<files(match)?[ \t]+/, "", s); sub(/>[ \t]*$/, "", s); gsub(/["\t ]/, "", s); sub(/^~/, "", s)
				if (s ~ /^\*\.(php[0-9]?|phtml)$/) return 1
				return s ~ /^\^?(\.[*+])?\\\.(php[0-9]?|phtml|\((php[0-9]?|phtml)(\|(php[0-9]?|phtml))*\))\$$/
			}
			{ l = tolower($0) }
			l ~ /^[ \t]*<(files|filesmatch|location|locationmatch|directory|directorymatch)[ \t>]/ { sect = l; head = $0; sub(/^[ \t]+/, "", head) }
			l ~ /^[ \t]*<\/(files|filesmatch|location|locationmatch|directory|directorymatch)>/ { sect = "" }
			# PHP handler for anything but .php/.phtml (e.g. .deb, .sig)
			l ~ /^[ \t]*add(handler|type)[ \t]+"?application\/x-httpd-php"?([ \t]|$)/ {
				for (i = 3; i <= NF; i++) { e = tolower($i); gsub(/"/, "", e)
					if (e !~ /^\.?(php[0-9]?|phtml)$/) { print "HIGH\t" f ":" NR ": " $0 "  (runs non-PHP files as PHP)"; break } }
			}
			# Safe only inside <Files>/<FilesMatch> that names nothing but PHP
			# extensions: "\.(php|deb)$" still leaves "deb" after removing them.
			l ~ /^[ \t]*(sethandler|forcetype)[ \t]+"?application\/x-httpd-php/ &&
			    !(sect ~ /^[ \t]*<files(match)?[ \t]/ && phponly(sect)) {
				print "HIGH\t" f ":" NR ": " $0 (sect != "" ? "  [in " head "]" : "") "  (runs non-PHP files as PHP)" }
			# Alias onto a hidden/.sig/.deb file, or a static URL (.ico, .css, ...)
			# onto a non-static file. Stock aliases (vpns/scripts/...) map like to like.
			# Also: a web asset path (/vpn/media/, /vpn/theme/, ...) mapped into a
			# client script folder (Mandiant). RewriteRule has flags after the target.
			l ~ /^[ \t]*(alias|aliasmatch|scriptalias|scriptaliasmatch|rewriterule)[ \t]/ && NF >= 3 {
				if (l ~ /^[ \t]*rewriterule/) { src = tolower($2); tgt = tolower($3) }
				else { src = tolower($(NF - 1)); tgt = tolower($NF) }
				gsub(/"/, "", src); gsub(/"/, "", tgt)
				if (src ~ /\/vpns?\/(media|theme|themes|images|help|logon|support)\// && tgt ~ /\/vpns?\/scripts\//) {
					print "HIGH\t" f ":" NR ": " $0 "  (maps a web asset path onto a script folder)"; next }
				# Stock config uses RewriteRule to force 404s (".../build.js.gz ->
				# /some-filepath-that-does-not-exist..."), so the static-to-other
				# rule below only applies to Alias lines.
				rw = (l ~ /^[ \t]*rewriterule/)
				base = tgt; sub(/.*\//, "", base)
				if (tgt ~ /\$[0-9]/) { suf = tgt; sub(/.*\$[0-9]+/, "", suf) } else suf = tgt
				if (base ~ /^\./ || suf ~ /\.(sig|deb)$/ ||
				    (!rw && src ~ /\.(ico|css|png|gif|js)/ && suf != "" && suf !~ /\.(ico|css|png|gif|js)$/ && (tgt !~ /\$[0-9]/ || suf ~ /^\./)))
					print "HIGH\t" f ":" NR ": " $0 "  (serves a disguised file)"
			}
			# Stock NetScaler ships "php_flag engine off" globally; the attackers
			# flip it to "on" (Unit 42). Inside a section it only needs a look.
			l ~ /^[ \t]*php_flag[ \t]+engine[ \t]+on/ {
				if (sect == "") print "HIGH\t" f ":" NR ": " $0 "  (PHP switched on for the whole web server - stock config has it off)"
				else print "CHECK\t" f ":" NR ": " $0 "  [in " head "]" }
			l ~ /#[ \t]*(require all denied|php_flag engine off)/ { print "CHECK\t" f ":" NR ": " $0 "  (protection commented out)" }
		' "$R$c" 2>>"$E"
	done > "$T/conf"
	# strip only the level prefix: config lines may contain tabs themselves
	awk 'sub(/^HIGH\t/, "")' "$T/conf" > "$T/f"
	awk 'sub(/^CHECK\t/, "")' "$T/conf" > "$T/f2"
	finding COMPROMISE "Web server config changed to run disguised files as PHP (web shell persistence)" "$T/f"
	finding REVIEW "Unusual PHP settings in the web server config - compare with another box on the same build" "$T/f2"
) || { echo "[SKIPPED] check 11 (Web server config) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 12. Startup scripts (run at every boot, survive a reboot) -------------
(
	for s in rc.netscaler nsbefore.sh nsafter.sh; do
		c=/flash/nsconfig/$s; [ -f "$R$c" ] || c=/nsconfig/$s; [ -f "$R$c" ] || continue
		grep -nE 'python|base64|b64decode|zlib|nohup|/tmp/\.|chmod[[:space:]]+[^ ]*s|chmod[[:space:]]+0?[2-7][0-7]{3}|x-httpd-php|Alias|curl |wget |fnoc\.dptth|php\.xedni|hs/pmt/rav/|relacsten|tnioPnogoL|gifnocsn' \
			"$R$c" 2>>"$E" | cut -c1-200 | sed "s|^|$c:|"
	done > "$T/f"
	# ns.conf and /etc/rc: only decoders, Python one-liners and reversed paths
	# (fnoc.dptth = httpd.conf, php.xedni = index.php, relacsten = netscaler,
	#  hs/pmt/rav/ = /var/tmp/sh, tnioPnogoL = LogonPoint, gifnocsn = nsconfig)
	for c in /flash/nsconfig/ns.conf /etc/rc; do
		[ -f "$R$c" ] || continue
		grep -niE 'python[0-9.]*[[:space:]]+-c|base64[.](b64|b85)decode|zlib[.]decompress|fnoc[.]dptth|php[.]xedni|relacsten|hs/pmt/rav/|tnioPnogoL|gifnocsn' \
			"$R$c" 2>>"$E" | cut -c1-200 | sed "s|^|$c:|"
	done >> "$T/f"
	finding REVIEW "Startup scripts run loaders, downloads or permission changes at boot" "$T/f"
) || { echo "[SKIPPED] check 12 (Startup scripts) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 13. Fake .deb packages in web folders (WHIPSHOT disguise) -------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f -name '*.deb' 2>>"$E" | while IFS= read -r f; do
		# every real .deb is an ar archive and starts with "!<arch>"
		[ "$(head -c 7 "$f" 2>>"$E")" = '!<arch>' ] || printf '%s\n' "$f"
	done | list > "$T/f"
	# Client-package and media folders hold compiled packages and images only
	# (Gotham, Mandiant): a script or PHP code there is a disguised web shell.
	: > "$T/f2"; : > "$T/pkgscript"
	# shellcheck disable=SC2046
	set -- $(dirs "/var/netscaler/gui/vpn/scripts/linux /netscaler/ns_gui/vpn/scripts/linux /var/netscaler/gui/vpns/scripts/vista /var/netscaler/gui/vpns/scripts/mac /netscaler/ns_gui/vpn/media")
	[ $# -gt 0 ] && find "$@" -maxdepth 1 -type f 2>>"$E" | while IFS= read -r f; do
		if [ "$(head -c 2 "$f" 2>>"$E")" = '#!' ] || grep -qIE '<\?|eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(' "$f" 2>>"$E"; then
			printf '%s\n' "$f" >&3
		elif [ "$(head -c 7 "$f" 2>>"$E")" != '!<arch>' ] && grep -qI . "$f" 2>>"$E"; then
			case "$f" in *.xml|*.js|*.css|*.html|*.htm|*.json|*.svg|*.map|*.txt) ;; *) printf '%s\n' "$f" ;; esac
		fi
	done 3>"$T/pkgscript" | list | sed 's/$/  (text file among client packages)/' > "$T/f2"
	list < "$T/pkgscript" | sed 's/$/  (script or PHP code in a client-package folder)/' >> "$T/f"
	# PHP appended to a real package still runs once a handler is set: look
	# inside binaries too (these markers do not occur in package data by chance)
	[ $# -gt 0 ] && find "$@" -maxdepth 1 -type f -name '*.deb' -exec env LC_ALL=C grep -la -e '<?php' -e 'shell_exec(' -e 'passthru(' {} + 2>>"$E" |
		list | sed 's/$/  (package with PHP code inside)/' >> "$T/f"
	# .sig files there: a PHP web shell name (nsgclient.sig, <hex>.sig)
	[ $# -gt 0 ] && find "$@" -maxdepth 1 -type f -name '*.sig' 2>>"$E" | list |
		sed 's/$/  (.sig file - WHIPSHOT is served as <name>.sig)/' >> "$T/f2"
	# theme folder: CSS and images are normal, PHP is not
	[ -d "$R/var/vpn/theme" ] && grep -rlE '<\?php|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(' "$R/var/vpn/theme" 2>>"$E" | list |
		sed 's/$/  (PHP code in the VPN theme folder)/' >> "$T/f"
	sort -u -o "$T/f" "$T/f"
	finding COMPROMISE "Disguised files in web folders (fake .deb packages, scripts among client packages)" "$T/f"
	finding REVIEW "Unexpected files among the client packages - packages and images are normal, anything else is not" "$T/f2"
) || { echo "[SKIPPED] check 13 (Fake .deb packages) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 14. Shells / interpreters with setuid or setgid -----------------------
(
	# Check 8 skips the system folders; a setuid /bin/sh hides there.
	# shellcheck disable=SC2046
	set -- $(dirs "/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /netscaler")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -maxdepth 1 -type f \( -perm -4000 -o -perm -2000 \) \
		\( -name sh -o -name bash -o -name dash -o -name csh -o -name tcsh -o -name ksh -o -name zsh \
		-o -name 'python*' -o -name 'perl*' -o -name 'php*' -o -name nc -o -name busybox \) 2>>"$E" | list > "$T/f"
	finding COMPROMISE "Shell or interpreter with setuid/setgid bit (anyone running it gets root)" "$T/f"
) || { echo "[SKIPPED] check 14 (setuid shells) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 15. SLAPSHOT tunnel (hidden Python backdoor) --------------------------
(
	for p in "$R"/tmp/.uxdport* "$R"/tmp/.uxdlock* "$R"/var/tmp/.uxdport* "$R"/var/tmp/.uxdlock*; do
		if [ -e "$p" ] || [ -L "$p" ]; then printf '%s  %s\n' "$(when "$p")" "${p#$R}"; fi
	done > "$T/f"
	# Running processes only on the live box, not on a copy.
	if [ -z "$R" ]; then
		ps axww -o user= -o pid= -o command= 2>>"$E" |
			awk '$3 ~ /(^|\/)python[0-9.]*$/ && ((/exec *\(/ && /b64decode|base64/) || /uxdport|uxdlock|UXD_IDLE_EXIT/)' |
			cut -c1-200 | sed 's/^/running: /' >> "$T/f"
		# payload process names (Gotham); match whole command tokens, not substrings
		ps axww -o user= -o pid= -o command= 2>>"$E" |
			awk '{ for (i = 3; i <= NF; i++) if ($i ~ /(^|\/)(lula|update_c[^\/]*\.pl|\.x)$/ || $i == "/var/1.py") { print; break } }' |
			cut -c1-200 | sed 's/^/running: /' >> "$T/f"
	fi
	finding COMPROMISE "SLAPSHOT tunnel or known payload process running" "$T/f"
) || { echo "[SKIPPED] check 15 (SLAPSHOT tunnel) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 16. Web access log: web shell URLs and base64 payloads ----------------
(
	# cap <file>: at most 15 lines, 200 chars each, plus how many were left out
	cap() { n=$(wc -l < "$1" | tr -d ' '); head -15 "$1" | cut -c1-200
		[ "$n" -gt 15 ] && echo "... $((n - 15)) more"; return 0; }
	# decode: base64 tokens on stdin -> "token... -> text" (skipped without openssl)
	decode() { command -v openssl >/dev/null 2>&1 || return 0
		sort -u | head -5 | while IFS= read -r x; do
			printf '  decoded %s... -> %s\n' "$(printf '%s' "$x" | cut -c1-16)" \
				"$(printf '%s' "$x" | openssl base64 -d -A 2>/dev/null | tr -c '[:print:]' '.' | cut -c1-400)"
		done; }

	# WHIPSHOT answers with a fake 404 that carries data: a 404 on a static
	# Gateway path with a multi-KB body means a web shell answered (Mandiant).
	# The stock NetScaler 404 page is a few hundred bytes.
	alogs | awk '
		match($0, /"[A-Z]+ [^ "]+ [^"]*" [0-9]+ [0-9]+/) {
			split(substr($0, RSTART, RLENGTH), a, " "); path = a[2]; sub(/\?.*/, "", path)
			if (path ~ /^\/vpns?\/(media|scripts|theme)\// && a[4] == 404 && a[5] + 0 > 5000) print }' |
		cut -c1-200 > "$T/big"
	head -10 "$T/big" > "$T/f"
	n=$(wc -l < "$T/big" | tr -d ' '); [ "$n" -gt 10 ] && echo "... $((n - 10)) more" >> "$T/f"
	finding COMPROMISE "Fake 404 answers with large bodies on Gateway media/script paths - a web shell answered" "$T/f"

	# nsginstaller64.deb is the real Linux client installer - normal downloads
	alogs | awk '/\/[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]+\.(ico|sig)/ ||
		/\/(nsgclient18|nsgser18|nsgsupport|nsgpackage64|nsgbuild|nsg64)\.deb/ ||
		(/\/nsginstaller[0-9]*\.deb/ && !/\/nsginstaller64\.deb/) ||
		/\/vpns?\/scripts\/linux\/[^ "?]*\.php/ || /"POST \/vpns?\/(media|scripts|theme)\//' > "$T/acc"
	cap "$T/acc" > "$T/f"
	[ -s "$T/f" ] && echo "(WHIPSHOT answers 404 - a 404 with a large response size means the shell ran)" >> "$T/f"
	finding ATTEMPT "Requests for web shell URLs (<hex>.ico / .sig, known web shell .deb names, POSTs to static paths) in the web access logs" "$T/f"

	alogs | grep -E '"INDEX:[A-Za-z0-9+/=]{8,}|"[A-Za-z0-9+/]{40,}={0,2}"[[:space:]]*$' > "$T/ua"
	cap "$T/ua" > "$T/f"
	grep -oE '"INDEX:[A-Za-z0-9+/=]{8,}|"[A-Za-z0-9+/]{40,}={0,2}"[[:space:]]*$' "$T/ua" |
		sed -e 's/^"INDEX://' -e 's/[" ]//g' | decode >> "$T/f"
	finding ATTEMPT "Base64 payloads sent as User-Agent (staging for the log-injection attack)" "$T/f"
) || { echo "[SKIPPED] check 16 (Web access log) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 17. Recent crashes -----------------------------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/var/core /var/crash")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f -mtime -14 ! -name bounds ! -name minfree 2>>"$E" | list > "$T/f"
	# packet engine crashes and failed DTLS handshakes (CVE-2026-88772, Mandiant)
	# Only lines from the last 14 days, sorted by time across all rotations.
	# ns.log lines carry a GMT date; syslog-only lines (messages) have no year.
	{ logs; logs messages; } | grep -v 'shell_command=' |
		grep -E 'ClientVersion DTLSv1\.0.*Handshake failure-Internal Error|exit with orphan rings|NOT restarting NSPPE|\(NSPPE-[0-9]+\),( jid [0-9]+,)? uid [0-9]+: exited on signal' |
		awk -v now="$NOW" "$AWKTIME"'
		BEGIN { Y = substr(now, 1, 4) + 0
			N = mins(Y, substr(now, 5, 2) + 0, substr(now, 7, 2) + 0, substr(now, 9, 2) + 0, substr(now, 11, 2) + 0) }
		{ t = -1
			if (match($0, /[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) { s = substr($0, RSTART, RLENGTH)
				t = mins(substr(s, 7, 4) + 0, substr(s, 1, 2) + 0, substr(s, 4, 2) + 0, substr(s, 12, 2) + 0, substr(s, 15, 2) + 0)
			} else if (mon($1) >= 1 && split($3, h, ":") >= 2) {
				t = mins(Y, mon($1), $2 + 0, h[1] + 0, h[2] + 0)
				if (t > N + 1440) t = mins(Y - 1, mon($1), $2 + 0, h[1] + 0, h[2] + 0)
			}
			if (t >= N - 14 * 1440) printf "%012d\t%s\n", t, $0 }' | sort -n | cut -f2- > "$T/crash"
	if [ -s "$T/crash" ]; then
		echo "$(wc -l < "$T/crash" | tr -d ' ') packet engine crash / DTLS failure log line(s) in the last 14 days, newest:" >> "$T/f"
		tail -3 "$T/crash" | cut -c1-200 | sed 's/^/  /' >> "$T/f"
	fi
	finding REVIEW "Packet engine crashes in the last 14 days (CVE-2026-88772 exploits crash it)" "$T/f"
	# A failed DTLS handshake followed within 10 minutes by a packet engine crash
	# is how successful CVE-2026-88772 exploitation looked (Mandiant). Both log
	# files start with the box's local syslog time, so compare that.
	awk -v now="$NOW" "$AWKTIME"'
		BEGIN { Y = substr(now, 1, 4) + 0
			N = mins(Y, substr(now, 5, 2) + 0, substr(now, 7, 2) + 0, substr(now, 9, 2) + 0, substr(now, 11, 2) + 0) }
		mon($1) >= 1 && split($3, h, ":") >= 2 {
			t = mins(Y, mon($1), $2 + 0, h[1] + 0, h[2] + 0); if (t > N + 1440) t = mins(Y - 1, mon($1), $2 + 0, h[1] + 0, h[2] + 0)
			printf "%012d\t%s\n", t, $0 }' "$T/crash" | sort -n |
		awk -F '\t' '
		{ t = $1 + 0; sub(/^[^\t]*\t/, "") }
		/Handshake failure-Internal Error/ { dt = t; dl = $0; next }
		dl != "" && t - dt <= 10 && !(dl in shown) { shown[dl] = 1; print dl; print "  -> " $0 }' | cut -c1-200 > "$T/f2"
	finding COMPROMISE "Failed DTLS handshake followed by a packet engine crash - likely successful CVE-2026-88772 exploitation" "$T/f2"
) || { echo "[SKIPPED] check 17 (Recent crashes) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 18. Known attacker IP addresses ---------------------------------------
(
	# Published by Mandiant, GreyNoise, Lupovis, Gotham Technology Group, Unit 42
	# and the CVE-2025/2026 advisories. 158.94.209.12 was also seen attacking.
	IPS='45\.61\.136\.143|66\.55\.159\.67|149\.248\.21\.5|144\.126\.221\.237|107\.172\.221\.57|172\.98\.178\.104|88\.218\.105\.254|149\.28\.121\.199|80\.240\.22\.229|78\.135\.96\.136|149\.28\.29\.221|89\.36\.231\.206|91\.195\.240\.123|143\.198\.7\.94|157\.254\.167\.12|149\.104\.78\.141|138\.199\.200\.90'
	IPS="$IPS|78\\.128\\.113\\.10|138\\.28\\.234\\.38|82\\.167\\.14\\.7|154\\.217\\.251\\.226|85\\.203\\.46\\.191|62\\.133\\.62\\.80|31\\.56\\.197\\.72|64\\.94\\.85\\.67|158\\.94\\.209\\.12|23\\.27\\.143\\.20|68\\.178\\.160\\.183|5\\.188\\.206\\.226|92\\.118\\.204\\.229"
	# Unit 42 (Aug-Sep 2026 pre-disclosure activity)
	IPS="$IPS|66\\.227\\.183\\.84|77\\.83\\.199\\.39|104\\.248\\.244\\.66|162\\.33\\.178\\.9|193\\.149\\.176\\.207|216\\.245\\.184\\.164|78\\.47\\.24\\.217|139\\.180\\.152\\.138|66\\.135\\.19\\.18|167\\.99\\.111\\.203|142\\.93\\.85\\.227|104\\.248\\.74\\.206|137\\.184\\.91\\.207"
	# Cloudflare WARP exits the actor used - shared with ordinary WARP users
	IPS="$IPS|104\\.28\\.215\\.13[67]|104\\.28\\.247\\.13[67]"
	{ logs; logs messages; alogs; } | grep -v 'shell_command=' | grep -oE "(^|[^0-9.])($IPS)([^0-9]|\$)" |
		grep -oE "$IPS" | sort | uniq -c |
		awk '{ printf "%-16s %d log line(s)%s\n", $2, $1, ($2 ~ /^104\.28\./ ? "  (Cloudflare WARP - also used by ordinary WARP users)" : "") }' > "$T/f"
	finding ATTEMPT "Known attacker IP addresses in the logs" "$T/f"
	: > "$T/f2"
	if [ -z "$R" ] && command -v netstat >/dev/null 2>&1; then
		netstat -an 2>>"$E" | grep -E "(^|[^0-9.])($IPS)[.:][0-9]+([^0-9]|\$)" > "$T/f2"
	fi
	finding COMPROMISE "Open network connection to a known attacker IP right now" "$T/f2"
) || { echo "[SKIPPED] check 18 (Known attacker IP addresses) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 19. Files written by the published exploit payloads -------------------
(
	: > "$T/f"
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB /var/netscaler/gui")
	{
		# fixed names (watchTowr PoC, Gotham, Deyda)
		for p in /.x /s /tmp/s /var/tmp/s /lula /tmp/lula /var/tmp/lula /var/1.py /var/tmp/sh \
			/var/netscaler/logon/insight-new.js /netscaler/ns_gui/admin_ui/e.txt /netscaler/ns_gui/admin_ui/log.txt \
			/var/netscaler/gui/admin_ui/e.txt /var/netscaler/gui/admin_ui/log.txt; do
			if [ -e "$R$p" ] || [ -L "$R$p" ]; then printf '%s\n' "$R$p"; fi
		done
		for d in / /tmp /var/tmp; do [ -d "$R$d" ] && find "$R$d" -maxdepth 1 -name 'update_c*.pl' 2>>"$E"; done
		for d in /var/tmp; do [ -d "$R$d" ] && find "$R$d" -maxdepth 1 \( -name 'wtw*' -o -name 'watchTowr*' -o -name 'boom*' \) 2>>"$E"; done
		[ -d "$R/var/netscaler/logon/themes" ] && find "$R/var/netscaler/logon/themes" -maxdepth 1 -name 'wt88771*' 2>>"$E"
		[ $# -gt 0 ] && find "$@" -type f \( -name 'nx_verify.html' -o -name 'c88771*' -o -name 'xua.html' \) 2>>"$E"
		# web shell .deb names (Mandiant, Unit 42); nsginstaller64.deb is the
		# real Linux client installer (its content is checked in check 13)
		for d in /var/netscaler/gui/vpn/scripts/linux /netscaler/ns_gui/vpn/scripts/linux; do
			[ -d "$R$d" ] && find "$R$d" -maxdepth 1 -type f \( \( -name 'nsginstaller*.deb' ! -name 'nsginstaller64.deb' \) -o -name 'nsgclient18.deb' \
				-o -name 'nsgser18.deb' -o -name 'nsgsupport.deb' -o -name 'nsgpackage64.deb' -o -name 'nsgbuild.deb' \
				-o -name 'nsg64.deb' \) 2>>"$E"
		done
	} | sort -u | while IFS= read -r f; do
		if [ -f "$f" ]; then printf '%s  %s  (%s bytes)\n' "$(when "$f")" "${f#$R}" "$(wc -c < "$f" | tr -d ' ')"
		else printf '%s  %s\n' "$(when "$f")" "${f#$R}"; fi
	done > "$T/f"
	# output of "id" written to a file = proof an injected command ran
	# shellcheck disable=SC2046
	set -- $(dirs "/tmp /var/tmp /var/vpn /var/netscaler/logon /netscaler/ns_gui/vpn")
	[ $# -gt 0 ] && find "$@" -maxdepth 3 -type f -size -2k -exec grep -lE 'uid=[0-9]+\([a-z_]+\) gid=|NX-CVE-OK' {} + 2>>"$E" |
		list | sed 's/$/  (contains output of the id command or an exploit canary)/' >> "$T/f"
	# An archive disguised as a web file: how a stolen /flash/nsconfig is staged
	# for download. grep -l finds files containing a gzip/zip/tar signature
	# anywhere (one pass); each hit is then checked at the right offset.
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB /var/netscaler/gui")
	[ $# -gt 0 ] && find "$@" -type f \( -name '*.html' -o -name '*.htm' -o -name '*.json' -o -name '*.css' \
		-o -name '*.js' -o -name '*.txt' \) -size +0 -exec env LC_ALL=C grep -l \
		-e "$(printf '\037\213')" -e "$(printf 'PK\003\004')" -e ustar {} + 2>>"$E" | while IFS= read -r f; do
		m=$(head -c 4 "$f" 2>>"$E" | od -An -tx1 | tr -d ' \n')
		t=""
		case "$m" in 1f8b*) t=gzip ;; 504b0304) t=zip ;; esac
		[ -z "$t" ] && [ "$(head -c 262 "$f" 2>>"$E" | tail -c 5)" = ustar ] && t=tar
		[ -n "$t" ] && printf '%s  %s  (%s archive, %s bytes - possible stolen config)\n' "$(when "$f")" "${f#$R}" "$t" "$(wc -c < "$f" | tr -d ' ')"
	done >> "$T/f"
	finding COMPROMISE "Files written by the published exploit payloads (do not open them on the box - they may hold config data)" "$T/f"
) || { echo "[SKIPPED] check 19 (Exploit payload files) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 20. Exploit, scanner and probe strings in the web logs ----------------
(
	# errlogs: every httperror*.log* rotation, unzipped
	# vlogs: the Gateway's own access log (httpaccess-vpn*), unzipped
	vlogs() { for f in "$R"/var/log/httpaccess-vpn*.log "$R"/var/log/httpaccess-vpn*.log.*; do
		[ -f "$f" ] || continue; case "$f" in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac; done 2>/dev/null; }
	errlogs() { for f in "$R"/var/log/httperror*.log "$R"/var/log/httperror*.log.*; do
		[ -f "$f" ] || continue; case "$f" in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac; done 2>/dev/null; }
	# sum <label> [noip]: stdin log lines -> "label: N line(s), status 404 x3" and
	# the client IPs. Web log lines start with the client IP, error log lines
	# say "client IP"; 127.0.0.x is the NetScaler itself forwarding the request.
	sum() { awk -v l="$1" -v noip="$2" '
		{ n++; ip = $1
		  if (ip !~ /^[0-9a-fA-F.:]+$/) { ip = ""; if (match($0, /client [0-9a-fA-F.:]+/)) { ip = substr($0, RSTART + 7, RLENGTH - 7); sub(/:[0-9]+$/, "", ip) } }
		  if (ip ~ /^127\./) { lo++; ip = "" }
		  if (ip != "" && !(ip in s)) { s[ip]; if (++k <= 5) ips = ips (k > 1 ? ", " : "") ip }
		  if (match($0, /" [0-9][0-9][0-9] /)) { st = substr($0, RSTART + 2, 3); if (!(st in c)) so[++m] = st; c[st]++ } }
		END { if (!n) exit
			printf "%s: %d line(s)", l, n
			if (m) { printf ", status"; for (i = 1; i <= m; i++) printf "%s %s x%d", (i > 1 ? "," : ""), so[i], c[so[i]] }
			printf "\n"
			if (!noip && k) printf "    from %s%s\n", ips, (k > 5 ? " and " k - 5 " more" : "")
			if (!noip && lo) printf "    %sfrom 127.0.0.x - the NetScaler itself, this log does not show the real client\n", (k ? "also " : "") }'; }
	{
		alogs | grep -E 'httpworkbench|NX-CVE-OK|nx_verify|wtw888|ns-88771-poc|PoCbit' | sum "exploit canary / scanner strings"
		alogs | grep -E 'LogonPoint/custom/receiver\.min(\.[0-9a-f]+)?\.css|\.ctxs\.receiver' | sum "requests for the .ctxs.receiver web shell"
		alogs | grep -E 'nsepa\.deb' | grep -E '" 206 1 ' | sum "1-byte nsepa.deb probes (HTTP 206)"
		{ alogs; errlogs; } | grep -E 'vp_probe_nonexist' | sum "recon marker vp_probe_nonexist"
		# Unit 42: any request for this page is anomalous
		alogs | grep -E '"[A-Z]+ /logon/LogonPoint/Authentication/GetUserName[ ?]' | sum "requests for Authentication/GetUserName"
		# version fingerprinting: the timestamp in rdx_en.json.gz gives away the
		# build; the admin GUI stylesheet has no business on the Gateway (vpn log)
		{ alogs | grep -E '"[A-Z]+ /vpn/js/rdx/core/lang/rdx_en\.json\.gz[ ?]'
		  vlogs | grep -E '"[A-Z]+ /admin_ui/common/css/ns/ui\.css[ ?]'; } | sum "version fingerprinting (rdx_en.json.gz, admin ui.css)"
		errlogs | grep -iE '/vpns?/scripts/[^ ]*\.(deb|sig|php)|/vpn/media/[^ ]*\.ico' | sum "errors for package/icon files (web shell use)"
		logs | grep -v 'shell_command=' | grep -E 'scanner-probe' | sum "scanner-probe login attempts" noip
	} > "$T/f"
	finding ATTEMPT "Exploit, scanner and probe strings in the logs (the box was found and tested)" "$T/f"
	# PHP errors raised while running a file with a non-PHP extension: PHP
	# executed it, so a handler for that extension was active (Mandiant).
	errlogs | grep -E 'PHP (Parse|Fatal|Warning|Notice|Deprecated)' |
		grep -iE ' in /[^ ]+\.(deb|sig|rpm|tgz|sh|so|dat|ico|png|gif|jpg|css|js|html?|txt)( |:|$)' | cut -c1-200 > "$T/pe"
	head -10 "$T/pe" > "$T/f4"
	n=$(wc -l < "$T/pe" | tr -d ' '); [ "$n" -gt 10 ] && echo "... $((n - 10)) more" >> "$T/f4"
	finding COMPROMISE "PHP ran a file with a non-PHP extension (web server error log)" "$T/f4"
	# The exploit canary served = the injected command ran (the file never
	# exists on a clean box). xua.html / c88771.json are timed against the
	# attempt in check 2 instead.
	alogs | grep -E '"[A-Z]+ [^ "]*/nx_verify\.html[ ?][^"]*" 2[0-9][0-9] ' | cut -c1-200 > "$T/can"
	head -10 "$T/can" > "$T/f3"
	n=$(wc -l < "$T/can" | tr -d ' '); [ "$n" -gt 10 ] && echo "... $((n - 10)) more" >> "$T/f3"
	finding COMPROMISE "The exploit canary nx_verify.html was served (2xx) - an injected command ran on this box" "$T/f3"
	alogs | grep -E 'HeadlessChrome' | sum "HeadlessChrome requests" > "$T/f2"
	finding REVIEW "Headless browser automation against the Gateway (may be your own monitoring)" "$T/f2"
) || { echo "[SKIPPED] check 20 (Exploit and probe strings) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 21. Shell history: LDAP credential and key theft ---------------------
(
	# The NetScaler logs every shell command. The patterns use [x] brackets so
	# this script's own logged commands never match them; searches run with
	# grep/awk (by you or other scanners) are skipped too.
	for f in "$R"/var/log/sh.log "$R"/var/log/sh.log.* "$R"/var/log/bash.log "$R"/var/log/bash.log.*; do
		[ -f "$f" ] || continue; case "$f" in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac
	done 2>/dev/null |
		grep -E 'l[d]apsearch|o[p]enssl[[:space:]]+s_client|/flash/nsconfig/k[e]ys|F[12][.]k[e]y|d[a]tabase[.]php|L[D]APTLS_REQCERT|c[p][[:space:]]+/usr/bin/bash|d[e]l[[:space:]]+/etc/auth[.]conf|h[t]tpd[[:space:]]+-k[[:space:]]+restart|c[h]mod[[:space:]]+[ug]?[+]s|n[s]shutdown[[:space:]]+-R|c[h]mod[[:space:]]+0?[4-7][0-7]{3}[[:space:]]+/bin/|k[i]ll[[:space:]]+-HUP[^"]*httpd' |
		grep -vE 'sh_command="[[:space:]]*(z?[ef]?grep|awk|sed|find|ls)[[:space:]]' | cut -c1-200 > "$T/h"
	n=$(wc -l < "$T/h" | tr -d ' ')
	{ [ "$n" -gt 10 ] && echo "... $((n - 10)) older line(s) not shown"; tail -10 "$T/h"; } > "$T/f"
	finding REVIEW "Shell commands that read credentials or keys, restart the web server, set setuid or force a reboot - check who ran them" "$T/f"
) || { echo "[SKIPPED] check 21 (Shell history) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 22. Admin accounts added, EPA checks removed (config-only payload) ----
(
	# A 2026 payload needs no web shell: through cli_script.sh it adds a system
	# user, sets every epaAction to -defaultEPAGroup NO_AUTH, unbinds the EPA
	# policies, dumps the running config to /var/tmp/c1.txt / c2.txt (and the
	# policy labels to labels.txt) and saves the config.
	: > "$T/f"; : > "$T/f2"
	# Running-config dumps left in the temp folders: they hold password hashes
	# and encrypted secrets. The payload's own names are COMPROMISE.
	for d in /tmp /var/tmp; do
		[ -d "$R$d" ] || continue
		find "$R$d" -maxdepth 1 -type f -size +0 2>>"$E" | while IFS= read -r f; do
			case "${f##*/}" in results-nshunt*|nshunt*) continue ;; esac
			grep -qE '^#NS[0-9]+\.[0-9]+ Build|^(add|set) (ns ip|ns config|system user|ns hostName) ' "$f" 2>/dev/null || continue
			case "${f##*/}" in
			c1.txt|c2.txt) printf '%s  %s  (running config dump - name used by the payload)\n' "$(when "$f")" "${f#$R}" ;;
			*) printf '%s  %s  (running config dump)\n' "$(when "$f")" "${f#$R}" >> "$T/f2" ;;
			esac
		done >> "$T/f"
	done
	if [ -s "$T/f" ] && [ -f "$R/var/tmp/labels.txt" ]; then
		printf '%s  %s  (policy label dump - written by the same payload)\n' "$(when "$R/var/tmp/labels.txt")" /var/tmp/labels.txt >> "$T/f"
	fi
	finding COMPROMISE "Config dumps written by the admin-account payload (c1.txt / c2.txt) - the config was read and changed" "$T/f"
	finding REVIEW "Running config copies in temp folders (they contain password hashes and secrets - delete when done)" "$T/f2"

	# Commands the NetScaler logged (ns.log CMD_EXECUTED): who added or bound
	# a system user, switched EPA failures to NO_AUTH or unbound EPA policies.
	logs | grep 'CMD_EXECUTED' |
		grep -E 'Command "(add system user|bind system user|set authentication epaAction[^"]*NO_AUTH|unbind (authentication vserver|authentication policylabel|vpn vserver) [^"]*-polic)' |
		awk '{ u = ""; if (match($0, /User [^ ]+/)) u = substr($0, RSTART + 5, RLENGTH - 5)
			ip = ""; if (match($0, /Remote_ip [0-9a-fA-F.:]+/)) ip = substr($0, RSTART + 10, RLENGTH - 10)
			d = ""; if (match($0, /[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
				s = substr($0, RSTART, RLENGTH); d = substr(s, 7, 4) "-" substr(s, 1, 2) "-" substr(s, 4, 2) " " substr(s, 12, 5) " UTC" }
			c = ""; if (match($0, /Command "[^"]*"/)) c = substr($0, RSTART + 9, RLENGTH - 10)
			printf "%s  by %s from %s%s: %s\n", d, (u != "" ? u : "?"), (ip != "" ? ip : "?"),
				(ip ~ /^127\./ ? " (the box itself - a script)" : ""), substr(c, 1, 120) }' > "$T/cmd"
	# The source decides: GUI, SSH and NITRO commands carry the admin PC's IP,
	# while a script on the box (cli_script.sh / nscli, like the payload) logs
	# 127.0.0.1. A script adding admins or letting EPA failures through is the
	# payload; the same commands from an admin PC only need confirming.
	grep -E '\(the box itself - a script\): ((add|bind) system user|.*NO_AUTH)' "$T/cmd" > "$T/cmdhi"
	grep -v -E '\(the box itself - a script\): ((add|bind) system user|.*NO_AUTH)' "$T/cmd" > "$T/cmdlo"
	for x in cmdhi cmdlo; do
		n=$(wc -l < "$T/$x" | tr -d ' ')
		{ [ "$n" -gt 15 ] && echo "... $((n - 15)) older line(s) not shown"; tail -15 "$T/$x"; } > "$T/$x.f"
	done
	finding COMPROMISE "A script on the box added admin accounts or let EPA failures through (a 2026 payload) - check the accounts below" "$T/cmdhi.f"
	finding REVIEW "Admin accounts created, EPA failures let through or EPA policies unbound - make sure the admin shown did this" "$T/cmdlo.f"

	# Saved config: EPA failures let through, and admin accounts that are not
	# in a copy from before the campaign. "save ns config" rotates only
	# ns.conf.0-4 (days); upgrades leave ns.conf.NS<old build>. Baseline: the
	# newest copy older than Aug 1 2026 (first recon Aug 21), else the oldest.
	: > "$T/f4"
	c=/flash/nsconfig/ns.conf
	if [ -f "$R$c" ]; then
		grep -nE '^(add|set) authentication epaAction [^ ]+ .*-defaultEPAGroup NO_AUTH' "$R$c" 2>>"$E" |
			cut -c1-160 | sed "s|^|$c:|; s|\$|  (EPA failures let through)|" >> "$T/f4"
		touch -t 202608010000 "$T/campaign"
		old=""
		for x in "$R$c".[0-9]* "$R$c".NS* "$R$c".bak*; do [ -f "$x" ] && printf '%s\n' "$x"; done > "$T/copies"
		if [ -s "$T/copies" ]; then
			# shellcheck disable=SC2046
			old=$(find $(cat "$T/copies") ! -newer "$T/campaign" 2>/dev/null | xargs ls -t 2>/dev/null | head -1)
			[ -z "$old" ] && old=$(xargs ls -t < "$T/copies" 2>/dev/null | tail -1)
		fi
		if [ -n "$old" ]; then
			grep -E '^add system user ' "$R$c" | awk '{ print $4 }' | sort -u > "$T/unow"
			grep -E '^add system user ' "$old" | awk '{ print $4 }' | sort -u > "$T/uold"
			comm -23 "$T/unow" "$T/uold" | while IFS= read -r u; do
				adm=$(grep -E "^bind system user $u (superuser|sysAdmin)" "$R$c" | awk '{ print $5 }' | head -1)
				echo "system user $u${adm:+ (bound to $adm)} - added after ${old#$R} ($(when "$old"))"
			done >> "$T/f4"
		fi
	fi
	finding REVIEW "Saved config: new system users or EPA failures let through - make sure an admin did this" "$T/f4"
) || { echo "[SKIPPED] check 22 (Admin accounts and EPA) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- Summary ---------------------------------------------------------------
nb=0; for f in "$R"/var/vpn/bookmark/*.xml "$R"/var/vpn/bookmark/*/*.xml; do [ -f "$f" ] && nb=$((nb + 1)); done
nl=$(ls "$R"/var/log/ns.log* 2>/dev/null | wc -l | tr -d ' ')
na=$(ls "$R"/var/log/httpaccess*.log* 2>/dev/null | wc -l | tr -d ' ')
old=$(ls "$R"/var/log/ns.log.*.gz 2>/dev/null | sort -t. -k3 -n | tail -1)
[ -n "$old" ] && old=$(gzip -dc "$old" 2>/dev/null | head -1 | awk '{ print $1, $2 }')
h=$(grep -c '^COMPROMISE$' "$T/count"); a=$(grep -c '^ATTEMPT$' "$T/count"); c=$(grep -c '^REVIEW$' "$T/count")
echo ""
if [ $((h + a + c)) -eq 0 ]; then
	echo "RESULT: no findings."
else
	echo "RESULT: $h COMPROMISE, $a ATTEMPT, $c REVIEW."
	echo "        (number of [COMPROMISE] / [ATTEMPT] / [REVIEW] blocks above - each block is one"
	echo "        kind of evidence, not an IP address or an attempt; see the lines in each block)"
fi
nbad=$(wc -l < "$T/badlogs" | tr -d ' '); sk=$(grep -c SKIPPED "$T/count")
awk '!seen[$0]++' "$E" > "$E.u"; mv "$E.u" "$E"; nerr=$(wc -l < "$E" | tr -d ' ')
echo "Scanned: $nb bookmark files in /var/vpn/bookmark, $nl ns.log files, $na web access log files ($nbad unreadable)."
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then
	echo "WARNING: scan INCOMPLETE - $nbad unreadable log(s), $sk crashed check(s), $nerr file system error(s)."
	[ "$nbad" -gt 0 ] && sed 's/^/  unreadable: /' "$T/badlogs"
	[ "$nerr" -gt 0 ] && head -5 "$E" | sed "${R:+s|$R||g;} s/^/  error: /"
fi
echo "Log checks only see logs still on the box${old:+ (back to $old)}; older attacks need your syslog server."
echo ""
echo "What this means:"
if [ "$h" -gt 0 ]; then
	echo "  COMPROMISE - signs that the box WAS compromised. Treat it as compromised:"
	echo "               do not reboot or upgrade yet, copy /var/log and the listed"
	echo "               files off the box, check the HA peer, then rebuild it and"
	echo "               change nsroot, LDAP/RADIUS bind passwords and certificate"
	echo "               keys (Citrix CTX694799)."
fi
if [ "$a" -gt 0 ]; then
	if [ "$h" -eq 0 ]; then
		echo "  ATTEMPT    - the box was attacked, but these are only ATTEMPTS found in"
		echo "               the logs. 0 COMPROMISE means no sign that any attempt"
		echo "               succeeded. Check your firewall logs for connections to the"
		echo "               listed IPs and URLs."
		case "$FIXED" in
		yes) if [ -f "$T/before-fix" ]; then
		         echo "               The box runs a fixed build, installed $BINST, but some"
		         echo "               attempts came BEFORE that (marked above) - those could have"
		         echo "               run. Check what they tried and whether it left traces."
		     elif [ -n "$BINST" ] && [ -f "$T/injections" ]; then
		         echo "               The box runs a fixed build, installed $BINST:"
		         echo "               the command injections above all came later and could"
		         echo "               not run commands."
		     elif [ -n "$BINST" ]; then
		         echo "               The box runs a fixed build, installed $BINST:"
		         echo "               attempts after that could not run commands."
		     else
		         echo "               The box runs a fixed build: attempts made after it was"
		         echo "               installed could not run commands; earlier ones could have."
		     fi ;;
		no)  echo "               The box runs a VULNERABLE build: an attempt may have worked"
		     echo "               without leaving a trace nshunt knows. Upgrade now." ;;
		*)   echo "               Make sure the box runs a fixed build (show ns version)." ;;
		esac
	else
		echo "  ATTEMPT    - attack attempts in the logs (on their own not proof of success);"
		echo "               together with the COMPROMISE findings they show when and"
		echo "               how the box was compromised."
	fi
fi
if [ "$c" -gt 0 ]; then
	echo "  REVIEW     - unusual things that are often legitimate. Have an admin look"
	echo "               at each one; if unsure, compare with the HA peer or another"
	echo "               box on the same build."
fi
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then
	echo "  INCOMPLETE - some logs or folders could not be read (see WARNING above), so"
	echo "               findings there may be missing. Fix that and run the scan again."
fi
if [ $((h + a + c)) -eq 0 ]; then
	echo "  None of the known signs of attack or compromise were found. That does not"
	echo "  prove the box is clean - only these specific indicators were checked."
fi
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then exit 2; fi
[ $((h + a + c)) -gt 0 ] && exit 1
exit 0
