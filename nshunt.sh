#!/bin/sh
grep -q "$(printf '\r')" "$0" && printf '%s\n' "ERROR: $0 has Windows line endings. Fix: tr -d '\\r' < $0 > /tmp/nshunt-fixed.sh ; sh /tmp/nshunt-fixed.sh" && exit 2
# nshunt.sh - quick NetScaler compromise hunt. Prints findings only.
#
# Usage:  sh nshunt.sh        (read-only; writes nothing except a temp dir)
#
#   HIGH    evidence that the box was (or may have been) compromised
#   ATTACK  exploitation attempts found in the logs still on the box
#   CHECK   unusual, needs a human look
#
# Exit code: 0 = no findings, 1 = findings, 2 = scan incomplete (unreadable
# logs or a check that crashed) - never trust "no findings" with exit 2.

R=${NSHUNT_ROOT:-}   # test hook: prefix for all paths
WEB="/var/netscaler/logon /var/netscaler/gui /netscaler/ns_gui /var/vpn"

T=$(mktemp -d /tmp/nshunt.XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
: > "$T/count"
# Every filesystem error lands here; any line means the scan is incomplete.
E="$T/scanerr"; : > "$E"

dirs() { for d in $1; do [ -d "$R$d" ] && printf '%s\n' "$R$d"; done; }
# when <file> -> "Jan 11 2020 16:05" (ls -T works on every NetScaler; stat may be missing)
when() { ls -ldT "$1" 2>/dev/null | awk '{ print $6, $7, $9, substr($8, 1, 5) }'; }
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
logs() {
	for f in "$R"/var/log/ns.log "$R"/var/log/ns.log.*; do
		[ -f "$f" ] || continue
		case "$f" in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac
	done 2>/dev/null
}

echo "NetScaler quick hunt - $(hostname) - $(date '+%Y-%m-%d %H:%M')"

# A corrupt or unreadable log must not look like "no findings": test every
# log up front and report the scan as incomplete if any cannot be read.
: > "$T/badlogs"
for f in "$R"/var/log/ns.log "$R"/var/log/ns.log.*; do
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
		find "$R/var/vpn/bookmark" -type f -name '*.xml' 2>>"$E" | while IFS= read -r f; do
			why=""
			case "${f##*/}" in pwnpzi*) why="exploit file name" ;; esac
			grep -q '\[%' "$f" 2>>"$E" && why="${why:+$why, }contains template code"
			# ls/find only know the modification time, not when a file was created
			inwave=""; [ -n "$(find "$f" -newer "$T/a" ! -newer "$T/b")" ] && inwave=1
			if grep -q '^<user username="[^"]*" */>$' "$f" 2>>"$E"; then kind="empty bookmark stub"
			else kind="contains bookmarks"; fi
			if [ -n "$why" ]; then
				printf '%s  %s  (%s)\n' "$(when "$f")" "${f#$R}" "$why" >> "$T/f"
			elif [ -n "$inwave" ]; then
				printf '%s  %s  (%s)\n' "$(when "$f")" "${f#$R}" "$kind" >> "$T/f2"
			fi
		done
		sort -o "$T/f" "$T/f"; sort -o "$T/f2" "$T/f2"
	fi
	[ -d "$R/netscaler/portal/templates" ] &&
		find "$R/netscaler/portal/templates" -type f -user nobody 2>>"$E" | list >> "$T/f"
	finding HIGH "CVE-2019-19781 exploit files: this box was exploited (Jan 2020 wave)" "$T/f"
	finding CHECK "Bookmarks last modified during the Jan 2020 exploitation wave - random names and empty stubs point to the exploit, real user names may be legit" "$T/f2"
) || { echo "[SKIPPED] check 1 (CVE-2019-19781 (Shitrix) bookmark / template files) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 2. Shell commands injected through the VPN login (2026 attacks) -------
(
	logs | grep 'LOGIN_FAILED' | grep -E 'pitboss|`|\$\{IFS\}|\$\(|\|[ ]*sh' |
	awk '{
		ip = "?"; if (match($0, /Client_ip [0-9a-fA-F.:]+/)) ip = substr($0, RSTART + 10, RLENGTH - 10)
		d = ""; if (match($0, /[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
			s = substr($0, RSTART, RLENGTH)
			d = substr(s, 7, 4) "-" substr(s, 1, 2) "-" substr(s, 4, 2) " " substr(s, 12, 5)
		}
		u = $0; sub(/.*LOGIN_FAILED [0-9]+ [0-9]+ : +User /, "", u); sub(/ - Client_ip.*/, "", u)
		print ip "\t" d "\t" u
	}' | sort -t "$(printf '\t')" -k2 > "$T/att"

	if [ -s "$T/att" ]; then
		awk -F '\t' '
		!($1 in n) { order[++k] = $1; first[$1] = $2 }
		{ n[$1]++; last[$1] = $2; if (!seen[$1 SUBSEP $3]++) p[$1] = p[$1] "\n  tried: " substr($3, 1, 110) }
		END { for (i = 1; i <= k; i++) { ip = order[i]
			printf "%-16s %d attempt(s)  %s .. %s UTC%s\n", ip, n[ip], first[ip], last[ip], p[ip] } }' "$T/att" > "$T/f"

		# Files the attacker tried to create in web folders: do they exist now?
		cut -f3 "$T/att" | grep -oE '/(var/netscaler/(logon|gui)|netscaler/ns_gui|var/vpn)/[^] `;$|>"<'"'"'()[]+' |
			sort -u > "$T/drop"
		: > "$T/exists"
		if [ -s "$T/drop" ]; then
			echo "Files the attacks tried to create:" >> "$T/f"
			while IFS= read -r p; do
				if [ -e "$R$p" ]; then
					echo "  EXISTS: $p" >> "$T/f"; echo "$(when "$R$p")  $p" >> "$T/exists"
				else
					echo "  not present now (never created, or removed since): $p" >> "$T/f"
				fi
			done < "$T/drop"
		fi
		cut -f3 "$T/att" | grep -oE 'https?://[^ `;$|"<>'"'"'()]+' | sort -u > "$T/url"
		if [ -s "$T/url" ]; then
			echo "Check firewall logs for connections from the NetScaler to:" >> "$T/f"
			sed 's/^/  /' "$T/url" >> "$T/f"
		fi
		finding ATTACK "Shell commands sent in the VPN login name (command injection)" "$T/f"
		finding HIGH "A file the attackers tried to create EXISTS - the attack may have worked" "$T/exists"
	fi
) || { echo "[SKIPPED] check 2 (Shell commands injected through the VPN login (2026 attacks)) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 3. Blocked path-traversal probes carrying commands --------------------
(
	logs | grep 'Path traversal detected' | grep -iE 'curl|wget|%3b|;|\|' |
	awk '{ ip = "?"; if (match($0, /Source: [0-9a-fA-F.:]+:[0-9]+/)) { ip = substr($0, RSTART + 8, RLENGTH - 8); sub(/:[0-9]+$/, "", ip) }
		n[ip]++ } END { for (ip in n) printf "%-16s %d probe(s), blocked by the NetScaler\n", ip, n[ip] }' | sort > "$T/f"
	finding ATTACK "Path-traversal probes carrying commands (blocked)" "$T/f"
) || { echo "[SKIPPED] check 3 (Blocked path-traversal probes carrying commands) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 4. Web shells ---------------------------------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB")
	: > "$T/f"
	if [ $# -gt 0 ]; then
		find "$@" -type f \( -name '*.php' -o -name '*.php?' -o -name '*.phtml' -o -name '*.pl' \
			-o -name '*.py' -o -name '*.sh' \) ! -path '*/admin_ui/*' ! -name 'eula_upgrade.pl' 2>>"$E" | list > "$T/f"
		grep -rlI '<?php' "$@" 2>>"$E" | grep -v -e '/admin_ui/' -e '\.php$' | list >> "$T/f"
	fi
	finding HIGH "Script or PHP code in a web folder (possible web shell)" "$T/f"
) || { echo "[SKIPPED] check 4 (Web shells) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 5. Files the web server created outside the bookmark store ------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/var/netscaler/logon /var/netscaler/gui /netscaler/ns_gui")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f -user nobody 2>>"$E" | list > "$T/f"
	finding HIGH "Files owned by 'nobody' in web folders (written by the web server)" "$T/f"
) || { echo "[SKIPPED] check 5 (Files the web server created outside the bookmark store) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 6. Hidden files in web folders ----------------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "$WEB")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f -name '.*' ! -path '*/admin_ui/*' 2>>"$E" | list > "$T/f"
	finding CHECK "Hidden files in web folders" "$T/f"
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
	finding CHECK "Login page code that may steal passwords - open these files and look" "$T/f"
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
	finding HIGH "Unknown setuid/setgid programs (possible root backdoor)" "$T/f"
) || { echo "[SKIPPED] check 8 (Unknown setuid/setgid programs) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 9. User crontabs ------------------------------------------------------
(
	: > "$T/f"
	[ -d "$R/var/cron/tabs" ] && find "$R/var/cron/tabs" -type f 2>>"$E" | list > "$T/f"
	finding CHECK "User crontabs exist (attackers use these to come back)" "$T/f"
) || { echo "[SKIPPED] check 9 (User crontabs) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 10. Unknown programs in temp folders ----------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/tmp /var/tmp /var/nstmp")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f \( -perm -0100 -o -name '*.so' -o -name '*.php' -o -name '*.pl' -o -name '*.py' \) 2>>"$E" |
		sed "s|^$R||" |
		grep -v -E '^/var/tmp/(Fortville_Silicom_Intel|Mellanox|par-[^/]*)/|^/var/tmp/sum$|^/tmp/nshunt\.' |
		while IFS= read -r f; do printf '%s  %s\n' "$(when "$R$f")" "$f"; done | sort > "$T/f"
	finding CHECK "Programs in temp folders" "$T/f"
) || { echo "[SKIPPED] check 10 (Unknown programs in temp folders) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- Summary ---------------------------------------------------------------
nb=$(find "$R/var/vpn/bookmark" -type f -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')
nl=$(ls "$R"/var/log/ns.log* 2>/dev/null | wc -l | tr -d ' ')
old=$(ls "$R"/var/log/ns.log.*.gz 2>/dev/null | sort -t. -k3 -n | tail -1)
[ -n "$old" ] && old=$(gzip -dc "$old" 2>/dev/null | head -1 | awk '{ print $1, $2 }')
h=$(grep -c '^HIGH$' "$T/count"); a=$(grep -c ATTACK "$T/count"); c=$(grep -c CHECK "$T/count")
echo ""
if [ $((h + a + c)) -eq 0 ]; then
	echo "RESULT: no findings."
else
	echo "RESULT: $h HIGH, $a ATTACK, $c CHECK."
fi
nbad=$(wc -l < "$T/badlogs" | tr -d ' '); sk=$(grep -c SKIPPED "$T/count")
awk '!seen[$0]++' "$E" > "$E.u"; mv "$E.u" "$E"; nerr=$(wc -l < "$E" | tr -d ' ')
echo "Scanned: $nb bookmark files in /var/vpn/bookmark, $nl ns.log files ($nbad unreadable)."
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then
	echo "WARNING: scan INCOMPLETE - $nbad unreadable log(s), $sk crashed check(s), $nerr file system error(s)."
	[ "$nbad" -gt 0 ] && sed 's/^/  unreadable: /' "$T/badlogs"
	[ "$nerr" -gt 0 ] && head -5 "$E" | sed "s|$R||g; s/^/  error: /"
fi
echo "Log checks only see logs still on the box${old:+ (back to $old)}; older attacks need your syslog server."
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then exit 2; fi
[ $((h + a + c)) -gt 0 ] && exit 1
exit 0
