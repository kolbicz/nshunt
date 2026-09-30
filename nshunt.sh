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

VERSION=1.2
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

# A corrupt or unreadable log must not look like "no findings": test every
# log up front and report the scan as incomplete if any cannot be read.
: > "$T/badlogs"
for f in "$R"/var/log/ns.log "$R"/var/log/ns.log.* "$R"/var/log/httpaccess*.log "$R"/var/log/httpaccess*.log.*; do
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
	# Failed logins carry the client IP. The same payload is also logged as
	# "sending login req to aaad for <...>"; those lines have no IP but catch
	# attempts that never produced a LOGIN_FAILED line.
	logs | grep -E 'LOGIN_FAILED|sending login req to aaad for <' | grep -E 'pitboss|`|\$\{IFS\}|\$\(|\|[ ]*sh' |
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
		awk -F '\t' '
		!($1 in n) { order[++k] = $1; first[$1] = $2 }
		{ n[$1]++; last[$1] = $2; if (!seen[$1 SUBSEP $3]++) p[$1] = p[$1] "\n  tried: " substr($3, 1, 110) }
		END { for (i = 1; i <= k; i++) { ip = order[i]
			printf "%-16s %d attempt(s)  %s .. %s UTC%s\n", ip, n[ip], first[ip], last[ip], p[ip] } }' "$T/att" > "$T/f"

		# Files the attacker tried to create in web folders: do they exist now?
		cut -f3 "$T/att" | grep -oE '/(var/netscaler/(logon|gui)|netscaler/ns_gui|var/vpn)/[^] `;$|>"<'"'"'()[]+' |
			sort -u > "$T/drop"
		: > "$T/exists"; : > "$T/dl"
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
				# "GET /url HTTP/1.1" status size - count statuses, keep every 2xx
				awk -v u="$u" '
					match($0, /"[A-Z]+ [^ "]+ [^"]*" [0-9]+ [0-9-]+/) {
						split(substr($0, RSTART, RLENGTH), a, " "); path = a[2]; sub(/\?.*/, "", path)
						if (path != u) next
						if (!(a[4] in n)) order[++k] = a[4]
						n[a[4]]++
						if (a[4] ~ /^2/) { d = ""
							if (match($0, /\[[0-9]+\/[A-Za-z]+\/[0-9:]+ [-+][0-9]+\]/)) d = substr($0, RSTART + 1, RLENGTH - 2)
							print "DL\t" d "  " $1 "  status " a[4] ", " a[5] " bytes  " u }
					}
					END { if (k) { s = ""; for (i = 1; i <= k; i++) s = s (i > 1 ? ", " : "") "status " order[i] " x" n[order[i]]
						print "SUM\t    web requests for " u ": " s }
						else print "SUM\t    no web requests for " u " in the access logs still on the box" }' "$T/hits" > "$T/req"
				awk 'sub(/^SUM\t/, "")' "$T/req" >> "$T/f"
				awk 'sub(/^DL\t/, "")' "$T/req" >> "$T/dl"
			done < "$T/drop"
		fi
		cut -f3 "$T/att" | grep -oE 'https?://[^ `;$|"<>'"'"'()]+' | sort -u > "$T/url"
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
		finding ATTACK "Shell commands sent in the VPN login name (command injection)" "$T/f"
		finding HIGH "A file the attackers tried to create EXISTS - the attack may have worked" "$T/exists"
		finding HIGH "A file the attackers tried to create was DOWNLOADED from the web server - the attack worked" "$T/dl"
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
		grep -rlIE '<\?(php|=)' "$@" 2>>"$E" | grep -v -e '/admin_ui/' -e '\.php$' | list >> "$T/f"
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
	: > "$T/f2"
	if [ $# -gt 0 ]; then
		find "$@" -type f -name '.*' ! -path '*/admin_ui/*' ! -name '.ctxs.receiver' 2>>"$E" | list > "$T/f"
		# published web shell name (GreyNoise, CVE-2026-88771)
		find "$@" -name '.ctxs.receiver' 2>>"$E" | list > "$T/f2"
	fi
	finding HIGH "Known web shell file .ctxs.receiver (2026 attacks)" "$T/f2"
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

# --- 11. Web server config: PHP handlers and aliases (WHIPSHOT) ------------
(
	for c in /etc/httpd.conf /flash/nsconfig/httpd.conf /nsconfig/httpd.conf; do
		[ -f "$R$c" ] || continue
		# /nsconfig is normally a link to /flash/nsconfig: read it once
		[ "$c" = /nsconfig/httpd.conf ] && [ -f "$R/flash/nsconfig/httpd.conf" ] && continue
		awk -v f="$c" '
			# phponly(<files...> header): its pattern names only php/phtml
			function phponly(s) { sub(/^[ \t]*<files(match)?[ \t]+/, "", s); gsub(/php[0-9]?|phtml/, "", s); return s !~ /[a-z0-9]/ }
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
			l ~ /^[ \t]*(alias|aliasmatch|scriptalias|scriptaliasmatch)[ \t]/ && NF >= 3 {
				src = tolower($(NF - 1)); gsub(/"/, "", src)
				tgt = tolower($NF); gsub(/"/, "", tgt)
				base = tgt; sub(/.*\//, "", base)
				if (tgt ~ /\$[0-9]/) { suf = tgt; sub(/.*\$[0-9]+/, "", suf) } else suf = tgt
				if (base ~ /^\./ || suf ~ /\.(sig|deb)$/ ||
				    (src ~ /\.(ico|css|png|gif|js)/ && suf != "" && suf !~ /\.(ico|css|png|gif|js)$/ && (tgt !~ /\$[0-9]/ || suf ~ /^\./)))
					print "HIGH\t" f ":" NR ": " $0 "  (serves a disguised file)"
			}
			l ~ /^[ \t]*php_flag[ \t]+engine[ \t]+on/ { print "CHECK\t" f ":" NR ": " $0 }
			l ~ /#[ \t]*(require all denied|php_flag engine off)/ { print "CHECK\t" f ":" NR ": " $0 "  (protection commented out)" }
		' "$R$c" 2>>"$E"
	done > "$T/conf"
	# strip only the level prefix: config lines may contain tabs themselves
	awk 'sub(/^HIGH\t/, "")' "$T/conf" > "$T/f"
	awk 'sub(/^CHECK\t/, "")' "$T/conf" > "$T/f2"
	finding HIGH "Web server config changed to run disguised files as PHP (web shell persistence)" "$T/f"
	finding CHECK "Unusual PHP settings in the web server config - compare with another box on the same build" "$T/f2"
) || { echo "[SKIPPED] check 11 (Web server config) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 12. Startup scripts (run at every boot, survive a reboot) -------------
(
	for s in rc.netscaler nsbefore.sh nsafter.sh; do
		c=/flash/nsconfig/$s; [ -f "$R$c" ] || c=/nsconfig/$s; [ -f "$R$c" ] || continue
		grep -nE 'python|base64|b64decode|zlib|nohup|/tmp/\.|chmod[[:space:]]+[^ ]*s|chmod[[:space:]]+0?[2-7][0-7]{3}|x-httpd-php|Alias|curl |wget |fnoc\.dptth|php\.xedni|hs/pmt/rav/' \
			"$R$c" 2>>"$E" | cut -c1-200 | sed "s|^|$c:|"
	done > "$T/f"
	finding CHECK "Startup scripts run loaders, downloads or permission changes at boot" "$T/f"
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
	finding HIGH ".deb files in web folders that are not packages (disguised web shell)" "$T/f"
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
	finding HIGH "Shell or interpreter with setuid/setgid bit (anyone running it gets root)" "$T/f"
) || { echo "[SKIPPED] check 14 (setuid shells) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 15. SLAPSHOT tunnel (hidden Python backdoor) --------------------------
(
	for p in /tmp/.uxdport /tmp/.uxdlock /var/tmp/.uxdport /var/tmp/.uxdlock; do
		if [ -e "$R$p" ] || [ -L "$R$p" ]; then printf '%s  %s\n' "$(when "$R$p")" "$p"; fi
	done > "$T/f"
	# Running processes only on the live box, not on a copy.
	if [ -z "$R" ]; then
		ps axww -o user= -o pid= -o command= 2>>"$E" |
			awk '$3 ~ /(^|\/)python[0-9.]*$/ && ((/exec *\(/ && /b64decode|base64/) || /uxdport|uxdlock|UXD_IDLE_EXIT/)' |
			cut -c1-200 | sed 's/^/running: /' >> "$T/f"
	fi
	finding HIGH "SLAPSHOT tunnel traces (Python backdoor files or process)" "$T/f"
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
				"$(printf '%s' "$x" | openssl base64 -d -A 2>/dev/null | tr -c '[:print:]' '.' | cut -c1-150)"
		done; }

	alogs | grep -E '/[0-9A-Fa-f]{6,}\.(ico|sig)|nsginstaller\.deb' > "$T/acc"
	cap "$T/acc" > "$T/f"
	[ -s "$T/f" ] && echo "(WHIPSHOT answers 404 - a 404 with a large response size means the shell ran)" >> "$T/f"
	finding ATTACK "Requests for web shell URLs (<hex>.ico / .sig) in the web access logs" "$T/f"

	alogs | grep -E '"INDEX:[A-Za-z0-9+/=]{8,}|"[A-Za-z0-9+/]{40,}={0,2}"[[:space:]]*$' > "$T/ua"
	cap "$T/ua" > "$T/f"
	grep -oE '"INDEX:[A-Za-z0-9+/=]{8,}|"[A-Za-z0-9+/]{40,}={0,2}"[[:space:]]*$' "$T/ua" |
		sed -e 's/^"INDEX://' -e 's/[" ]//g' | decode >> "$T/f"
	finding ATTACK "Base64 payloads sent as User-Agent (staging for the log-injection attack)" "$T/f"
) || { echo "[SKIPPED] check 16 (Web access log) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 17. Recent crashes -----------------------------------------------------
(
	# shellcheck disable=SC2046
	set -- $(dirs "/var/core /var/crash")
	: > "$T/f"
	[ $# -gt 0 ] && find "$@" -type f -mtime -14 ! -name bounds ! -name minfree 2>>"$E" | list > "$T/f"
	finding CHECK "Crash dumps from the last 14 days (failed exploits can crash the packet engine)" "$T/f"
) || { echo "[SKIPPED] check 17 (Recent crashes) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- 18. Known attacker IP addresses ---------------------------------------
(
	# Published by Mandiant, GreyNoise, Lupovis and the CVE-2025/2026 advisories.
	IPS='45\.61\.136\.143|66\.55\.159\.67|149\.248\.21\.5|144\.126\.221\.237|107\.172\.221\.57|172\.98\.178\.104|88\.218\.105\.254|149\.28\.121\.199|80\.240\.22\.229|78\.135\.96\.136|149\.28\.29\.221|89\.36\.231\.206|91\.195\.240\.123|143\.198\.7\.94|157\.254\.167\.12|149\.104\.78\.141|138\.199\.200\.90'
	{ logs; alogs; } | grep -oE "(^|[^0-9.])($IPS)([^0-9]|\$)" |
		grep -oE "$IPS" | sort | uniq -c | awk '{ printf "%-16s %d log line(s)\n", $2, $1 }' > "$T/f"
	finding ATTACK "Known attacker IP addresses in the logs" "$T/f"
	: > "$T/f2"
	if [ -z "$R" ] && command -v netstat >/dev/null 2>&1; then
		netstat -an 2>>"$E" | grep -E "(^|[^0-9.])($IPS)[.:][0-9]+([^0-9]|\$)" > "$T/f2"
	fi
	finding HIGH "Open network connection to a known attacker IP right now" "$T/f2"
) || { echo "[SKIPPED] check 18 (Known attacker IP addresses) stopped with an error (exit $?)"; echo SKIPPED >> "$T/count"; }

# --- Summary ---------------------------------------------------------------
nb=$(find "$R/var/vpn/bookmark" -type f -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')
nl=$(ls "$R"/var/log/ns.log* 2>/dev/null | wc -l | tr -d ' ')
na=$(ls "$R"/var/log/httpaccess*.log* 2>/dev/null | wc -l | tr -d ' ')
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
echo "Scanned: $nb bookmark files in /var/vpn/bookmark, $nl ns.log files, $na web access log files ($nbad unreadable)."
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then
	echo "WARNING: scan INCOMPLETE - $nbad unreadable log(s), $sk crashed check(s), $nerr file system error(s)."
	[ "$nbad" -gt 0 ] && sed 's/^/  unreadable: /' "$T/badlogs"
	[ "$nerr" -gt 0 ] && head -5 "$E" | sed "${R:+s|$R||g;} s/^/  error: /"
fi
echo "Log checks only see logs still on the box${old:+ (back to $old)}; older attacks need your syslog server."
if [ "$nbad" -gt 0 ] || [ "$sk" -gt 0 ] || [ "$nerr" -gt 0 ]; then exit 2; fi
[ $((h + a + c)) -gt 0 ] && exit 1
exit 0
