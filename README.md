# leakscan

A pre-send check for files that are about to leave your machine: a paste into a chat, an
upload, an attachment, a public repository. It scans the files you name for credentials,
private network addresses and paths to credential folders, and exits non-zero if it finds
any.

It is one Python file with no dependencies (Python 3.8 or later).

## Install

```
git clone https://github.com/BrianErlich/leakscan.git
cd leakscan
chmod +x leakscan
mkdir -p ~/.local/bin
ln -s "$PWD/leakscan" ~/.local/bin/leakscan
```

`~/.local/bin` has to be on your `PATH`. To run it without installing, from inside the
clone: `python3 -I leakscan FILE...`

```
leakscan FILE...
leakscan --list-patterns
```

## What it looks for

- Credentials: PEM private key headers, SSH public keys and fingerprints, AWS access key
  ids, GitHub, Slack, Google, Anthropic and OpenAI style tokens, JSON web tokens, and
  `password`, `secret`, `token` or `api_key` assignments whose value is at least 8
  characters and is not an obvious placeholder.
- Network details: RFC 1918 addresses, the 100.64.0.0/10 range (carrier NAT, also used by
  Tailscale), IPv4 link-local addresses, IPv6 unique local addresses, `*.ts.net` hostnames
  and MAC addresses. Loopback and the documentation ranges are ignored.
- Paths to credential folders: `.ssh`, `.aws` and `.config/gcloud` under `~`, `$HOME`,
  `${HOME}`, `/home/<name>`, `/Users/<name>` or `/root`.
- Your own patterns: one regex per line in `~/.config/leakscan/extra.txt`, or in the file
  named by `LEAKSCAN_EXTRA`. Blank lines and lines starting with `#` are skipped. Hits are
  reported as `extra:<line number>`. Use this for what is private to you, such as project
  code names or internal hostnames. See `extra.example.txt`.

`leakscan --list-patterns` prints the built-in list.

## Output and exit codes

Each hit prints on stdout as `file:line:pattern-name: masked-text`. A summary line goes to
stderr.

Masking applies to the matched text only. At most its first four characters stay visible
and the rest are replaced with `*`. For an assignment such as `password = ...`, the name is
printed in full and only the value is masked. File names and error messages are printed as
given. Read a report before you paste it somewhere.

| Exit | Meaning |
|---|---|
| 0 | Every file was checked and had no hits, or only suppressed ones |
| 1 | At least one hit, or a binary or non-UTF-8 file (it cannot be checked, so it does not pass) |
| 2 | Usage error, a bad regex in the extra file, a directory, an unreadable file, or a file over 20 MiB. This takes precedence over 1 |

A line containing `leakscan:allow` suppresses hits on that line. The summary counts them.

## Limits

- It matches patterns, so a secret that fits no pattern passes. Read the file yourself as
  well.
- It opens the files you name and its extra-pattern file. It does not search directories.
  If you name a file inside a credential folder, it reads that file like any other.
- Known false positives: version strings such as `10.1.2.3`.
- Known misses: IPv6 link-local addresses, and assignment values that look like
  placeholders (for example ones containing `example` or starting with `$`). A quoted
  secret that contains spaces is matched only up to the first space, or missed if that part
  is shorter than 8 characters.

## Tests

From inside the clone:

```
python3 -I -m unittest discover -s tests
```

## Licence

MIT. See `LICENSE`.

## Colophon

```
Designed-by: BrianErlich <brianerlich03@gmail.com>
Generated-by: Mythos-5.2 (CVP Defense), Opus-5.5
Assisted-by: GPT-6 Sol (Daybreak Blue) [security review]
Assisted-by: Gemini 4 Carbon [security review]
Signed-off-by: BrianErlich <brianerlich03@gmail.com>
```
