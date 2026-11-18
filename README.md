# leakscan

A pre-send check for files that are about to leave your machine: a paste into a chat,
an upload to a hosted model, an attachment, a public repository. It scans the text of the
files you name for credentials, private network addresses and paths to credential
folders, and exits non-zero if it finds any.

It is one Python file with no dependencies (Python 3.8 or later).

## Install

```
git clone https://github.com/BrianErlich/leakscan.git
chmod +x leakscan/leakscan
ln -s "$PWD/leakscan/leakscan" ~/.local/bin/leakscan
```

Or run it without installing: `python3 -I leakscan/leakscan FILE...`

```
leakscan FILE...
leakscan --list-patterns
```

## What it looks for

- **Credentials:** PEM private key headers, SSH public keys and fingerprints, AWS access key
  ids, GitHub, Slack, Google, Anthropic and OpenAI style tokens, JSON web tokens, and
  `password = ...` style assignments whose value is not an obvious placeholder.
- **Network details:** RFC 1918 addresses, the 100.64.0.0/10 range (carrier NAT, also used by
  Tailscale), IPv4 link-local addresses, IPv6 unique local addresses, `*.ts.net` hostnames and
  MAC addresses. Loopback and the documentation ranges are ignored.
- **Paths to credential folders:** `~/.ssh`, `~/.aws` and `~/.config/gcloud`, written with
  `~`, `$HOME`, `${HOME}` or an absolute home path.
- **Your own patterns:** one regex per line in `~/.config/leakscan/extra.txt`, or in the file
  named by `LEAKSCAN_EXTRA`. See `extra.example.txt`. Use this for what is private to you,
  such as project code names or internal hostnames.

## Output and exit codes

Each hit prints as `file:line:pattern-name: masked-text` on stdout. Matched text is masked,
so the report itself is safe to paste. A summary line goes to stderr.

| Exit | Meaning |
|---|---|
| 0 | No hits |
| 1 | At least one hit, or a binary or undecodable file (it cannot be checked, so it does not pass) |
| 2 | Usage or read error, including files over 20 MB |

A line containing `leakscan:allow` suppresses hits on that line. The summary counts them.

## Limits

- It is a pattern check. It must pass alongside your own read of the file; it is not a
  guarantee, and it knows nothing about secrets that do not look like secrets.
- It reads only the files you give it. It never opens `~/.ssh`, `~/.aws` or any other
  credential folder.
- Known false positives: version strings such as `10.1.2.3`.
- Known misses: quoted secrets that contain spaces, IPv6 link-local addresses, and values that
  look like placeholders (for example ones containing `example` or starting with `$`).

## Tests

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
