import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "leakscan")


def J(*p):
    return "".join(p)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def env(self, extra=None):
        env = dict(os.environ)
        env["HOME"] = self.d.name
        env["LEAKSCAN_EXTRA"] = extra or os.path.join(self.d.name, "no-extra.txt")
        return env

    def run_text(self, text, extra=None):
        p = os.path.join(self.d.name, "f.txt")
        with open(p, "w") as fh:
            fh.write(text)
        r = subprocess.run([sys.executable, "-I", TOOL, p], capture_output=True, text=True, env=self.env(extra))
        return r

    def hit(self, text, name):
        r = self.run_text(text)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(":" + name + ":", r.stdout)
        return r

    def clean(self, text):
        r = self.run_text(text)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class Credentials(Base):
    def test_positive(self):
        b = "A" * 43
        self.hit(J("-----BEGIN OPENSSH ", "PRIVATE KEY-----"), "private-key-block")
        self.hit(J("ssh-ed", "25519 ", "AAAAC3Nz" * 4, " me"), "ssh-public-key")
        self.hit(J("ecdsa-sha2-", "nistp256 AAAAE2VjZHNh"), "ssh-public-key")
        self.hit(J("ssh-", "rsa ", "AAAAB3NzaC1yc2E"), "ssh-public-key")
        self.hit(J("SHA", "256:", b), "ssh-fingerprint")
        self.hit(J("AK", "IA", "B" * 16), "aws-access-key-id")
        self.hit(J("gh", "p_", "a1" * 20), "github-token")
        self.hit(J("sk", "-ant-", "abcd1234efgh"), "anthropic-openai-key")
        self.hit(J("sk", "-", "z" * 40), "anthropic-openai-key")
        self.hit(J("AI", "za", "q" * 35), "google-api-key")
        self.hit(J("xo", "xb-", "123456789-abc"), "slack-token")
        self.hit(J("ey", "Jhbgc1.", "ey", "Jzdwi1.", "sigsig1"), "jwt")
        self.hit(J("pass", "word = ", "hunter2hunter2"), "generic-secret")
        self.hit(J("API", "_KEY: ", '"', "abcdef123456", '"'), "generic-secret")

    def test_negative(self):
        self.clean("hello world\nSHA256:short\nsk-short\nthe password is stored elsewhere\n")
        self.clean("OpenSSH supports ecdsa-sha2-nistp256 and ssh-ed25519 keys; ssh-rsa is deprecated\n")
        self.clean(J("pass", "word = ", "changeme123"))
        self.clean(J("tok", "en: ", "<your-token-here>"))
        self.clean(J("sec", "ret=", "${SOME_ENV_VAR}"))
        self.clean(J("pass", "word=", "short"))


class Paths(Base):
    def test_positive(self):
        self.hit(J("cat ~/.s", "sh/id"), "path-ssh")
        self.hit(J("~/.a", "ws/credentials"), "path-aws")
        self.hit(J("cat ${HOME}/.s", "sh/id"), "path-ssh")
        self.hit(J("/home/alice/.config/", "gcloud"), "path-gcloud")
        self.hit(J("/Users/alice/.s", "sh/known_hosts"), "path-ssh")

    def test_negative(self):
        self.clean("see https://example.com/archive/2020 and /home/alice/projects\n")


class Network(Base):
    def test_positive(self):
        self.hit(J("10.", "1.2.3"), "ipv4-rfc1918")
        self.hit(J("172.", "20.0.9"), "ipv4-rfc1918")
        self.hit(J("192.", "168.1.1"), "ipv4-rfc1918")
        self.hit(J("100.", "100.1.1"), "ipv4-cgnat-tailscale")
        self.hit(J("169.", "254.1.1"), "ipv4-link-local")
        self.hit(J("fd7a", ":115c:a1e0:ab12::1"), "ipv6-tailscale")
        self.hit(J("fd", "12:3456::1"), "ipv6-ula")
        self.hit(J("box.tail", "abc.ts", ".net"), "tailnet-hostname")
        self.hit(J("de:ad:be", ":ef:00:11"), "mac-address")

    def test_negative(self):
        self.clean("127.0.0.1\n127.1.2.3\n")
        self.clean("192.0.2.5 198.51.100.7 203.0.113.9\n")
        self.clean("172.32.0.1 100.128.0.1 11.1.1.1 8.8.8.8 1.2.3.4.5\n")
        self.clean("2001:db8::1 ::1\n")


class Behaviour(Base):
    def test_masking(self):
        secret = J("gh", "p_", "Zq" * 20)
        r = self.hit(secret, "github-token")
        self.assertNotIn(secret, r.stdout)
        pw = J("hunter", "2hunter2xyz")
        r = self.hit(J("pass", "word=", pw), "generic-secret")
        self.assertNotIn(pw, r.stdout)
        self.assertNotIn(pw[4:], r.stdout)

    def test_allow(self):
        r = self.run_text(J("10.", "0.0.5 leakscan:allow\n"))
        self.assertEqual(r.returncode, 0)
        self.assertIn("1 suppressed", r.stderr)
        r = self.run_text(J("10.", "0.0.5 leakscan:allow\n10.0.0.6\n"))
        self.assertEqual(r.returncode, 1)
        self.assertIn(":2:", r.stdout)
        self.assertNotIn(":1:", r.stdout)

    def test_binary(self):
        p = os.path.join(self.d.name, "b.bin")
        with open(p, "wb") as fh:
            fh.write(b"abc\x00\x01\x02")
        r = subprocess.run([sys.executable, "-I", TOOL, p], capture_output=True, text=True, env=self.env())
        self.assertEqual(r.returncode, 1)
        self.assertIn("binary", r.stderr)

    def test_missing_and_usage(self):
        r = subprocess.run([sys.executable, "-I", TOOL, os.path.join(self.d.name, "nope")], capture_output=True, text=True, env=self.env())
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([sys.executable, "-I", TOOL], capture_output=True, text=True, env=self.env())
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([sys.executable, "-I", TOOL, "-"], capture_output=True, text=True, env=self.env(), input="x")
        self.assertEqual(r.returncode, 2)

    def test_extra(self):
        ex = os.path.join(self.d.name, "extra.txt")
        with open(ex, "w") as fh:
            fh.write("# comment\n\nProject[Zz]ed\n")
        r = self.run_text("see ProjectZed here", extra=ex)
        self.assertEqual(r.returncode, 1)
        self.assertIn(":extra:3:", r.stdout)
        self.assertNotIn("ProjectZed", r.stdout)

    def test_bad_extra_in_home_is_not_read(self):
        os.makedirs(os.path.join(self.d.name, ".config", "leakscan"))
        with open(os.path.join(self.d.name, ".config", "leakscan", "extra.txt"), "w") as fh:
            fh.write("[unclosed\n")
        self.clean("nothing here\n")

    def test_list_patterns(self):
        r = subprocess.run([sys.executable, "-I", TOOL, "--list-patterns"], capture_output=True, text=True, env=self.env())
        self.assertEqual(r.returncode, 0)
        self.assertIn("github-token", r.stdout)

    def test_big_file(self):
        r = self.run_text("a line of nothing\n" * 800000)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
