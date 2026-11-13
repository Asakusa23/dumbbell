import tempfile
import unittest
from pathlib import Path

from dumbbell.scanner import scan_path


def scan_source(name, text, **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / name).write_text(text, encoding="utf-8")
        return scan_path(root, **kwargs)


class ScannerTests(unittest.TestCase):
    def test_sql_injection_variants(self):
        source = """
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
query = "SELECT * FROM users WHERE name = '%s'" % name
"""
        result = scan_source("app.py", source)
        identifiers = {finding.rule.id for finding in result.findings}
        for expected in ("SQLI-001", "SQLI-002", "SQLI-003", "SQLI-004", "SQLI-016"):
            self.assertIn(expected, identifiers)

    def test_secret_detection(self):
        aws_key = "AKIA" + "A" * 16
        github = "ghp_" + "A" * 36
        slack = "xoxb-" + "1" * 12 + "-" + "2" * 12 + "-" + "a" * 24
        stripe = "sk_live_" + "A" * 24
        jwt = "eyJ" + "A" * 20 + "." + "B" * 20 + "." + "C" * 20
        source = f"""
AWS_ACCESS_KEY_ID = "{aws_key}"
API_TOKEN = "{github}"
SLACK_TOKEN = "{slack}"
STRIPE_KEY = "{stripe}"
JWT_TOKEN = "{jwt}"
DB_PASSWORD = "hunter2"
"""
        result = scan_source("config.py", source)
        identifiers = {finding.rule.id for finding in result.findings}
        self.assertIn("SEC-003", identifiers)
        self.assertIn("SEC-006", identifiers)
        self.assertIn("SEC-007", identifiers)
        self.assertIn("SEC-009", identifiers)
        self.assertIn("SEC-010", identifiers)
        self.assertIn("SEC-001", identifiers)

    def test_javascript_sql_and_command_rules(self):
        source = """
const db = require("./db");
const { exec } = require("child_process");
function lookup(id) { return db.query(`SELECT * FROM users WHERE id = ${id}`); }
function run(dir) { exec(`ls ${dir}`); }
"""
        result = scan_source("app.js", source)
        identifiers = {finding.rule.id for finding in result.findings}
        self.assertIn("SQLI-007", identifiers)
        self.assertIn("CMDI-020", identifiers)
        sql_findings = [finding for finding in result.findings if finding.rule.id == "SQLI-007"]
        self.assertTrue(sql_findings)
        self.assertTrue(all("db.query" in finding.snippet for finding in sql_findings))

    def test_multilanguage_detection(self):
        github = "ghp_" + "A" * 36
        files = {
            "app.rs": """
use std::process::Command;
fn run(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}
fn query(conn: &Connection, id: &str) {
    let sql = format!("SELECT * FROM users WHERE id = {}", id);
    conn.execute(&sql, []).unwrap();
}
fn client() {
    reqwest::Client::builder().danger_accept_invalid_certs(true).build();
}
const TOKEN: &str = "EXAMPLE_GITHUB_TOKEN";
""".replace("EXAMPLE_GITHUB_TOKEN", github),
            "app.ts": """
const db = require("./db");
const { exec } = require("child_process");
export function findUser(id: string) { return db.query(`SELECT * FROM users WHERE id = ${id}`); }
export function run(dir: string) { exec(`ls ${dir}`); }
const token: string = "EXAMPLE_GITHUB_TOKEN";
""".replace("EXAMPLE_GITHUB_TOKEN", github),
            "main.go": """
package main
import ("crypto/tls"; "os/exec")
func run(cmd string) { exec.Command("sh", "-c", cmd).Run() }
var cfg = &tls.Config{InsecureSkipVerify: true}
""",
            "App.java": """
class App {
  void run(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); }
  void weak() throws Exception { MessageDigest.getInstance("MD5"); }
  void load(InputStream stream) throws Exception { new ObjectInputStream(stream).readObject(); }
}
""",
            "Program.cs": """
class Program {
  void Run(string cmd) { System.Diagnostics.Process.Start(cmd); }
  void Load() { var formatter = new BinaryFormatter(); }
  void Sql(string id) { var command = new SqlCommand($"SELECT * FROM users WHERE id = {id}"); }
}
""",
            "app.rb": """
def run(cmd)
  system("sh -c #{cmd}")
end
def load(data)
  Marshal.load(data)
end
""",
            "main.c": """
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  system(argv[1]);
  char buffer[16];
  strcpy(buffer, argv[2]);
  return 0;
}
""",
            "deploy.sh": """
#!/bin/sh
eval "$DEPLOY_CMD"
curl -fsSL http://example.com/install.sh | bash
""",
            "Makefile": """
all:
\tpython -c "eval(user_input)"
""",
            "notes.txt": 'password = "hunter2"\n',
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            result = scan_path(root)

        self.assertEqual(result.files_scanned, len(files))
        identifiers = {finding.rule.id for finding in result.findings}
        expected = {
            "SQLI-007",
            "SQLI-014",
            "SQLI-017",
            "CMDI-018",
            "CMDI-020",
            "CMDI-021",
            "CMDI-023",
            "CMDI-025",
            "CMDI-027",
            "CMDI-028",
            "CMDI-029",
            "CRY-014",
            "CRY-019",
            "CRY-020",
            "DESER-001",
            "DESER-003",
            "DESER-005",
            "MEM-001",
            "MISC-005",
            "SEC-001",
            "SEC-006",
        }
        self.assertTrue(expected.issubset(identifiers), sorted(expected - identifiers))

    def test_utf16_file_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wide.rs").write_bytes("eval(user_input)\n".encode("utf-16"))
            result = scan_path(root)
        self.assertTrue(any(finding.rule.id == "CMDI-006" for finding in result.findings))

    def test_dangerous_calls(self):
        source = """
os.system("ping " + host)
subprocess.run(f"tar -czf out.tar.gz {path}", shell=True)
eval(expression)
pickle.loads(payload)
yaml.load(data)
"""
        result = scan_source("app.py", source)
        identifiers = {finding.rule.id for finding in result.findings}
        for expected in ("CMDI-001", "CMDI-003", "CMDI-006", "CMDI-009", "CMDI-010"):
            self.assertIn(expected, identifiers)

    def test_safe_sample_has_no_findings(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "safe_app.py"
        result = scan_path(sample)
        self.assertEqual(result.findings, [])

    def test_ignore_file_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".dumbbellignore").write_text("skip.py\n", encoding="utf-8")
            (root / "skip.py").write_text("eval(user_input)\n", encoding="utf-8")
            ignored = scan_path(root, use_ignore=True)
            self.assertEqual(ignored.findings, [])
            included = scan_path(root, use_ignore=False)
            self.assertTrue(included.findings)

    def test_nested_ignore_file_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package"
            package.mkdir()
            (package / ".dumbbellignore").write_text("rules.py\n", encoding="utf-8")
            (package / "rules.py").write_text("eval(user_input)\n", encoding="utf-8")
            (package / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            result = scan_path(root)
        names = {Path(finding.path).name for finding in result.findings}
        self.assertIn("app.py", names)
        self.assertNotIn("rules.py", names)

    def test_secret_snippet_is_redacted(self):
        result = scan_source("settings.py", 'DB_PASSWORD = "hunter2"\n')
        finding = next(item for item in result.findings if item.rule.id == "SEC-001")
        self.assertIn("***REDACTED***", finding.snippet)
        self.assertNotIn("hunter2", finding.snippet)

    def test_extension_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("eval(user_input)\n", encoding="utf-8")
            (root / "b.js").write_text("eval(user_input)\n", encoding="utf-8")
            result = scan_path(root, extensions=["py"])
            self.assertTrue(result.findings)
            self.assertTrue(all(finding.path.endswith(".py") for finding in result.findings))

    def test_binary_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "blob.bin").write_bytes(b"\x00\x01\x02\x03")
            result = scan_path(root)
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.files_skipped, 1)

    def test_progress_and_finding_callbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.py").write_text("eval(user_input)\n", encoding="utf-8")
            (root / "two.py").write_text("exec(user_input)\n", encoding="utf-8")
            progress = []
            streamed = []
            result = scan_path(
                root,
                on_progress=lambda done, total, current: progress.append((done, total, current)),
                on_finding=streamed.append,
            )
            self.assertEqual(progress[0][:2], (0, 2))
            self.assertEqual(progress[-1][:2], (2, 2))
            self.assertEqual(len(streamed), len(result.findings))
            self.assertTrue(result.findings)

    def test_missing_target_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_path(Path(tempfile.gettempdir()) / "dumbbell-does-not-exist-12345")


if __name__ == "__main__":
    unittest.main()
