import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { INJECTION_PATTERNS } from "./injection.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(INJECTION_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("injection patterns - SQL", () => {
  describe("positives", () => {
    it("flags string concat in JS query()", () => {
      const rules = scan(
        `db.query("SELECT * FROM users WHERE id = " + req.params.id);`,
        "javascript",
      );
      expect(rules).toContain("sql-injection-concat-js");
    });

    it("flags template literal with SQL keyword interpolation", () => {
      const rules = scan("knex.raw(`SELECT * FROM users WHERE id = ${userId}`);", "javascript");
      expect(rules).toContain("sql-injection-template-js");
    });

    it("flags Python concat in cursor.execute()", () => {
      const rules = scan(`cursor.execute("SELECT * FROM users WHERE id = " + user_id)`, "python");
      expect(rules).toContain("sql-injection-concat-py");
    });

    it("flags Python f-string in execute()", () => {
      const rules = scan(`cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`, "python");
      expect(rules).toContain("sql-injection-fstring-py");
    });

    it("flags Python `%` formatting in execute()", () => {
      const rules = scan(`cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)`, "python");
      expect(rules).toContain("sql-injection-percent-format-py");
    });

    it("flags Python `.format()` in execute()", () => {
      const rules = scan(`cursor.execute("DELETE FROM x WHERE id = {}".format(uid))`, "python");
      expect(rules).toContain("sql-injection-percent-format-py");
    });
  });

  describe("negatives", () => {
    it("does not flag parameterized JS query", () => {
      const rules = scan(`db.query("SELECT * FROM users WHERE id = ?", [id]);`, "javascript");
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });

    it("does not flag parameterized Python execute", () => {
      const rules = scan(`cursor.execute("SELECT * FROM x WHERE id = %s", (uid,))`, "python");
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });

    it("does not flag a static query literal", () => {
      const rules = scan(`db.query("SELECT 1");`, "javascript");
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });

    it("does not flag SQL concat inside a comment", () => {
      const rules = scan(
        `// db.query("SELECT * FROM x WHERE id = " + id);\nconst x = 1;`,
        "javascript",
      );
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });
  });
});

describe("injection patterns - NoSQL", () => {
  describe("positives", () => {
    it("flags Mongo $where with non-literal", () => {
      const rules = scan(`db.find({$where: userScript});`, "javascript");
      expect(rules).toContain("nosql-injection-mongo-where");
    });

    it("flags find(req.body)", () => {
      const rules = scan(`users.find(req.body);`, "javascript");
      expect(rules).toContain("nosql-injection-request-body");
    });

    it("flags updateMany(req.query)", () => {
      const rules = scan(`coll.updateMany(req.query, {$set: {x: 1}});`, "javascript");
      expect(rules).toContain("nosql-injection-request-body");
    });
  });

  describe("negatives", () => {
    it("allows $where with a literal function", () => {
      const rules = scan(`db.find({$where: function() { return this.x > 0; }});`, "javascript");
      expect(rules).not.toContain("nosql-injection-mongo-where");
    });

    it("allows validated body field", () => {
      const rules = scan(`users.find({ _id: validated.id });`, "javascript");
      expect(rules).not.toContain("nosql-injection-request-body");
    });

    it("allows static query", () => {
      const rules = scan(`db.find({ active: true });`, "javascript");
      expect(rules).not.toContain("nosql-injection-request-body");
    });
  });
});

describe("injection patterns - OS command", () => {
  describe("positives", () => {
    it("flags exec with template literal", () => {
      const rules = scan("exec(`ping ${host}`);", "javascript");
      expect(rules).toContain("command-injection-exec-js");
    });

    it("flags exec with variable argument", () => {
      const rules = scan("child_process.exec(cmd);", "javascript");
      expect(rules).toContain("command-injection-exec-js");
    });

    it("flags `shell: true` option", () => {
      const rules = scan("spawn('ls', [], { shell: true });", "javascript");
      expect(rules).toContain("command-injection-shell-true-js");
    });

    it("flags os.system with concat", () => {
      const rules = scan(`os.system("rm " + name)`, "python");
      expect(rules).toContain("command-injection-os-system-py");
    });

    it("flags subprocess with shell=True", () => {
      const rules = scan(`subprocess.run(cmd, shell=True)`, "python");
      expect(rules).toContain("command-injection-subprocess-shell-py");
    });

    it("flags os.popen with variable", () => {
      const rules = scan(`os.popen(cmd)`, "python");
      expect(rules).toContain("command-injection-os-system-py");
    });
  });

  describe("negatives", () => {
    it("allows execFile with argv array", () => {
      const rules = scan(`execFile('/usr/bin/ls', ['-la'], cb);`, "javascript");
      expect(rules.filter((r) => r.startsWith("command-injection"))).toEqual([]);
    });

    it("allows subprocess with shell=False", () => {
      const rules = scan(`subprocess.run(['ls', '-la'], shell=False)`, "python");
      expect(rules.filter((r) => r.startsWith("command-injection"))).toEqual([]);
    });

    it("allows subprocess with default shell setting", () => {
      const rules = scan(`subprocess.run(['ls', '-la'])`, "python");
      expect(rules.filter((r) => r.startsWith("command-injection"))).toEqual([]);
    });
  });
});

describe("injection patterns - LDAP", () => {
  describe("positives", () => {
    it("flags JS LDAP filter concat", () => {
      const rules = scan(`const filter = "(uid=" + user + ")";`, "javascript");
      expect(rules).toContain("ldap-injection-filter-js");
    });

    it("flags Python LDAP filter f-string", () => {
      const rules = scan(`filt = f"(uid={user})"`, "python");
      expect(rules).toContain("ldap-injection-filter-py");
    });

    it("flags JS LDAP filter concat with multiple attributes", () => {
      const rules = scan(`const f = "(cn=" + cn + ")";`, "javascript");
      expect(rules).toContain("ldap-injection-filter-js");
    });
  });

  describe("negatives", () => {
    it("allows escaped LDAP filter via library", () => {
      const rules = scan(`const filter = ldap.escapeFilter(user);`, "javascript");
      expect(rules).not.toContain("ldap-injection-filter-js");
    });

    it("allows static filter", () => {
      const rules = scan(`const filter = "(objectClass=user)";`, "javascript");
      expect(rules).not.toContain("ldap-injection-filter-js");
    });

    it("allows Python escaped filter", () => {
      const rules = scan(`filt = "(uid=" + escape_filter_chars(user) + ")"`, "python");
      expect(rules).not.toContain("ldap-injection-filter-py");
    });
  });
});

describe("injection patterns - Go", () => {
  describe("positives", () => {
    it("flags db.Query with fmt.Sprintf", () => {
      const rules = scan(
        `rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))`,
        "go",
      );
      expect(rules).toContain("sql-injection-sprintf-go");
    });

    it("flags db.Exec with string concatenation", () => {
      const rules = scan(`db.Exec("DELETE FROM users WHERE id = " + id)`, "go");
      expect(rules).toContain("sql-injection-concat-go");
    });

    it("flags QueryRowContext with fmt.Sprintf", () => {
      const rules = scan(
        `row := db.QueryRowContext(ctx, fmt.Sprintf("SELECT name FROM t WHERE id=%d", id))`,
        "go",
      );
      expect(rules).toContain("sql-injection-sprintf-go");
    });

    it("flags exec.Command with sh -c", () => {
      const rules = scan(`cmd := exec.Command("sh", "-c", "ls "+dir)`, "go");
      expect(rules).toContain("command-injection-exec-sh-go");
    });

    it("flags exec.Command with fmt.Sprintf", () => {
      const rules = scan(`exec.Command(fmt.Sprintf("/usr/bin/%s", tool)).Run()`, "go");
      expect(rules).toContain("command-injection-exec-sprintf-go");
    });
  });

  describe("negatives", () => {
    it("does not flag db.Query with placeholders", () => {
      const rules = scan(`rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)`, "go");
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });

    it("does not flag exec.Command with discrete args", () => {
      const rules = scan(`cmd := exec.Command("ls", "-la", dir)`, "go");
      expect(rules.filter((r) => r.startsWith("command-injection"))).toEqual([]);
    });

    it("does not flag a static query literal", () => {
      const rules = scan(`db.Exec("DELETE FROM sessions WHERE expired = true")`, "go");
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });
  });
});

describe("injection patterns - Rust", () => {
  describe("positives", () => {
    it("flags query() with format!", () => {
      const rules = scan(
        `sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id)).fetch_one(&pool).await?;`,
        "rust",
      );
      expect(rules).toContain("sql-injection-format-rust");
    });

    it("flags execute() with format!", () => {
      const rules = scan(`conn.execute(format!("DELETE FROM t WHERE id = {id}"));`, "rust");
      expect(rules).toContain("sql-injection-format-rust");
    });

    it("flags Command::new(sh) with -c and format!", () => {
      const rules = scan(
        `Command::new("sh").arg("-c").arg(format!("ls {}", dir)).output()?;`,
        "rust",
      );
      expect(rules).toContain("command-injection-command-sh-rust");
    });

    it("flags Command::new with a variable program", () => {
      const rules = scan(`let out = Command::new(prog).output()?;`, "rust");
      expect(rules).toContain("command-injection-command-var-rust");
    });
  });

  describe("negatives", () => {
    it("does not flag query() with bound parameters", () => {
      const rules = scan(
        `sqlx::query("SELECT * FROM users WHERE id = $1").bind(id).fetch_one(&pool).await?;`,
        "rust",
      );
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });

    it("does not flag Command::new with a literal program", () => {
      const rules = scan(`let out = Command::new("ls").arg("-la").output()?;`, "rust");
      expect(rules.filter((r) => r.startsWith("command-injection"))).toEqual([]);
    });

    it("does not flag a static query literal", () => {
      const rules = scan(`conn.execute("DELETE FROM sessions WHERE expired = true");`, "rust");
      expect(rules.filter((r) => r.startsWith("sql-"))).toEqual([]);
    });
  });
});
