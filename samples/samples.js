// Built-in samples shown in the UI and used by the tests.
export const SAMPLES = {
  'express-orders.js': `import express from 'express';
const app = express();

app.get('/orders/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const order = await db.query(\`SELECT * FROM orders WHERE id = \${id}\`);
  res.json(order);
});

app.get('/users', async (req, res) => {
  const { userId } = req.query;
  const r = await fetch(\`https://api.example.com/users/\${userId}\`);
  res.json(await r.json());
});

const tweetId = 1790462981234567891;
`,
  'flask_accounts.py': `from flask import Flask, request
app = Flask(__name__)

@app.route("/account")
def account():
    account_id = int(request.args["account_id"])
    limit = request.args.get("limit")
    rows = db.execute(f"SELECT * FROM ledger WHERE account = {account_id} LIMIT {limit}")
    return {"rows": rows}
`,
  'Transfer.java': `public class Transfer {
    public static void main(String[] args) {
        long amount = Long.parseLong(args[0]);
        String to = System.getenv("TO_ACCOUNT");
        long target = Long.parseLong(to);
        Bank.send(target, amount);
    }
}
`,
  'handler.go': `package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	serve(w, id)
}
`,
  'serial.c': `#include <stdio.h>

int main(int argc, char **argv) {
    long serial = atol(argv[1]);
    printf("serial %ld\\n", serial);
    return 0;
}
`,
  'safe_gate.js': `function verifyLong(value) {
  const s = String(value).trim();
  if (!/^\\d{1,19}$/.test(s)) throw new RangeError('not a long');
  return BigInt(s);
}

export function load(req) {
  const id = verifyLong(req.params.id);
  return fetch(\`/api/items/\${id}\`);
}
`,
  'known_stamp.py': `# The known stamp: residual rule from axb_residual_known.
# Four cases only: null and zero-b are -1, aligned 1 is 0, aligned 3 is 2.
import sys

def known(b, aligned):
    if b is None or b == 0:
        return -1
    return {1: 0, 3: 2}[aligned]

b = int(sys.argv[1])
print(known(b, 3))
`,
};
