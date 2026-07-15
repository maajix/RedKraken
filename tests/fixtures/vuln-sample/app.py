# Deliberately vulnerable fixture for the whitebox audit smoke test.
# ONE unambiguous, traceable SQL injection: request param -> string-concat SQL.
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/item")
def item():
    item_id = request.args.get("id")                              # SOURCE: user input
    con = sqlite3.connect("app.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM items WHERE id = " + item_id)      # SINK: SQLi (concatenation)
    return str(cur.fetchall())


if __name__ == "__main__":
    app.run(debug=True)                                          # secondary: debug mode on
