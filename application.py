import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, logo
from datetime import datetime, timezone

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


#API_KEY: Get from IEX Cloud

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

db.execute("CREATE TABLE IF NOT EXISTS orders (id INTEGER, user_id NUMERIC NOT NULL, symbol TEXT NOT NULL,\
            shares NUMERIC NOT NULL, price NUMERIC NOT NULL, timestamp TEXT, PRIMARY KEY(id), \
            FOREIGN KEY(user_id) REFERENCES users(id))")
db.execute("CREATE INDEX IF NOT EXISTS orders_by_user_id_index ON orders (user_id)")


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    total = 0
    result = db.execute(
        "SELECT symbol, SUM(shares) FROM orders WHERE user_id = ?  GROUP BY symbol HAVING SUM(shares) > 0;", session["user_id"])
    for r in result:
        stock = lookup(r["symbol"])
        r["price"], r["name"] = stock["price"], stock["name"]
        stock_value = r["price"]*r["SUM(shares)"]
        r["shares"] = r["SUM(shares)"]
        r["value"] = stock_value
        total += stock_value
    cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])[0]['cash']
    total += int(cash)
    return render_template("index.html", result=result, total=total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        price = lookup(symbol)
        shares = request.form.get("shares")
        user_cash = db.execute(
            "SELECT cash FROM users WHERE id = ? ", session["user_id"]
        )[0]["cash"]

        if not symbol:
            return apology("a valid symbol must be provide", 400)
        elif price is None:
            return apology("must provide valid symbol", 400)

        try:
            shares = int(shares)
            if shares < 1:
                return apology("share must be a positive integer", 400)
        except ValueError:
            return apology("share must be a positive integer", 400)

        shares_price = shares * price["price"]
        if user_cash < (shares_price):
            return apology("cash is not sufficient", 400)
        else:
            db.execute(
                "UPDATE users SET cash = cash - ? WHERE id = ?",
                shares_price,
                session["user_id"],
            )
            db.execute(
                "INSERT INTO orders (user_id, symbol, shares, price,timestamp) VALUES (?, ?, ?, ?, ?)",
                session["user_id"],
                symbol.upper(),
                shares,
                price["price"],
                time_now(),
            )

            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY timestamp DESC", session["user_id"])
    for trans in history:
        trans["name"] = lookup(trans["symbol"])["name"]
    return render_template("history.html", history=history)


@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "POST":
        current = request.form.get("cur_password")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        rows = db.execute("SELECT * FROM users WHERE id= ?", session["user_id"] )
        if password != confirmation:
            return apology("password and confirmation are not the sames!", 400)

        elif not check_password_hash(rows[0]["hash"], current):
            return apology("Invalid password", 400)
        else:
            hashpass = generate_password_hash(
                password, method="pbkdf2:sha256", salt_length=8
            )
            db.execute("UPDATE users SET hash = ? WHERE id = ? ", hashpass, session["user_id"] )
            return redirect("/")

    else: 
        return render_template("edit.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

 
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = request.form.get("symbol")
        stocks = lookup(quote)
        url = logo(quote)

        if not stocks:
            return apology("Invalid quote", 400)
        else:
            name = stocks["name"]
            price = stocks["price"]
            symbol = stocks["symbol"]
            url = url["url"]

        return render_template("quoted.html", name=name, price=price, symbol=symbol, url=url)
    else:
        return render_template("quote.html")


@app.route("/reset", methods=["GET", "POST"])
@login_required
def ranking():
    if request.method == 'POST':
        money = int(request.form.get("money"))
        db.execute("DELETE FROM orders WHERE user_id = ?", session["user_id"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", money, session["user_id"])
        return redirect("/")
    else:
        return render_template("reset.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username
        if not username:
            return apology("must provide username", 400)
        # Ensure password
        elif not password:
            return apology("must provide password", 400)
        # Ensure confirmation
        elif not confirmation:
            return apology("must confirm password", 400)
        # Check password and confirmation
        elif password != confirmation:
            return apology("password differ from confirmation", 400)
        # Check if username already existed
        elif len(rows) != 0:
            return apology("username existed", 400)
        # Hash password
        else:
            hashpass = generate_password_hash(
                password, method="pbkdf2:sha256", salt_length=8
            )
        # Insert user into database
        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, hashpass,)

        # Log user in
        query = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = query[0]["id"]

        # Return to main page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks = db.execute("SELECT symbol FROM orders WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
                            session["user_id"],)
        return render_template("sell.html", stocks=stocks)

    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)
        shares = int(shares)
        owns = db.execute("SELECT SUM(shares) FROM orders  WHERE user_id = ? GROUP BY symbol = ?", session["user_id"], symbol)
        if not shares:
            return apology("shares required", 400)
        elif shares < 1:
            return apology("shares invalid", 400)
        elif not symbol:
            return apology("stocks required", 400)
        for own in owns:
            if shares > own["SUM(shares)"]:
                return apology("shares invalid", 400)
        revenue = stock["price"] * shares
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", revenue, session["user_id"])
        db.execute("INSERT INTO orders (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol.upper(), -shares, revenue, time_now())

    return redirect("/")


@app.route("/append", methods=[ "POST"])
@login_required
def append():
    """"Add to watchlist """
    symbol = request.form.get("symbol")
    db.execute("INSERT INTO watchlist (user_id, symbol) VALUES (?, ?)", session["user_id"], symbol)

    return redirect("/watchlist")


@app.route("/watchlist", methods=["GET", "POST"])
@login_required
def watchlist():
    """" Return watchlist """
    result = db.execute("SELECT DISTINCT symbol FROM watchlist WHERE user_id = ?", session["user_id"])
    for r in result:
        stock = lookup(r["symbol"])
        r["price"], r["name"] = stock["price"], stock["name"]
    
    return render_template("watchlist.html", result=result)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


def time_now():
    """HELPER: get current UTC date and time"""
    now_utc = datetime.now(timezone.utc)
    return str(now_utc.date()) + ' @time ' + now_utc.time().strftime("%H:%M:%S")
    