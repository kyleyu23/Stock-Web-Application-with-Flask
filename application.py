import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


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

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    transactions_data = db.execute("SELECT symbol, sum(shares) FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
    rows = []
    stocks_total = 0
    for row in transactions_data:
        entry = {}
        # stock_info to get price and name of symbol
        stock_info = lookup(row["symbol"])
        entry["symbol"] = row["symbol"]
        entry["shares"] = row["sum(shares)"]
        entry["name"] = stock_info["name"]
        entry["price"] = stock_info["price"]
        stock_total = entry["shares"] * entry["price"]
        stocks_total +=  stock_total
        entry["total"] = usd(stock_total)
        rows.append(entry)
    cash = db.execute("SELECT cash FROM users WHERE id= ?", session["user_id"])[0]["cash"]


    grand_total = stocks_total + cash


    return render_template("index.html", rows=rows, cash=usd(cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        shares = request.form.get("shares")
        # shares must be positive
        if shares.isnumeric():
            if int(shares) <= 0:
                return apology("invalid shares amount")
        else:
            return apology("invalid shares amount")

        stock = lookup(request.form.get("symbol"))

        # if symbol does not exist or blank
        if not stock:
            return apology("invalid symbol")

        # buy
        cost = stock["price"] * float(shares)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if cash >= cost:
            # insert into new table
            # user_id, symbol, shares, price , total , time
            db.execute("INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?);", session["user_id"], stock["symbol"], float(shares), stock["price"], cost,  datetime.now())

            #update original table
            db.execute("UPDATE users SET cash = ? WHERE id = ?", (cash - cost), session["user_id"])
        else:
            return apology("not enough cash")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", history=history)


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
        quoted = lookup(request.form.get("symbol"))
        if not quoted:
            return apology("invalid stock symbol", 403)
        return render_template("quoted.html", quoted=quoted)
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # username blank
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            return apology("must provide username", 403)
        #password blank
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username does not exist
        if len(rows) > 0:
            return apology("username already exist", 403)

        #passwords do not match
        if password != request.form.get("confirmation"):
              return apology("passwords do not match", 403)
        #hash password
        hash_password = generate_password_hash(password)
        #insert
        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, hash_password)

        #redirect to login page
        return render_template("login.html")
    else:
        return render_template("register.html")
    return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # get the user's stocks on hand
    stocks = db.execute("SELECT symbol, sum(shares) FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
    # [{'symbol': 'AAPL', 'sum(shares)': 3}, {'symbol': 'TSLA', 'sum(shares)': 1}]
    symbols = [entry["symbol"] for entry in stocks]


    if request.method == "POST":

        # get symbol from user
        selected_symbol = request.form.get("symbol")
        if not selected_symbol:
          return apology("Please select a symbol")

        # mapping
        stock_to_sell = lookup(selected_symbol)
        shares_to_sell = int(request.form.get("shares"))
        shares_available = sum([entry["sum(shares)"] for entry in stocks if entry["symbol"] == selected_symbol])

        if shares_to_sell < 0 or (shares_available < shares_to_sell):
            return apology("Invalids shares")

        cost = shares_to_sell * stock_to_sell["price"]

        # sell and update database
        db.execute("INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?);", session["user_id"], stock_to_sell["symbol"], float(shares_to_sell)*-1, stock_to_sell["price"], cost,  datetime.now())

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cost, session["user_id"])

        return redirect("/")
    else:
        return render_template("sell.html", symbols=symbols)





    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
