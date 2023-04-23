import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import lookup
from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session["user_id"]
    data = db.execute("SELECT * FROM stocks where user_id = ?", id)
    cash = db.execute("SELECT cash from users where id = ?", id)[0]["cash"]
    sum_total = cash
    for d in data:
        search = lookup(d["symbol"])
        sum_total += float(search["price"] * float(d["shares"]))
        d["total"] = usd(search["price"] * d["shares"])
        d["price"] = usd(search["price"])
    return render_template("index.html", data=data, cash=usd(cash), total=usd(sum_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        id = session["user_id"]
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing Symbol")
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")
        if not shares:
            return apology("Missing shares")

        lookedup = lookup(symbol)
        if not lookedup:
            return apology("Invalid symbol")

        name = lookup(symbol)["name"]
        transacted = datetime.now()
        price = float(lookedup.get("price"))
        total = ((lookedup["price"]) * shares)

        if shares < 0:
            return apology("Value must be greater than or equal to 1")

        cash = db.execute("SELECT cash from users where id = ?",
                          id)[0]["cash"]
        # if unaffordable return error
        if cash < total:
            return apology("Cannot Afford")
        update = cash - total
        stock = db.execute("SELECT * from stocks where user_id = ? and symbol = ?", id, symbol)
        if stock:
            db.execute("UPDATE stocks set shares = ? WHERE user_id = ? and symbol = ?", stock[0]["shares"] + shares, id, symbol)
        else:
            db.execute("INSERT INTO stocks (user_id, symbol, name, shares) VALUES (?, ?, ?, ?)", id, symbol, name, shares)
        # update the cash after the stock is brought
        db.execute("UPDATE users SET cash = ? where id = ?",
                   update, id)
        db.execute("INSERT INTO history (symbol, shares, price, transacted, user_id) VALUES (?, ?, ?, ?, ?)",
                   symbol.upper(), shares, price, transacted.strftime('%Y-%d-%m %H:%M:%S'), id)
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    data = db.execute(
        "SELECT symbol, shares, transacted, price from history where user_id = ?", session["user_id"])
    return render_template("history.html", data=data)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    if request.method == "GET":
        return render_template("login.html")
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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")


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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("Invalid symbol")
    return render_template("quoted.html", quote=quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Please provide a username")
        elif not request.form.get("password"):
            return apology("Please provide a password")
        elif not request.form.get("confirmation"):
            return apology("Please provide password again")
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Password does not match")

        # if any username exist in the database
        data = db.execute("SELECT * FROM users where username = ?",
                          request.form.get("username"))
        # if the username is taken already
        if len(data) == 1:
            return apology("Username is already taken. Please take another username.", 400)
        else:
            hash = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users(username, hash) VALUES (?,?)",
                       request.form.get("username"), hash)
            print("You have successfully registered!")

            rows = db.execute(
                "SELECT id FROM users where username = ?", request.form.get("username"))
            data = db.execute(
                "SELECT * FROM stocks where user_id = ?", rows[0]["id"])
            for d in data:
                x = {}
                x["shares"] = d["shares"]
                x["symbol"] = d["symbol"]
                x["name"] = lookup(d["symbol"])["name"]
                x["price"] = lookup(d["symbol"])["price"]
                x["total"] = d["shares"] * x["price"]
           # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

            # redirect to the index page
            return redirect("/")
    return render_template("register.html", username=request.form.get("username"), hash=request.form.get("password"), confirmation=request.form.get("confirmation"))


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        data = db.execute(
            "SELECT symbol from stocks where user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", data=data)
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing Symbol")
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")

        if not shares:
            return apology("Missing shares")
        if shares < 1:
            return apology("Value must be greater than or equal to 1")
        id = session["user_id"]
        price = lookup(symbol)["price"]
        total = int(shares * float(price))
        transacted = datetime.now()
        cash = db.execute("SELECT cash from users where id = ?",
                          session["user_id"])[0]["cash"]
        update = cash + total

        if not lookup(symbol):
            return apology("Invalid symbol")

        data = db.execute("SELECT shares from stocks where user_id = ? and symbol = ?", id, symbol)
        if (not data or (int(data[0]["shares"]) < shares)):
            return apology("Do not have enough stocks to sell")
        else:
            if (int(data[0]["shares"]) == shares):
                db.execute("DELETE from stocks where symbol = ? and user_id = ?", symbol, id)
            else:
                new_shares = int(data[0]["shares"]) - shares
                db.execute("UPDATE stocks SET shares = ? where user_id = ? and symbol = ?", new_shares, id, symbol)

                db.execute("INSERT INTO history(symbol, shares, price, transacted, user_id) VALUES (?, ?, ?, ?, ?)",
                           symbol, int((-1) * shares), price, transacted.strftime('%Y-%d-%m %H:%M:%S'), id)

        return redirect("/")
