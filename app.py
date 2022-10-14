import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, is_int

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
    if session.get("user_id"):
        db_user = db.execute ("SELECT * FROM users WHERE id=?",session["user_id"])
        user_data = db.execute("SELECT * FROM purchse WHERE user_id =?" ,session["user_id"])
        return render_template("index.html",user_data =user_data,db_user=db_user)
    else:
        return redirect("/login")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST" and session.get("user_id"):
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        elif not request.form.get("shares"):
            return apology("must provide shares", 403)
        ssymbol = request.form.get("symbol")
        symbol = lookup(ssymbol)
        if symbol == None:
            return apology("Symbol isn't valid", 403)
        s_price = symbol["price"]
        shares = request.form.get("shares")
        try:
            shares=int(shares)
        except ValueError:
            return apology("Invalild valule please try again",403)
        # checking if the user input of shares is valid or not
        if shares > 0 :
            total_price= float(shares) * float(s_price)
            cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
            cash=cash[0]["cash"]
            s_shares = db.execute("SELECT * FROM purchse WHERE user_id=? AND symbol LIKE?",session["user_id"], ssymbol)

            if float(cash) > total_price:
                cash = float(cash) - total_price
                if len(s_shares) != 1:
                    db.execute("INSERT INTO purchse (user_id, symbol, shares, price, total) VALUES (?,?,?,?,?);",session["user_id"],ssymbol, shares, s_price, total_price)
                else:
                    # INSERT INTO users (username, hash) VALUES (?,?)",user_name,password
                    total = int(s_shares[0]["shares"])
                    shares = total + int(shares)
                    db.execute("UPDATE purchse set shares=? WHERE user_id=? And symbol LIKE?",shares,session["user_id"], ssymbol)
                    db.execute("UPDATE users set cash =? WHERE id=?",cash,session["user_id"])
                    buy_shares=  int(request.form.get("shares"))
                    db.execute("INSERT INTO transcation (user_id,symbol,shares,price) VALUES(?,?,?,?)",session["user_id"] , ssymbol, buy_shares, s_price)
                return redirect ("/")

            return apology ("Not enough money",403)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    if session.get("user_id"):
        h_transcation = db.execute("SELECT * FROM transcation WHERE user_id =?",session["user_id"])
        return render_template("history.html",h_data=h_transcation)
    return redirect("/login")


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
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        symbol = request.form.get("symbol")
        Sdict = lookup(symbol)
        if Sdict == None :
            return apology("Not valid symbol", 403)
        else:
            return render_template("quoted.html",sdict= Sdict)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
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
        elif not request.form.get("confirmation"):
            return apology("confirm your password", 403)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology ("passwords don't match",403)
        else:
            user_name = request.form.get("username")
            valid = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
            if valid:
                return apology("username taken", 403)
            password = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)",user_name,password)
            return redirect ("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology ("Must provide a symbol",403)
        if not request.form.get("shares"):
            return apology ("not valid shares",403)
        symbol= request.form.get("symbol")
        shares = request.form.get("shares")
        user_shares = db.execute("SELECT * FROM purchse WHERE symbol=? AND user_id=?", symbol, session["user_id"])
        if len(user_shares) != 1:
            return apology("No valid",403)
        user_shares= user_shares[0]["shares"]
        sym_price=lookup(symbol)
        sym_price=sym_price["price"]
        try:
            shares=int(shares)
        except ValueError:
            return apology("Invalild valule please try again",403)
        if shares <= 0:
            return apology("Invalild valule please try again",403)

        if int(user_shares) >= shares:
            sell_shares= -shares
            db.execute("INSERT INTO transcation (user_id,symbol,shares,price) VALUES(?,?,?,?)",session["user_id"],symbol,sell_shares,sym_price)
            cash= db.execute("SELECT * FROM users WHERE id=?",session["user_id"])
            cash= (float(cash[0]["cash"]))+ (float(shares)* sym_price)
            db.execute("UPDATE users set cash=? WHERE id=?", cash,session["user_id"])
            shares= int(user_shares) - int(shares)
            if shares == 0:

                db.execute("DELETE FROM purchse WHERE user_id=? AND symbol=?",session["user_id"],symbol)
            else:
                db.execute("UPDATE purchse set shares=? WHERE symbol=? AND user_id=?",shares, symbol, session["user_id"])
            return redirect("/")
        else:
            return apology("No enough shares",403)
    else:
        ssymbol =db.execute("SELECT * FROM purchse WHERE user_id=?",session["user_id"])
        return render_template("sell.html",dico = ssymbol)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        if not request.form.get("o-password"):
            return apology("must provide password", 403)
        if not request.form.get("n-password"):
            return apology("must provide password", 403)
        if not request.form.get("confirmation"):
            return apology("confirm your password", 403)
        if request.form.get("n-password") != request.form.get("confirmation"):
            return apology ("passwords don't match",403)
        old_password = request.form.get("o-password")
        rows = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], old_password):
            return apology("invalid password", 403)
        new_password=generate_password_hash(request.form.get("n-password"))
        db.execute("UPDATE users set hash=? WHERE id=?",new_password,session["user_id"])
        massege="Your password has been changed successfully"
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("profile.html")

