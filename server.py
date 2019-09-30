from flask import Flask, render_template, redirect, request, flash, session
from mysqlconnection import connectToMySQL    # import the function that will return an instance of a connection
import re
from flask_bcrypt import Bcrypt        
  

app = Flask(__name__)
app.secret_key = "keep it secret"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST"])
def create_user():
    is_valid = True
    if len(request.form['fname']) < 2:
    	is_valid = False
    	flash("Please enter a first name - letters only, at least 2 characters", "signup")
    if len(request.form['lname']) < 2:
        is_valid = False
        flash("Please enter a last name - letters only, at least 2 characters", "signup")
    if not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        flash("Please enter valid email address", "signup")
    if len(request.form['password']) < 2:
    	is_valid = False
    	flash("Please enter password - at least 8 characters", "signup")
    if request.form['password'] != request.form['conf_password']:
    	is_valid = False
    	flash("Password Confirmation - does NOT match password", "signup")
    if not is_valid:
        return redirect("/")
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print(pw_hash) 
        mysql = connectToMySQL('login_registration')
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s,%(pw)s, NOW(), NOW());"
        data = {
            "fn": request.form["fname"],
            "ln": request.form["lname"],
            "em": request.form["email"],
            "pw": pw_hash,
        }
        userid=mysql.query_db(query, data)
        print("type is: %s" % type(userid))
        session[str(userid)] = True
        session['userid'] = userid
        print("done with db")
        return redirect("/success/%s" % userid)

@app.route("/success/<userid>")
def result(userid):
    print("in in success")
    # is user session valid?
    if 'userid' in session:
        # user session is valid, proceed with "results"
        mysql = connectToMySQL('login_registration')

        query = ('SELECT * FROM users WHERE id=%(id)s;') 
        data = {
            "id": session['userid']
        }
        users = mysql.query_db(query, data)
        # print(users)
        return render_template('success.html', users=users )
    else:
        # user session is invalid
        print("user session is invalid: %s, %s" % (userid, session))
        # set flash message saying "session invalid" as login category
        # ... 
        return redirect("/")

@app.route("/login", methods=["POST"]) 
def login():
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        flash("Please enter valid email address", "login")
    if len(request.form['password']) < 2:
    	is_valid = False
    	flash("Please enter password - at least 8 characters", "login")


    # see if the username provided exists in the database
    mysql = connectToMySQL('login_registration')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if len(result) > 0:
        # assuming we only have one user with this username, the user would be first in the list we get back
        # of course, we should have some logic to prevent duplicates of usernames when we create users
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session (to start user session)
            session['userid'] = result[0]['id']
            # session[str(result[0]['id'])] = True
            # never render on a post, always redirect!
            return redirect('/success/%s' % result[0]['id'])
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash("You could not be logged in", "login")
    return redirect("/")

@app.route('/sign_out')
def sign_out():
    session.pop('userid', None)
    return redirect("/")
            
if __name__ == "__main__":
    app.run(debug=True) 

