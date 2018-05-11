from flask import Flask, request, redirect, render_template, session, flash
from flask_bcrypt import Bcrypt
# import the function connectToMySQL from the file mysqlconnection.py
from mysqlconnection import connectToMySQL


import re
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = "Shh....It's a secret!"
bcrypt = Bcrypt(app)
mysql = connectToMySQL('register_db')

# print("all the users", mysql.query_db("SELECT * FROM users;"))

@app.route('/')
def index():
    if 'id' not in session:
        session['id'] = ''
    if 'first_name' not in session:
        session['name'] = ''
    return render_template("index.html", id=session['id'])


@app.route('/process', methods=['POST'])
def validate():
    error_flag = 0
    # result = request.form
    # print(result)

    if len(request.form['first_name']) < 2:
        flash('First Name field cannot be blank')
        error_flag = 0
    elif not request.form['first_name'].isalpha():
        flash('Name fields cannot contain numbers')
        error_flag = 0
        # return redirect('/')
    if len(request.form['last_name']) < 2:
        flash('Last Name field cannot be blank')
        error_flag = 0
    elif not request.form['last_name'].isalpha():
        flash('Name fields cannot contain numbers')
        error_flag = 0
        # return redirect('/')
    if len(request.form['email']) < 1:
        flash('Email field cannot be blank')
        error_flag = 0
        # return redirect('/')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email address')
        error_flag = 0
        # return redirect('/')
    if request.form['password'] != request.form['confirm']:
        flash('Passwords must match to register!')
        error_flag = 0


    if error_flag == 0:
        # include some logic to validate user input before adding them to the database!
        # create the hash
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        print(pw_hash)

        query = "INSERT INTO users(first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s);"
        data = {
            'first_name':request.form['first_name'],
            'last_name':request.form['last_name'],
            'email':request.form['email'],
            'password_hash':pw_hash
            }
        mysql.query_db(query, data)
        # print("Data dict: ", data)

        queryID = "SELECT * FROM users WHERE email = %(email)s;"
        query_result = mysql.query_db(queryID, data)
        # print('Results from query: ', query_result)
        session['id'] = query_result[0]['id']
        # print(session)
        session['first'] = request.form['first_name']
        return redirect('/success')
    else:
        return redirect('/')


@app.route('/success')
def success():
    # result = request.form
    # print(result)
    flash("Success! You have been registered.")
    all_users = mysql.query_db("SELECT * FROM users")
    # print('Users: ', all_users)
    return render_template('success.html', users=all_users)

# def debugHelp(message = ""):
#     print("\n\n-----------------------", message, "--------------------")
#     print('REQUEST.FORM:', request.form)
#     print('SESSION:', session)




if __name__=="__main__":

    app.run(debug=True)
