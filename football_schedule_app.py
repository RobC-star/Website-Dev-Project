"""Imports classes used in order of occurrence"""
import os
from datetime import datetime
import re
import flask
import pandas
from passlib.hash import sha512_crypt
import numpy
import flask_session


def get_hashed_pw(password):
    """Provides a passwords hash.

    :rtype: str
    """
    hashed_password = sha512_crypt.hash(password)
    return hashed_password


def verify_pw(password, hashed_password):
    """Compares password with users hashed password

    :rtype: Bool
    """
    if bool(sha512_crypt.verify(password, hashed_password)) is True:
        return True
    return False


def post_user_data(user_name, email, first_name, last_name):
    """Imports user_file.csv from package and returns pandas dataframe table if file exists"""
    user_data = pandas.DataFrame(numpy.array([[user_name, email, first_name, last_name]]),
                                 columns=["user_name", "email", "first_name", "last_name"])
    try:
        old_user_file = pandas.read_csv("user_file.csv")
        new_user_file = pandas.concat([old_user_file, user_data], axis="rows", ignore_index=True)
        new_user_file.to_csv("user_file.csv", index=False)
    except FileNotFoundError as error:
        print(f"Error: {error}")


def get_user_id(user_name):
    """Gets the index of the username from user_file.csv

    :rtype: int
    """
    try:
        old_user_file = pandas.read_csv("user_file.csv")
        user_name_check = old_user_file["user_name"].str.fullmatch(f"{re.escape(user_name)}")
        if bool(user_name_check.any()) is True:
            user_id = old_user_file[old_user_file["user_name"].str.fullmatch(
                f"{re.escape(user_name)}")].index[0]
            return user_id
        return -1
    except IndexError as error:
        print(f"Error: {error}")
    return None


def get_user_hash(user_id):
    """Uses index of users name to find users hash

    :rtype: string
    """
    try:
        old_pass_file = pandas.read_csv("pass_file.csv")
        hashed_pw = old_pass_file.iloc[user_id, 0]
        return hashed_pw
    except IndexError as error:
        print(f"Error: {error}")
    return None


def post_hashed_pw(hashed_password):
    """Imports Housing.csv from package and returns pandas dataframe table if file exists"""
    hashed_data = pandas.DataFrame(numpy.array([[hashed_password]]), columns=["hash"])
    try:
        old_pass_file = pandas.read_csv("pass_file.csv")
        new_pass_file = pandas.concat([old_pass_file, hashed_data], ignore_index=True)
        new_pass_file.to_csv("pass_file.csv", index=False)
    except FileNotFoundError as error:
        print(f"Error: {error}")


def log_failed_login_attemps(webpage, error_type):
    """Builds failed login attempt log or appends existing log_failed_password_attempts.csv"""
    date_time = datetime.now()
    date = datetime.now().strftime("%d/%m/%Y")
    time = datetime.now().strftime("%X")
    user_ip = get_ip()
    failed_attempt = (pandas.DataFrame
                      (numpy.array([[date_time, date, time, user_ip, webpage, error_type]]),
                       columns=["date_time", "date", "time", "ip", "page", "type"]))
    if bool(os.path.exists("log_failed_password_attemps.csv") is False):
        failed_attempt.to_csv("log_failed_password_attemps.csv", index=False)
    else:
        old_failed_attempts_file = pandas.read_csv("log_failed_password_attemps.csv")
        new_failed_attempts_file = pandas.concat([old_failed_attempts_file, failed_attempt],
                                                 axis="rows", ignore_index=True)
        new_failed_attempts_file.to_csv("log_failed_password_attemps.csv", index=False)


def get_common_passwords(users_password):
    """Compares password with CommonPassword.txt

    :rtype: int
    """
    try:
        common_passwords_file = pandas.read_csv("CommonPassword.txt", names=["common_passwords"])
        common_password_check = (common_passwords_file["common_passwords"].str.fullmatch
                                 (f"{re.escape(users_password)}"))
        if bool(common_password_check.any()) is True:
            return -1
        return 0
    except FileNotFoundError as error:
        print(f"Error: {error}")
    return None


def update_hashed_pw(user_id, hashed_password):
    """Uses the index of the username to replace hashed password"""
    try:
        old_pass_file = pandas.read_csv("pass_file.csv")
        old_pass_file.loc[user_id, "hash"] = hashed_password
        old_pass_file.to_csv("pass_file.csv", index=False)
    except IndexError as error:
        print(f"Error: {error}")


def get_ip():
    """Provides users ip or the servers"""
    if client() == "None":
        return proxy_client()
    return client()


app = flask.Flask(__name__)
app.secret_key = "(UiH:qY%sK{uPg;LFeHg*hY"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
flask_session.Session(app)


@app.route('/')
def initiate_login():
    """Starts login"""
    return flask.redirect(flask.url_for('login_page'))


@app.route("/login/")
def login_page():
    """Starts and ends current sessions and renders login page."""
    if not flask.session.get("name"):
        return flask.render_template("login.html",
                                     date=datetime.now().strftime("%A / %d %B, %Y / %X"),
                                     server_form="/football_schedule_app_login_form.py")

    flask.session["name"] = None
    return flask.render_template("login.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"),
                                 server_form="/football_schedule_app_login_form.py")


@app.route("/registration/")
def registration_page():
    """Renders registration page."""
    return flask.render_template("registration.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"),
                                 server_form="/football_schedule_app_registration_form.py")


@app.route("/update_login_info/")
def update_login_page():
    """Renders update password page."""
    return flask.render_template("update_login_info.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"),
                                 server_form="/football_schedule_app_update_user_pw_form.py")


@app.route("/football_schedule_app_login_form.py", methods=["POST", "GET"])
def get_login_info():
    """Verifies user login data"""
    if flask.request.method == "POST":
        login_form = flask.request.form.get("form_submit_login_btn")
        login_password = flask.request.form.get("password")
        login_user_name = flask.request.form.get("username")

        if get_user_id(login_user_name) < 0:
            log_failed_login_attemps("login", "username")
            flask.flash('Incorrect Username.')
            return flask.redirect(flask.url_for('login_page'))
        login_user_id = get_user_id(login_user_name)
        login_user_hashed_pw = get_user_hash(login_user_id)
        login_pw_verified = verify_pw(login_password, login_user_hashed_pw)

        if login_pw_verified is True:
            print("1")
            if login_form == "updating":
                return flask.redirect(flask.url_for('update_login_page'))
            flask.session["name"] = login_user_name
            return flask.redirect(flask.url_for('home_page'))

        log_failed_login_attemps("login", "password_verification")
        flask.flash('Please use a different password.')
        return flask.redirect(flask.url_for('login_page'))

    return flask.redirect(flask.url_for('login_page'))


@app.route("/football_schedule_app_registration_form.py", methods=["POST", "GET"])
def get_new_user_info():
    """Verifies user registration data"""
    if flask.request.method == "POST":
        registration_user_name = flask.request.form.get("username")

        if get_user_id(registration_user_name) >= 0:
            log_failed_login_attemps("registration", "username")
            flask.flash('Please use a different username.')
            return flask.redirect(flask.url_for('registration_page'))
        registration_password = flask.request.form.get("password")
        if get_common_passwords(registration_password) < 0:
            log_failed_login_attemps("registration", "common_password")
            flask.flash('Please use a different password.')
            return flask.redirect(flask.url_for('registration_page'))
        registration_user_hashed_pw = get_hashed_pw(registration_password)
        pw_verified = verify_pw(registration_password, registration_user_hashed_pw)

        if pw_verified is True:
            post_hashed_pw(registration_user_hashed_pw)
            registration_first_name = flask.request.form.get("first_name")
            registration_last_name = flask.request.form.get("last_name")
            registration_email = flask.request.form.get("email")
            post_user_data(registration_user_name, registration_first_name,
                           registration_last_name, registration_email)
            return flask.redirect(flask.url_for('login_page'))
        log_failed_login_attemps("registration", "password_verification")
        flask.flash('Please use a different password.')
        return flask.redirect(flask.url_for('registration_page'))

    return flask.redirect(flask.url_for('login_page'))


@app.route("/football_schedule_app_update_user_pw_form.py", methods=["POST", "GET"])
def update_user_pw():
    """Verifies username and updates password data

    :rtype: object
    """
    if flask.request.method == "POST":
        login_password = flask.request.form.get("password")
        login_user_name = flask.request.form.get("username")

        if get_user_id(login_user_name) < 0:
            log_failed_login_attemps("update_password", "username")
            flask.flash('Incorrect Username.')
            return flask.redirect(flask.url_for('update_login_page'))
        login_user_id = get_user_id(login_user_name)

        if get_common_passwords(login_password) < 0:
            log_failed_login_attemps("update_password", "common_password")
            flask.flash('Please use a different password.')
            return flask.redirect(flask.url_for('update_login_page'))
        users_hashed_pw = get_hashed_pw(login_password)
        login_pw_verified = verify_pw(login_password, users_hashed_pw)

        if login_pw_verified is True:
            update_hashed_pw(login_user_id, users_hashed_pw)
            return flask.redirect(flask.url_for('login_page'))
        log_failed_login_attemps("update_password", "password_verification")
        flask.flash('Please use a different password.')
        return flask.redirect(flask.url_for('update_login_page'))

    return flask.redirect(flask.url_for('login_page'))


@app.route("/home_page/")
def home_page():
    """Verifies current session and renders home page, Schedules."""
    if not flask.session.get("name"):
        return flask.redirect(flask.url_for('login_page'))
    return flask.render_template("home_page.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"))


@app.route("/league_schedules/")
def league_page():
    """Verifies current session and renders home page, League."""
    if not flask.session.get("name"):
        return flask.redirect(flask.url_for('login_page'))
    return flask.render_template("league_schedules.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"))


@app.route("/afc_schedules/")
def afc_page():
    """Verifies current session and renders afc page, AFC."""
    if not flask.session.get("name"):
        return flask.redirect(flask.url_for('login_page'))
    return flask.render_template("afc_schedules.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"))


@app.route("/nfc_schedules/")
def nfc_page():
    """Verifies current session and renders nfc page, NFC."""
    if not flask.session.get("name"):
        return flask.redirect(flask.url_for('login_page'))
    return flask.render_template("nfc_schedules.html",
                                 date=datetime.now().strftime("%A / %d %B, %Y / %X"))


@app.route('/client/')
def client():
    """Returns user ip"""
    ip_address = flask.request.environ['REMOTE_ADDR']
    return ip_address


@app.route('/proxy-client/')
def proxy_client():
    """Returns users server ip, ie. VPN"""
    ip_address = flask.request.environ.get('HTTP_X_FORWARDED_FOR', flask.request.remote_addr)
    return ip_address
