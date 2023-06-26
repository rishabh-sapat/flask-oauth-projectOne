from functools import wraps
import json
import requests
from flask import Flask, jsonify, redirect, session, url_for, render_template, request
import jwt
import datetime
from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.decorators import (auth_required, cognito_login, cognito_login_callback, cognito_logout)
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = "my-secret-key"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/user_db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Sapat1925@192.168.0.103:3308/user_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()


class User(db.Model):
    id = db.Column('user_id', db.Integer, primary_key=True, autoincrement=True)
    name = db.Column('user_name', db.String(300), default="Sapat")
    email = db.Column('user_email', db.String(300))
    cog_username = db.Column('cog_username', db.String(500))
    scope = db.Column('user_scope', db.String(300))
    user_role = db.Column('user_role', db.String(300), default="GUEST")


print('User Table is Created...')
db.create_all()


def token_required(fun):
    @wraps(fun)
    def decorated(*args, **kwargs):
        token = ''
        if request.args.get('token'):
            token = request.args.get('token')
        elif request.headers.get('token'):
            token = request.headers.get('token')
        print("token is :", token)
        if not token:
            return jsonify({"error": "Token Missing"})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid Token"})
        return fun(*args, **kwargs)

    return decorated


#
# # Configuration required for CognitoAuth RISHABH
# app.config["AWS_REGION"] = "us-east-2"
# app.config["AWS_COGNITO_USER_POOL_ID"] = "us-east-2_Yi9CwLOSA"
# app.config["AWS_COGNITO_DOMAIN"] = "https://domainown.auth.us-east-2.amazoncognito.com"
# app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "2dvk2cevei1dlm6i3ipgp38c5q"
# app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "c0sc8cqvcj25obvu492023hr229mtuq7689a6g743cj8a9dnb3i"
# app.config["AWS_COGNITO_REDIRECT_URL"] = "http://localhost:5000/callback"  # redirect, callback should be same
# app.config["AWS_COGNITO_LOGOUT_URL"] = "https://google.com"

# # Configuration required for CognitoAuth localhost
# app.config["AWS_REGION"] = "ap-south-1"
# app.config["AWS_COGNITO_USER_POOL_ID"] = "ap-south-1_MQbgKr7MY"
# app.config["AWS_COGNITO_DOMAIN"] = "https://newpool1.auth.ap-south-1.amazoncognito.com"
# app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "5lcoco8uaalng85s3atpn19q06"
# app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "17dqiq7v31bmnoqho3ssc8ug5odeu7q2tfimahrccqjvvaikonff"
# app.config["AWS_COGNITO_REDIRECT_URL"] = "http://localhost:5000/postlogin" #redirect, callback should be same
# app.config["AWS_COGNITO_LOGOUT_URL"] = "https://qr4order.com"

# Configuration required for CognitoAuth localhost
app.config["AWS_REGION"] = "ap-south-1"
app.config["AWS_COGNITO_USER_POOL_ID"] = "ap-south-1_MQbgKr7MY"
app.config["AWS_COGNITO_DOMAIN"] = "https://newpool1.auth.ap-south-1.amazoncognito.com"
app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "5lcoco8uaalng85s3atpn19q06"
app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "17dqiq7v31bmnoqho3ssc8ug5odeu7q2tfimahrccqjvvaikonff"
app.config["AWS_COGNITO_REDIRECT_URL"] = "https://115.242.15.204:4443/postlogin"
# redirect, callback should be same 8000
app.config["AWS_COGNITO_LOGOUT_URL"] = "https://115.242.15.204:4443"

auth = CognitoAuth(app)


@app.route("/")
def home():
    return render_template('index.html')


@app.route("/login")
@cognito_login
def login():
    # A simple route that will redirect to the Cognito Hosted UI.
    # No logic is required as the decorator handles the redirect to the Cognito
    # hosted UI for the user to sign in.
    # An optional "state" value can be set in the current session which will
    # be passed and then used in the postlogin route (after the user has logged
    # into the Cognito hosted UI); this could be used for dynamic redirects,
    # for example, set `session['state'] = "some_custom_value"` before passing
    # the user to this route
    print("into login")


@app.route("/callback")
@app.route("/postlogin")
@cognito_login_callback
def postlogin():
    # A route to handle the redirect after a user has logged in with Cognito.
    # This route must be set as one of the User Pool client's Callback URLs in
    # the Cognito console and also as the config value AWS_COGNITO_REDIRECT_URL.
    # The decorator will store the validated access token in a HTTP only cookie
    # and the user claims and info are stored in the Flask session:
    # session["claims"] and session["user_info"].
    # Do anything after the user has logged in here, e.g. a redirect or perform
    # logic based on a custom `session['state']` value if that was set before
    # login
    print("after login")
    try:
        # name = session["user_info"]["name"]
        email = session["user_info"]["email"]
        client_id = session["claims"]["client_id"]
        scope = session["claims"]["scope"]
        cog_username = session["user_info"]["cognito:username"]
        # payload = {'client_id': client_id, 'email': email, 'cognito-username': cog_username, 'scope': scope,
        # 'user_role':user_role, 'logged_in': session['logged_in'], "exp": datetime.datetime.utcnow() +
        # datetime.timedelta(minutes=15)} token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    except Exception as e:
        return e
    usr = User.query.filter_by(email=email).first()
    if not usr:
        usr = User(email=email, cog_username=cog_username, scope=scope, )
        db.session.add(usr)
        db.session.commit()
        user_role = User.query.filter_by(email=email).first().user_role
    else:
        user_role = usr.user_role

    payload = {'client_id': client_id, 'email': email, 'cognito-username': cog_username, 'scope': scope,
               'user_role': user_role, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    # data = json.dumps(token)
    session['LOGGED_IN'] = True
    return redirect(url_for("userdata", token=token))
    # return jsonify(session)


@app.route("/claims")
@auth_required()
def claims():
    # This route is protected by the Cognito authorisation. If the user is not
    # logged in at this point or their token from Cognito is no longer valid
    # a 401 Authentication Error is thrown, which can be caught by registering
    # an `@app.error_handler(AuthorisationRequiredError)
    # If their auth is valid, the current session will be shown including
    # their claims and user_info extracted from the Cognito tokens.
    # def encode_auth_token(self, payload):
    #     """
    #     Generates the Auth Token
    #     :return: string
    #     """
    #  return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    # try:
    #     session["user_info"]["name"]
    # except:
    #     pass
    # email = session["user_info"]["email"]
    # client_id = session["claims"]["client_id"]
    # scope = session["claims"]["scope"]
    # cog_username = session["user_info"]["cognito:username"]
    # try:
    #     payload = {'client_id': client_id, 'email': email, 'cognito-username': cog_username, 'scope': scope,
    #                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}
    #     token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    #
    # except Exception as e:
    #     return e
    #
    # usr = User(email=email, cog_username=cog_username, scope=scope, client_id=client_id, token=token)
    # db.session.add(usr)
    # db.session.commit()

    # return jsonify({'token': token})
    # print(session)
    try:
        data = request.args['token']
        # data_dict = json.loads(data)
        # return redirect(url_for("userdata", token=data))
    except:
        return jsonify({"error": "Token missing, Please login again"})


@app.route("/userdata")
@auth_required()
def userdata():
    token = request.args.get('token')
    # print('session :', session[logged_in])
    try:
        isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        if session.get('LOGGED_IN') is not False:
            # print("isvalid type :", type(isvalid))
            # data_dict = json.loads(token)
            return render_template('user_data.html', data=isvalid, token=token)
        else:
            return jsonify({"error": "Please login again userdata"})
    except:
        return jsonify({"error": "Token missing, Please login again userdata"})
    # if request.args['token']:
    #     data = request.args['data']
    #     data_dict = json.loads(data)
    #
    # else:
    #     return jsonify({"error": "Please login again"})


@app.route("/dashboard")
@auth_required()
def dashboard():
    try:
        token = request.args['token']
    except:
        return jsonify({"error": "Token missing, Please login again userapp.dashboard"})
    if session.get('LOGGED_IN') is not False:
        try:
            isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({"error": "token is invalid, Please login again userapp.dashboard"})
        result = User.query.all()
        if not result:
            return jsonify({"error": "no response from service"})
        return render_template('admin_menu.html', response=result, token=token)
    else:
        return redirect(url_for('home'))


@app.route("/admin")
@auth_required(groups=["admin"])
def admin():
    # This route will only be accessible to a user who is a member of all of
    # groups specified in the "groups" argument on the auth_required decorator
    # If they are not, a 401 Authentication Error is thrown, which can be caught
    # by registering an `@app.error_handler(CognitoGroupRequiredError).
    # If their auth is valid, the set of groups the user is a member of will be
    # shown.

    # Could also use: jsonify(session["user_info"]["cognito:groups"])
    return jsonify(session["claims"]["cognito:groups"])


# # Define a resource for the /call_app_b endpoint
# @app.route("/foodfirst")
# def food_first():
#     token = request.args.get('token')
#     # print('from get :', token)
#     try:
#         isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#         # print("isvalid :", isvalid)
#         # data_dict = json.loads(token)
#         session['logged_in'] = True
#         return render_template('user_data.html', data=isvalid, token=token)
#     except:
#         return jsonify({"error": "Token missing, Please login again userdata"})

# Define a resource for the /call_app_b endpoint
@app.route("/food/create")
def food_create():
    try:
        token = request.args['token']
    except:
        return jsonify({"error": "Token missing, Please login again userapp.food/create"})
    if session.get('LOGGED_IN') is not False:
        try:
            isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({"error": "token is invalid, Please login again userapp.food/create"})
        # resp = requests.get("http://localhost:5001/create", headers={'Authorization': 'Bearer ' + token})
        resp = requests.get("https://13.234.66.235:5000/create", headers={'Authorization': 'Bearer ' + token})
        if not resp:
            return jsonify({"error": "no response from service"})
        response_dict = resp.json()
        # print(response_dict)
        return render_template('food_create.html', response=response_dict, token=token)
    else:
        return redirect(url_for('home'))


# Define a resource for the /call_app_b endpoint
@app.route("/food")
def food_list():
    try:
        token = request.args['token']
    except:
        return jsonify({"error": "Token missing, Please login again userapp.food"})
    # data_dict = json.loads(data)
    if session.get('LOGGED_IN') is not False:
        try:
            isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return redirect(url_for('log_out'))
        # resp = requests.get("http://localhost:5001/get", headers={'Authorization': 'Bearer ' + token})
        resp = requests.get("https://13.234.66.235:5000/get", headers={'Authorization': 'Bearer ' + token})
        # print("content :", resp.content)
        if not resp:
            return jsonify({"error": "no response from service"})
        # print("resp is:", resp)
        # print("resp type is:", type(resp))
        response_dict = resp.json()
        # print("resp :", response_dict)
        return render_template('food.html', response=response_dict, token=token)
    else:
        return redirect(url_for('log_out'))

    '''
    try:
        if not session['logged_in']:
            return jsonify({"error": "No session, Please login again"})
        if not request.args.get('token'):
            return jsonify({"error": "No token, Please login again"})
            # Make a GET request to App B's /hello endpoint
        # resp = requests.get("http://localhost:5001/get", headers=token)
        # Return the response from App B
        response_dict = resp.json()
        # print(response_dict[0]['foodname'])
        # print(response_dict["response"])
        # print(resp["message"]["foodname"])
        # return jsonify({"message": "List of Products", "response": response.json()})
        return render_template('food.html', response=response_dict)
    except:
        '''

    # return jsonify({"header": "Token missing, Please login again"})


# Define a resource for the /call_app_b endpoint
@app.route("/demo")
def demo():
    # resp = requests.get("http://localhost:5002")
    resp = requests.get("https://13.234.66.235:5000")
    response_dict = resp.json()
    return jsonify(response_dict)


# Define a resource for the /call_app_b endpoint
@app.route("/order/<fname>/<fprice>") # DONE
def make_order(fname,fprice):
    try:
        token = request.args['token']
    except:
        return jsonify({"error": "Token missing, Please login again userapp.order/id"})
    print("in /order/fname/fprice", session)
    if session.get('LOGGED_IN') is not False:
        try:
            isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({"error": "token is invalid, Please login again userapp.order/id"})
        try:
            # resp = requests.get("http://localhost:5002/create/" + fname + "/" + str(fprice),  headers={'Authorization': 'Bearer ' + token})
            resp = requests.get("https://13.234.66.235:5001/create/" + fname + "/" + str(fprice),  headers={'Authorization': 'Bearer ' + token})
        except:
            return jsonify({"error": "Wrong URL, Please login again userapp.order/id"})
        if not resp:
            return jsonify({"error": "no response from service"})
        # print('resp_ is:', resp)
        response_dict = resp.json()
        # foodname = response_dict['foodname']
        # foodprice = response_dict['foodprice']
        # resp = requests.get("http://localhost:5002/create/" + str(fid) + "/" + foodname + "/" + foodprice,
        #                     headers={'Authorization': 'Bearer ' + token})
        # if not resp:
        #     return jsonify({"error": "no response from service"})
        # print('resp_dict is:',response_dict)
        return render_template('order.html', response=response_dict)
    else:
        return redirect(url_for('home'))
    # ________________________
    # # Make a GET request to App B's /hello endpoint
    # # redirect("http://localhost:5001/get/" + str(fid))
    # resp1 = requests.get("http://localhost:5001/get/" + str(fid))
    # # Return the response from App B
    # response_dict = resp1.json()
    # foodname = response_dict['foodname']
    # foodprice = response_dict['foodprice']
    # resp2 = requests.get("http://localhost:5002/create/" + str(fid) + "/" + foodname + "/" + foodprice)
    # # return jsonify({"message": "List of Products", "response": response.json()})
    # # createorder = requests.get("http://localhost:5002/create/" + str(fid), params={ "order" : response_dict})
    # response_dict = resp2.json()
    # return render_template('order.html', response=response_dict)

# Define a resource for the /call_app_b endpoint
@app.route("/order/history")
def order_history():
    try:
        token = request.args['token']
    except:
        return jsonify({"error": "Token missing, Please login again userapp.order/history"})
    # data_dict = json.loads(data)
    if session.get('LOGGED_IN') is not False:
        try:
            isvalid = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return redirect(url_for('log_out'))
        # resp = requests.get("http://localhost:5002/history", headers={'Authorization': 'Bearer ' + token})
        resp = requests.get("https://13.234.66.235:5001/history", headers={'Authorization': 'Bearer ' + token})
        # print("content :", resp.content)
        if not resp:
            return jsonify({"error": "no response from service"})
        # print("resp is:", resp)
        # print("resp type is:", type(resp))
        response_dict = resp.json()
        # print("resp :", response_dict)
        return render_template('order_history.html', response=response_dict, token=token)
    else:
        return redirect(url_for('log_out'))

@app.route("/postlogout")
def postlogout():
    # This is the endpoint Cognito redirects to after a user has logged out,
    # handle any logic here, like returning to the homepage.
    # This route must be set as one of the User Pool client's Sign Out URLs.
    return redirect(url_for("home"))


@app.route("/log_out")
def log_out():
    # Logout of the Cognito User pool and delete the cookies that were set
    # on login.
    # No logic is required here as it simply redirects to Cognito.

    print("log_out")
    # print(session)
    if session.get('LOGGED_IN') is not False:
        session.clear()
        session['LOGGED_IN'] = False
        # print(session)
        return redirect(url_for('logout'))
    else:
        return redirect(url_for('logout'))


@app.route("/logout")
@cognito_logout
def logout():
    # Logout of the Cognito User pool and delete the cookies that were set
    # on login.
    # No logic is required here as it simply redirects to Cognito.
    print("never executes")
    # if session.get('LOGGED_IN') is not False:
    #     session.clear()
    #     return redirect(url_for('home'))
    # else:
    #     return jsonify({"error": "Please login again logout"})


# Run the app in debug mode
if __name__ == "__main__":
    app.run(debug=True)
