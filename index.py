from flask import Flask,render_template, request, Response, jsonify, make_response
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import json
import re
from datetime import date, timedelta, datetime
from jwt import encode, decode
from functools import wraps

 
app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'mydb'
mysql = MySQL(app)



def is_authenticated(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers.get('Authorization').split(" ")[1]
        print(token)
        if not token: 
            return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")

        decoded_token = decode(token, 'secret')
        try:
            decoded_token = decode(token, 'secret')
            if datetime.fromtimestamp(decoded_token['exp']) < datetime.now():
                return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")
            else: 
                # GET USER
                try:
                    cursor = mysql.connection.cursor()
                    get_user = f"SELECT * FROM user WHERE id='{decoded_token['id']}'"
                    cursor.execute(get_user)
                    user = cursor.fetchone() 
                except:
                    return Response(response=json.dumps({'message': "User does not exists anymore"}), status=404, content_type="application/json")
        except:
            return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")

        return func(user, *args, **kwargs)
    return decorator

 
# #commande a mettre pour envoyer en db
# mysql.connection.commit()
@app.route('/')
def hello():
    return '<h1>Hello, World!</h1>'


@app.route('/user', methods=['POST'])
def create_user():
    json_data = request.data
    data = json.loads(json_data)
    username, pseudo, email, password  = data.values()

    # CHECK BODY 
    invalid = []
    if not (isinstance(data.get("username"), str) and re.match('[a-zA-Z0-9_-]', data["username"])): 
        invalid.append("username")
    email_validation = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not (isinstance(data.get("email"), str) and re.match(email_validation, data["email"])):
        invalid.append("email")
    if not isinstance(data.get("password"), str):
        invalid.append("password")
    
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    cursor = mysql.connection.cursor()

    # VERIFY IF DUPLICATES
    sql_get_duplicate = "SELECT * from user WHERE username=%s OR EMAIL=%s"
    val_duplicate = (username, email)
    cursor.execute(sql_get_duplicate, val_duplicate)
    duplicates = cursor.fetchall()
    
    if len(duplicates) > 0: 
        response = {"message": "Bad Request: email or username already used", "code": 10001, "data": []}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    # HASH PASSWORD
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # CREATE USER
    sql = "INSERT INTO user (username, email, pseudo, password, created_at) VALUES (%s , %s , %s ,%s, %s)"
    val = (username, email, pseudo, pw_hash, date.today())
    cursor.execute(sql, val)
    mysql.connection.commit()

    # GET CREATED USER
    get_user = "SELECT * FROM user WHERE email=%s"
    print(email)
    cursor.execute(get_user, (email,))
    user = cursor.fetchone()

    # SEND RESPONSE
    response = {"message": "Ok", "data": {"id": user[0], "username": user[1], "email": user[2], "pseudo": user[3]}}
    return Response(response=json.dumps(response), status=201, content_type="application/json")

@app.route('/auth', methods=['POST'])
def authentication():
    print('hello')
 
    json_data = request.data
    data = json.loads(json_data)
    login, password = data.values()
    
    # CHECK INFO
    invalid=[]
    if not isinstance(data.get("login"), str):
        invalid.append('login')
    if not isinstance(data.get("password"), str):
        invalid.append("password")

    # IF ERROR RETURN ERROR 
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    cursor = mysql.connection.cursor()

    # GET USER
    get_user = f"SELECT * FROM user WHERE username='{login}' OR email='{login}'"
    cursor.execute(get_user)
    user = cursor.fetchone() 
    print(user)

    # IF WRONG LOGIN OR WRONG PASSWORD RETURN ERROR
    if user == None or not bcrypt.check_password_hash(user[4], password):
        response = {"message" : "Wrong Credentials", "code": 10001, "data": []}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    # CREATE AND SEND TOKEN
    token = encode({'id': user[0], 'username': user[1], 'exp': datetime.utcnow() + timedelta(minutes=45)}, 'secret')
    token_string = token.decode('utf-8')

    # SEND RESPONSE
    response = {"message" : "OK", "data" : token_string }
    response_json = json.dumps(response)
    return Response(response=response_json, status=200, content_type="application/json")

@app.route('/user/<id>', methods=['DELETE'])
@is_authenticated
def delete_user(user, id):
    # IF USER TRY TO DELETE ANOTHER ACCOUNT SEND ERROR
    if user[0] != int(id):
        return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")
    
    try:
        cursor = mysql.connection.cursor()
        delete_user = f"DELETE from user WHERE id={id}"
        cursor.execute(delete_user)
        mysql.connection.commit()
    except:
        return Response(response=json.dumps({'message': "Not found"}), status=404, content_type="application/json")

    return Response(status=204)

@app.route('/user/<id>', methods=['PUT'])
@is_authenticated
def update_user(user, id):
     # IF USER TRY TO UPDATE ANOTHER ACCOUNT SEND ERROR
    if user[0] != int(id):
        return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")
    
    json_data = request.data
    data = json.loads(json_data)

    # CHECK BODY 
    invalid = []
    if 'username' in data and not (isinstance(data.get("username"), str) and re.match('[a-zA-Z0-9_-]', data["username"])): 
        invalid.append("username")
    if 'pseudo' in data and not isinstance(data.get("pseudo"), str): 
        invalid.append("pseudo")
    email_validation = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if 'email' in data and not (isinstance(data.get("email"), str) and re.match(email_validation, data["email"])):
        invalid.append("email")
    if 'password' in data and not isinstance(data.get("password"), str):
        invalid.append("password")
    
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    cursor = mysql.connection.cursor()

    # GET USER
    get_user = f"SELECT * FROM user WHERE id='{id}'"
    cursor.execute(get_user)
    user_found = cursor.fetchone() 
    
    # HASH PASSWORD
    pw_hash = ""
    if 'password' in data:
        pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    update_info = {
        'username': data['username'] if 'username' in data else user_found[1], 
        'pseudo': data['pseudo'] if 'pseudo' in data else user_found[3],
        'email': data['email'] if 'email' in data else user_found[2],
        'password' : pw_hash if 'password' in data else user_found[4]}
    
   
    update_query = f"UPDATE user SET username='{update_info['username']}', pseudo='{update_info['pseudo']}', email='{update_info['email']}', password=\"{update_info['password']}\" WHERE id='{id}'"
    cursor.execute(update_query)
    mysql.connection.commit()

    get_user = f"SELECT * FROM user WHERE id='{id}'"
    cursor.execute(get_user)
    user_found = cursor.fetchone() 

    # SEND RESPONSE
    response = {"message": "Ok", "data": {"id": user_found[0], "username": user_found[1], "email": user_found[2], "pseudo": user_found[3]}}
    return Response(response=json.dumps(response), status=200, content_type="application/json")

    