from flask import Flask,render_template, request, Response, jsonify, make_response
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import json
import re
from datetime import date, timedelta, datetime
from jwt import encode, decode
from functools import wraps
import os
import shutil
import ffmpeg

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
                    get_user = f"SELECT id, username, pseudo, created_at, email FROM user WHERE id='{decoded_token['id']}'"
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

@app.route('/users', methods=['GET'])
def list_users():
    cursor = mysql.connection.cursor()
    # GET ALL USERS
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)
    get_users = f"SELECT * FROM user"
    cursor.execute(get_users)
    users = cursor.fetchall().paginate(page, per_page, False)
    users_list = []
    
    
    #LIST ALL USER INFO
    for user in users:
        users_list.append({"id": user[0], "username": user[1], "email": user[2], "pseudo": user[3]})
    
    
    pager = {
        "current_page": users.page,
        "per_page": users.per_page,
        "total": users.total,
        "total_pages": users.pages
    }
    # SEND RESPONSE
    response = {"message": "Ok", "data": users_list }
    return Response(response=json.dumps(response), status=200, content_type="application/json")

@app.route('/user/<id>', methods=['GET'])
def get_user(id):
    cursor = mysql.connection.cursor()
    get_user = f"SELECT * FROM user WHERE id='{id}'"
    cursor.execute(get_user)
    user = cursor.fetchone() 
    #CHECK IF USER ID EXISTS
    if user == None:
        return Response(response=json.dumps({'message': "Not found"}), status=404, content_type="application/json")
    
    # SEND RESPONSE
    response = {"message": "Ok", "data": {"id": user[0], "username": user[1], "email": user[2], "pseudo": user[3]}}
    return Response(response=json.dumps(response), status=200, content_type="application/json")
    

@app.route('/user/<id>/video', methods=['POST'])
@is_authenticated
def create_video(user, id):
    # IF USER TRY TO UPDATE ANOTHER ACCOUNT SEND ERROR
    if user[0] != int(id):
        return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")
    
    invalid = []
    if not (isinstance(request.form['name'], str)):
        invalid.append('name')
    if not request.files['video'] or not request.files['video'].mimetype.startswith('video/'):
        invalid.append('video')
    
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    # GET VIDEO
    file = request.files['video']

    # EDIT FILENAME
    filename = request.form['name']
    print(filename)
    file_extension = file.filename.split('.')[-1]
    # CREATE USER FOLDER
    if not os.path.isdir(f"./videos/{id}"):
        os.makedirs(f"./videos/{id}")

    # CREATE VIDEO FOLDER
    # CHECK IF THERE IS ANOTHER FILE WITH SAME NAME
    if os.path.isdir(f"./videos/{id}/{filename}"):
        i=1
        while os.path.isfile(f"./videos/{id}/{filename}({i})/original.{file_extension}"):
            i+=1
        filename += f"({i})"
    os.makedirs(f"./videos/{id}/{filename}")
    
    
    # SAVE FILE
    
    save_path = f"./videos/{id}" + f"/{filename}/original.{file_extension}"
    # file.save(os.path.join(save_path))
    file_b = file.read()
    with open(save_path, 'wb') as f:
        # Write the video data to the file
        f.write(file_b)
    # SAVE VIDEO IN DB

    cursor = mysql.connection.cursor()
    insert_video = f"INSERT INTO video (name, user_id, source, created_at, view, enabled) VALUES ('{filename}', '{id}', '{save_path}', '{date.today()}', '0', '1')"
    cursor.execute(insert_video)
    mysql.connection.commit()

    # SEND RESPONSE
    get_video = f"SELECT id, source, created_at, view, enabled FROM video WHERE source='{save_path}'"
    cursor.execute(get_video)
    video = cursor.fetchone()

    userKeys = ('id', "username", "pseudo", "created_at", "email")
    userDict = dict(zip(userKeys, user))
    response = {"message": "Ok", "data": {"id": video[0], "source": video[1], "created_at": video[2], "view": video[3], "enabled": video[4], "user" : userDict}}
    return Response(response=json.dumps(response, default=str), status=201, content_type="application/json")
############################################################################################################  
@app.route('/user/video', methods=['GET'])
def list_videos():
    cursor = mysql.connection.cursor()
    get_videos = f"SELECT * FROM video"
    cursor.execute(get_videos)
    videos = cursor.fetchall() 
    videos_list = []
    
    for video in videos:
        get_user = f"SELECT * FROM user WHERE id='{video[2]}'"
        cursor.execute(get_user)
        user = cursor.fetchone()
        userKeys = ('id', "username", "pseudo", "created_at", "email")
        userDict = dict(zip(userKeys, user))
        videos_list.append({"id": video[0], "name": video[1], "user_id": video[2], "source": video[3], "created_at": video[4], "view": video[5], "enabled": video[6], "user": userDict})
        
    response = {"message": "Ok", "data": videos_list}
    return Response(response=json.dumps(response, default=str), status=200, content_type="application/json")


@app.route('/user/<id>/video', methods=['GET'])
def get_videos(id):
    cursor = mysql.connection.cursor()
    get_videos = f"SELECT * FROM video WHERE user_id='{id}'"
    cursor.execute(get_videos)
    videos = cursor.fetchall() 
    videos_list = []
    
    for video in videos:
        get_user = f"SELECT * FROM user WHERE id='{video[2]}'"
        cursor.execute(get_user)
        user = cursor.fetchone()
        userKeys = ('id', "username", "pseudo", "created_at", "email")

@app.route('/video/<id>', methods=['PATCH'])
def encode_video(id):
    # GET DATA 
    json_data = request.data
    data = json.loads(json_data)

    # CHECK DATA
    invalid = []
    if not (isinstance(data['format'], str)):
        invalid.append('format')
    if not (isinstance(data['source'], str)) :
        invalid.append('source')
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    # CHECK IF VIDEO EXISTS
    if not os.path.isfile(data['source']):
        return Response(response=json.dumps({"message": "Not Found"}), status=400, content_type="application/json")

    # ENCODE VIDEO
    video = ffmpeg.input(data['source'])
    save_path = data['source'].rsplit('/', 1)[0]
    full_path = f"{save_path}/{data['format']}.mp4"

    low_res = video.filter('scale', width=int(data['format']), height=-1).output(full_path, acodec='aac', ab='128k')  
    ffmpeg.run(low_res)
    
    # SAVE IN DB
    cursor = mysql.connection.cursor()
    insert_video = f"INSERT INTO video_format (code, uri, video_id) VALUES ('{data['format']}', '{full_path}', '{id}')"
    cursor.execute(insert_video)
    mysql.connection.commit()

    # SEND RESPONSE
    get_video = f"SELECT id, source, created_at, view, enabled FROM video WHERE source='{save_path}'"
    cursor.execute(get_video)
    video = cursor.fetchone()

    response = {"message": "Ok", "data": {"id": video[0], "source": video[1], "created_at": video[2], "view": video[3], "enabled": video[4], "format": {data['format'] : full_path}}}
    return Response(response=json.dumps(response, default=str), status=201, content_type="application/json")

@app.route('/video/<id>', methods=['PUT'])
def update_video(name,user):
    if user[0] != int(id):
        return Response(response=json.dumps({'message': "Unauthorized"}), status=401, content_type="application/json")
    
    invalid = []
    if not (isinstance(request.form['name'], str)):
        invalid.append('name')
    if not request.files['video'] or not request.files['video'].mimetype.startswith('video/'):
        invalid.append('video')
    
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    file = request.files['video']

    print(file)
    filename = request.form['name']
    print(filename)
    file_extension = file.filename.split('.')[-1]
    if not os.path.isdir(f"./videos/{id}"):
        os.makedirs(f"./videos/{id}")
    
    if os.path.isfile(f"./videos/{id}/{filename}.{file_extension}"):
        i=1
        while os.path.isfile(f"./videos/{id}/{filename}({i}).{file_extension}"):
            i+=1
        filename += f"({i})"
    
    save_path = f"./videos/{id}" + f"/{filename}.{file_extension}"
    file.save(os.path.join(save_path))

    cursor = mysql.connection.cursor()
    insert_video = f"INSERT INTO video (name, user_id, source, created_at, view, enabled) VALUES ('{filename}', '{id}', '{save_path}', '{date.today()}', '0', '1')"
    cursor.execute(insert_video)
    mysql.connection.commit()

    get_video = f"SELECT id, source, created_at, view, enabled FROM video WHERE source='{save_path}'"
    cursor.execute(get_video)
    video = cursor.fetchone()
    userKeys = ('id', "username", "pseudo", "created_at", "email")
    userDict = dict(zip(userKeys, user))
    response = {"message": "Ok", "data": {"id": video[0], "source": video[1], "created_at": video[2], "view": video[3], "enabled": video[4], "user" : userDict}}
    return Response(response=json.dumps(response, default=str), status=201, content_type="application/json")

@app.route('/video/<id>', methods=['DELETE'])
def delete_video(id):
    cursor = mysql.connection.cursor()
    get_video = f"SELECT source from video where id='{id}'"
    cursor.execute(get_video)
    source = cursor.fetchone()
    print(source[0])
    print(source[0].rsplit('/', 1)[0])
    folder = source[0].rsplit('/', 1)[0]
    if os.path.exists(folder):
        shutil.rmtree(folder)
    else:
        return Response(response=json.dumps({'message': "Not found"}), status=404, content_type="application/json")

    delete_video_format = f"DELETE FROM video_format WHERE video_id='{id}'"
    cursor.execute(delete_video_format)
    delete_video = f"DELETE FROM video WHERE id='{id}'"
    cursor.execute(delete_video)
    mysql.connection.commit()
    response = {"message": "Ok", "data": {"id": id}}
    return Response(response=json.dumps(response), status=200, content_type="application/json")
        

@app.route('/video/<id>/comment', methods=['POST'])
@is_authenticated
def create_comment(user, id):
    # GET DATA
    json_data = request.data
    data = json.loads(json_data)

    # IF ERROR SEND ERROR
    invalid = []
    if not (isinstance(data['body'], str)):
        invalid.append('body')
    if len(invalid) > 0:
        response = {"message" : "Bad Request", "code": 10001, "data": invalid}
        return Response(response=json.dumps(response), status=400, content_type="application/json")
    
    # INSERT COMMENT
    cursor = mysql.connection.cursor()
    insert_comment = f"INSERT INTO comment (body, video_id, user_id) VALUES ('{data['body']}', '{id}', '{user[0]}')"
    cursor.execute(insert_comment)
    mysql.connection.commit()

    # SEND RESPONSE
    response = {"message": "Ok", "data": {"id": cursor.lastrowid, "content": data['body'], "video_id": id, "user_id": user[0], "created_at": date.today()}}
    return Response(response=json.dumps(response, default=str), status=201, content_type="application/json")

@app.route('/video/<id>/comments', methods=['GET', 'POST'])
def get_comment_page(id):
    # GET QUERY PARAMS
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)\
    
    # IF QUERY PARAMS ERROR SEND ERROR
    if (page < 0) or (per_page < 0):
        response = {"message": "Bad Request", "code": 10001, "data": "page"}
        return Response(response=json.dumps(response), status=400, content_type="application/json")

    # GET COMMENTS
    cursor = mysql.connection.cursor()
    get_comments = f"SELECT * FROM comment LIMIT {per_page} OFFSET {(page - 1)*per_page}"
    cursor.execute(get_comments)
    comments = cursor.fetchall()

    # FORMAT COMMENTS WITH USER
    comments_list = []
    for comment in comments:
        get_user = f"SELECT id, username, pseudo, created_at FROM user WHERE id='{comment[2]}'"
        cursor.execute(get_user)
        user = cursor.fetchone()
        userKeys = ('id', "username", "pseudo", "created_at")
        userDict = dict(zip(userKeys, user))
        comments_list.append({"id": comment[0], "body": comment[1], "video_id": comment[2], "user": comment[3], "user": userDict})
    
    # RETURN RESPONSE
    response = {"message": "Ok", "data": comments_list, "pager": {"current": page, "total": len(comments)}}
    return Response(response=json.dumps(response, default=str), status=200, content_type="application/json")
