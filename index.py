from flask import Flask,render_template, request
from flask_mysqldb import MySQL
 
app = Flask(__name__)
 
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'mydb'
 
mysql = MySQL(app)
#commande a mettre pour envoyer en db
#mysql.connection.commit()
@app.route('/')
def hello():
    return '<h1>Hello, World!</h1>'