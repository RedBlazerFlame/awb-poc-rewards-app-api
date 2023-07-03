import xmlrpc.client
from dotenv import load_dotenv
import os
from flask import Flask, request, session
from uuid import uuid4
import bcrypt
import base64
import hashlib
from datetime import datetime, timedelta
# from flask_config import FLASK_SESSION_SECRET_KEY
from flask_session import Session

from validators import Validators

# Set-up
app = Flask(__name__)

## Dotenv
load_dotenv()

DB = os.getenv("DB_NAME")
URL = os.getenv("DB_URL")
USERNAME = os.getenv("CLIENT_USERNAME")
PASSWORD = os.getenv("CLIENT_PASSWORD")
FLASK_SESSION_SECRET_KEY = os.getenv("FLASK_SESSION_SECRET_KEY")
PORT = os.getenv("PORT")
HOST = os.getenv("HOST")
# CERT = os.getenv("CERT")
# KEY = os.getenv("KEY")

## Globals/Config
session_id_lifespan = timedelta(minutes=30)

app.config['SECRET_KEY'] = FLASK_SESSION_SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.permanent_session_lifetime = session_id_lifespan

sess = Session(app)

## External API
common = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/common")
uid = common.authenticate(DB, USERNAME, PASSWORD, {})
models = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/object")


def create_execute_kw(models, db, uid, password):

  def execute_kw(*args, **kwargs):
    return models.execute_kw(db, uid, password, *args, **kwargs)

  return execute_kw


query = create_execute_kw(models, DB, uid, PASSWORD)

# all_models = list(map(lambda m: m['model'], query('ir.model', 'search_read', [])))
# all_models.sort()

# for model in all_models:
#     print(model)

# Helper Functions


def field(model, field_name):
  return f"x_studio_{model}_{field_name}"


def field_l(model, field_names):
  return list(map(lambda field_name: field(model, field_name), field_names))


def full_model_name(model):
  return f"x_x_{model}"


def generate_customer_id():
  return str(uuid4())


def map_user_info_fields(user_info):
  fields_to_map = ['username', 'phone_number', 'email', 'customer_id']
  fields_to_get = list(
    map(lambda field_name: field('user_info', field_name), fields_to_map))
  return {
    new_name: user_info[old_name]
    for (new_name, old_name) in zip(fields_to_map, fields_to_get)
  }


def ensure_json():
  json = request.json
  return json is not None


def encode_pwd(plain):
  return base64.b64encode(hashlib.sha256(plain.encode()).digest())


def hash_pwd(plain):
  return bcrypt.hashpw(encode_pwd(plain), bcrypt.gensalt(12))


def check_pwd(plain, hashed):
  return bcrypt.checkpw(encode_pwd(plain), hashed.encode('utf-8'))


def get_by_field(model, field, field_value, fields_to_get):
  return query(model, 'search_read', [[(field, '=', field_value)]],
               {'fields': fields_to_get})


def get_users_by_field(field, field_value, fields_to_get):
  return get_by_field(full_model_name('user_info'), field, field_value,
                      fields_to_get)


def count_by_field(model, field, field_value):
  return query(model, 'search_count', [[(field, '=', field_value)]])


def count_users_by_field(field, field_value):
  return count_by_field(full_model_name('user_info'), field, field_value)


# Routes
@app.route("/")
def home():
  return "<h1>This is a Python Server!</h1>"


# @app.route("/user/users_by_name/", methods = ['GET'])
# def get_users_by_name(username):
#     if('customer_id' not in session):
#         return "You are not logged in!", 401
#     username = request.args.get('username')
#     fields_to_get = field_l('user_info', ['username', 'phone_number', 'email', 'customer_id'])
#     res = get_users_by_field(field('user_info', 'username'), username, fields_to_get)
#     return list(map(map_user_info_fields, res))

# @app.route("/user/users_by_email/", methods = ['GET'])
# def get_users_by_email():
#     if('customer_id' not in session):
#         return "You are not logged in!", 401
#     email = request.args.get('email')
#     fields_to_get = field_l('user_info', ['username', 'phone_number', 'email', 'customer_id'])
#     res = get_users_by_field(field('user_info', 'email'), email, fields_to_get)
#     return list(map(map_user_info_fields, res))


@app.route("/user/user_info", methods=['GET'])
def get_user_info():
  if ('customer_id' not in session):
    return "You are not logged in!", 401
  customer_id = session[customer_id]
  fields_to_get = field_l('user_info',
                          ['username', 'phone_number', 'email', 'customer_id'])
  res = get_users_by_field(field('user_info', 'customer_id'), customer_id,
                           fields_to_get)
  return list(map(map_user_info_fields, res))


@app.route("/user/update_user", methods=['POST'])
def update_user_by_customer_id():
  if (not ensure_json()):
    return "POST body is not JSON", 400
  if ('customer_id' not in session):
    return "You are not logged in!", 401

  fields_to_get = field_l('user_info',
                          ['username', 'phone_number', 'email', 'customer_id'])
  customer = get_users_by_field(field('user_info', 'customer_id'),
                                session['customer_id'], fields_to_get)
  if (len(customer) == 0):
    return f"No customer exists with customer id {session['customer_id']}"
  customer = customer[0]

  fields_to_update = ['username', 'phone_number', 'email']
  email = request.json.get('email')
  phone_number = request.json.get('phone_number')
  username = request.json.get('username')

  validation_result = Validators.multi_validator([
    Validators.username_check(username),
    Validators.phone_number_check(phone_number),
    Validators.email_check(email),
  ])

  if (validation_result is not None):
    return validation_result, 400

  if (email is not None
      and count_users_by_field(field('user_info', 'email'), email) > 0):
    return "Email is not unique", 400

  if (username is not None
      and count_users_by_field(field('user_info', 'username'), username) > 0):
    return "Username is not unique", 400

  if (phone_number is not None and count_users_by_field(
      field('user_info', 'phone_number'), phone_number) > 0):
    return "Phone number is not unique", 400

  res = query(full_model_name('user_info'), 'write',
              [[customer["id"]],
               {(field('user_info', field_name)): request.json.get(field_name)
                for field_name in filter(
                  lambda field_name: request.json.get(field_name) is not None,
                  fields_to_update)}])
  return f"Successfully updated customer {session['customer_id']}"


@app.route("/user/sign_up/", methods=['POST'])
def sign_up_user():
  email = request.json.get('email')
  username = request.json.get('username')
  phone_number = request.json.get('phone_number')
  password = request.json.get('password')

  validation_result = Validators.multi_validator([
    Validators.username_check(request.json.get('username'),
                              perform_none_check=True),
    Validators.phone_number_check(request.json.get('phone_number'),
                                  perform_none_check=True),
    Validators.email_check(request.json.get('email'), perform_none_check=True),
    Validators.password_check(request.json.get('password'),
                              perform_none_check=True),
  ])

  if (validation_result is not None):
    return validation_result, 400

  pwd_hash = hash_pwd(password)
  customer_id = generate_customer_id()

  if (count_users_by_field(field('user_info', 'email'), email) > 0):
    return "Email is not unique", 400

  if (count_users_by_field(field('user_info', 'username'), username) > 0):
    return "Username is not unique", 400

  if (count_users_by_field(field('user_info', 'phone_number'), phone_number) >
      0):
    return "Phone number is not unique", 400

  res = query(full_model_name('user_info'), 'create',
              [{
                field('user_info', 'email'): email,
                field('user_info', 'username'): username,
                field('user_info', 'phone_number'): phone_number,
                field('user_info', 'customer_id'): customer_id,
                field('user_info', 'account_type'): 'normal',
                field('user_info', 'password'): pwd_hash,
              }])

  session.permanent = True
  session['customer_id'] = customer_id

  return "Successfully created an account", 200


@app.route("/user/log_in/", methods=['POST'])
def log_in_user():
  email = request.json.get('email')
  username = request.json.get('username')
  password = request.json.get('password')
  res = []
  fields_to_get = field_l('user_info',
                          ['password', 'account_type', 'customer_id'])

  if (password is None):
    return "A password must be provided", 400

  if (email is not None):
    res = get_users_by_field(field('user_info', 'email'), email, fields_to_get)
  elif (username is not None):
    res = get_users_by_field(field('user_info', 'username'), username,
                             fields_to_get)
  else:
    return "The email and username cannot simultaneously be null", 400

  res = list(
    filter(lambda entry: entry[field('user_info', 'account_type')] == 'normal',
           res))

  if (len(res) > 1):
    return "There is more than one user with the provided identifier", 400
  if (len(res) == 0):
    return "There are no users with the provided identifier", 400

  if (check_pwd(password, res[0][field('user_info', 'password')])):
    session.permanent = True
    session['customer_id'] = res[0][field('user_info', 'customer_id')]
    return "Successfully authenticated", 200
  else:
    return "The password provided is incorrect", 400


@app.route("/user/log_out/", methods=['POST'])
def log_out_user():
  if ('customer_id' in session):
    session.pop('customer_id', None)
  return "You are no longer logged in", 200


if __name__ == "__main__":
  app.run(port = PORT, host=HOST, debug=True)
