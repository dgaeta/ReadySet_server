# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from gcloud import datastore
from datetime import timedelta
from flask import make_response, request, current_app
from functools import update_wrapper
from passlib.apps import custom_app_context as pwd_context
from flask import Blueprint, current_app, redirect, render_template, request, \
    url_for, json, jsonify, g 
from flask.ext.cors import CORS, cross_origin
from flask.ext.httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from pfs_auth import *
from gcloud import storage
import tempfile
from flask import send_file
import StringIO
import base64


auth = HTTPBasicAuth()


# Copied from model_datastore.py
builtin_list = list # idk what this does 

deal_crud = Blueprint('deal_crud', __name__)




def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator



# START AUTH 
def hash_password(password):
    return pwd_context.encrypt(password)

def verify_password_helper(password_plain, password_hash):
    return pwd_context.verify(password_plain, password_hash)


@auth.verify_password
def verify_password(email_or_token, password):

    # first try to authenticate by token
    user = verify_auth_token(email_or_token)


    if not user:
        # try to authenticate with username/password

        ds = get_client()
        key = ds.key('User', str(email_or_token))
        results = ds.get(key)
        # End copy.

        # below was modified from: return from_datastore(results)
        user = from_datastore(results)

        if not user or not verify_password_helper(password, user['password']):
            return False
    g.user = user
    return True


def generate_auth_token(email, expiration = 60000):
    s = Serializer(current_app.config['SECRET_KEY'], expires_in = expiration)
    return s.dumps({ 'email': email })


def verify_auth_token(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None # valid token, but expired
    except BadSignature:
        return None # invalid token

    ds = get_client()
    key = ds.key('User', str(data['email']))
    results = ds.get(key)
    # End copy.

    # below was modified from: return from_datastore(results)
    user = from_datastore(results)

    return user


# Copied from model_datastore.py
def get_client():
    return datastore.Client(
        dataset_id=current_app.config['DATASTORE_DATASET_ID'])


# Copied from model_datastore.py
# [START from_datastore]
def from_datastore(entity):
    """Translates Datastore results into the format expected by the
    application.

    Datastore typically returns:
        [Entity{key: (kind, id), prop: val, ...}]

    This returns:
        {id: id, prop: val, ...}
    """
    if not entity:
        return None
    if isinstance(entity, builtin_list):
        entity = entity.pop()

    entity['id'] = entity.key.id
    return entity
# [END from_datastore]


def gcloud_upload_file(file):
    """
    Upload the user-uploaded file to Google Cloud Storage and retrieve its
    publicly-accessible URL.
    """
    if not file:
        return None

    public_url = storage.upload_file(
        file.read(),
        file.filename,
        file.content_type
    )

    current_app.logger.info(
        "Uploaded file %s as %s.", file.filename, public_url)

    return public_url

# Copied form model_datastore.py
def upsert(data, id=None):
  ds = get_client()
  if id:
  	key = ds.key('User', str(id))
  else:
  	key = ds.key('User', data['email'])

  entity = datastore.Entity(key=key)

  entity.update(data)
  ds.put(entity)
  return from_datastore(entity)


def deal_upsert(data, id=None):
  ds = get_client()
  if id:
    key = ds.key('Deal', str(id))
  else:
    key = ds.key('Deal', data['deal_id'])

  entity = datastore.Entity(key=key)

  entity.update(data)
  ds.put(entity)
  return from_datastore(entity)


def file_upsert(data, id=None):
	ds = get_client()
	if id:
		key = ds.key('File', id)
	else:
		key = ds.key('File', data['id'])

	entity = datastore.Entity(key=key)

	entity.update(data)
	ds.put(entity)
 	return from_datastore(entity)



def remove_null(array):
	while True:
		try:
			array.remove('')
		except ValueError:
			break
	return array


def recursive_dict_to_json(curr_folder):
	if curr_folder == None:
		return curr_folder

	if 'children' in curr_folder:
		recursive_dict_to_json(curr_folder['children'])
		curr_folder['children'] = json.dumps(curr_folder['children'])
	
	return curr_folder



def get_user(email):
	ds = get_client()
	key = ds.key('User', str(email))
	results = ds.get(key)
 	user = from_datastore(results)
 	user['deals'] = ast.literal_eval(user['deals'])
 	return user

def get_deal(deal_id):
	ds = get_client()
	key = ds.key('Deal', str(deal_id))
 	results = ds.get(key)
 	deal = from_datastore(results)
 	return deal


def get_file(file_id):
	ds = get_client()
	key = ds.key('File', file_id)
 	results = ds.get(key)
 	_file = from_datastore(results)
 	return _file




############################
# BEGIN DEAL CRUD OPERATIONS
############################


@deal_crud.route('/get_deals', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def get_deals():
    data = request.json
    email = g.user['email']



@deal_crud.route('/initialize', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def initialize():
    data = request.json
    email = g.user['email']

    try:
        deal_name = data['deal_name']
    except KeyError, e:
        return jsonify(status="failure", message="no file_id param.")

    try:
        date = data['date']
    except KeyError, e:
        return jsonify(status="failure", message="no date param.")

    try:
        description = data['description']
    except KeyError, e:
        return jsonify(status="failure", message="no description param.")

    ds = get_client()
    deal_id = "{}_{}".format(email, deal_name)
    print deal_id
	
	# Check if deal already exists

    deal = get_deal(deal_id)

    if deal != None:
		return jsonify(status="failure", message="deal {} already exists".format(deal_id))

  	
    # Create the Device root 'Folder' Entity
    key = ds.key('Deal', deal_id)
    entity = datastore.Entity(key=key)

    deal = {'deal_id': deal_id, 'date': date, 'description': description, 
		'documents': '{}'}
    print deal

    entity.update(deal)
    ds.put(entity)

    result = from_datastore(entity)
    print result

    user = get_user(email)
    print user
    print type(user['deals'])
    user['deals'][deal_name] = deal
    user['deals'] = json.dumps(user['deals'])
    upsert(user)

    return jsonify(status="success", deal_id=deal_id, user=user)



@deal_crud.route('/upload_file', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def upload_file():
    data = request.form
    print data 

    email = g.user['email']

    uploaded_file =request.files['file']
    print type(uploaded_file)
    file_name = uploaded_file.filename
    print file_name

    try:
        deal_name = data['deal_name']
    except KeyError, e:
        return jsonify(status="failure", message="no deal_name param.")

    try:
        file_type = data['file_type']
    except KeyError, e:
        return jsonify(status="failure", message="no file_type param.")

    # See if file exists with Deal already
    user = get_user(email)
    try:
        deal = user['deals'][deal_name]
    except KeyError, e:
        return jsonify(status="failure", message="User {} has no deal {}.".format(email, deal_name))

    try:
        deal = user['deals'][deal_name]
    except KeyError, e:
        return jsonify(status="failure", message="User {} has no deal {}.".format(email, deal_name))


    if type(deal['documents'])== str:
        deal['documents'] = json.loads(deal['documents'])

    try:
        doc = deal['documents']['file_name']
        return jsonify(status="failure", message="file already exists")
    except KeyError, e:
        pass

    deal_id = "{}_{}".format(email, deal_name)
    deal = get_deal(deal_id)

    print deal_id
    if deal == None:
        return jsonify(status="failure", message="deal entity not found")

    ds = get_client()
    deal_name_nospaces = deal_name.replace(" ", "")
    file_name_nospaces = file_name.replace(" ", "")

    file_id = "{}_{}_{}".format(email, deal_name_nospaces, file_name_nospaces)

    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket('ready-set-files-bucket')
    print bucket
    blob = bucket.get_blob(file_id)
    print blob
    print type(blob)
    if blob == None:
        blob = storage.blob.Blob(file_id, bucket)

    doc_encoded = base64.b64encode(uploaded_file.read())
    blob.upload_from_string(doc_encoded)
    blob.make_public()

    print blob.path
    
    _file = {'id': file_id, 'file_name': file_name, 'file_type': file_type, 'file_data_url': blob.path}

    deal['documents'] = json.loads(deal['documents'])
    deal['documents'][file_name] = _file
    deal['documents'] = json.dumps(deal['documents'])

    print deal
    deal_upsert(deal, deal['id'])
    user['deals'][deal_name]['documents'][file_name] = _file
    docs = user['deals'][deal_name]['documents']
    user['deals'] = json.dumps(user['deals'])
    upsert(user)
    return jsonify(status="true", user=user, documents=docs)


@deal_crud.route('/get_document', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def get_document():
    data = request.json
    print data

    email = g.user['email']

    try:
        deal_name = data['deal_name']
    except KeyError, e:
        return jsonify(status="failure", message="no deal_name param.")

    try:
        file_name = data['file_name']
    except KeyError, e:
        return jsonify(status="failure", message="no file_name param.")

    deal_id = "{}_{}".format(email, deal_name)
    deal = get_deal(deal_id)

    if deal == None:
        return jsonify(status="failure", message="No deal entity found")

    deal['documents'] = json.loads(deal['documents'])
    _file = deal['documents'][file_name]
    file_type = _file['file_type']

    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket('ready-set-files-bucket')

    deal_name_nospaces = deal_name.replace(" ", "")
    file_name_nospaces = file_name.replace(" ", "")
    file_id = "{}_{}_{}".format(email, deal_name_nospaces, file_name_nospaces)
    blob = bucket.get_blob(file_id)
    # tmp = tempfile.SpooledTemporaryFile()
    #blob.download_to_file(tmp)
    # print blob.public_url
    #print type(tmp)
    doc_base64 = blob.download_as_string()

    if blob == None:
        return jsonify(status="failure", message="no blob found")
    else:
        return jsonify(status="success", doc_base64=doc_base64, file_type=file_type)

@deal_crud.route('/exists')
@auth.login_required
def exists():
  	data = request.json

  	email = g.user['email']

  	try:
  		device_id = data['deal_name']
  	except KeyError, e:
  		return jsonify(status="failure", message="no deal_name param.")


  	ds = get_client()
  	deal_id = "{}_{}".format(email, deal_id)
  	
  	# Check if file already exists
  	deal = get_deal(deal_id)

  	if deal == None:
  		return jsonify(status="sucess", message="non existant")
  	else:
  		return jsonify(status="success", message="existant")


@deal_crud.route('/delete')
@auth.login_required
def delete():
  	return jsonify(status=200)




@deal_crud.route('/get_deal_object')
@auth.login_required
def get_deal_object():
  	data = request.json

  	email = g.user['email']

  	try:
  		deal_name = data['deal_name']
  	except KeyError, e:
  		return jsonify(status="failure", message="no device_id param.")

  	deal_id = "{}_{}".format(email, deal_name)

	deal = get_deal(deal_id)


	if deal == None:
		return jsonify(status="failure", message="no deal found")
	else:
		return jsonify(status="success", deal= deal)


