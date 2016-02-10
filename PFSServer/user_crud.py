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

from PFSServer import storage
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



auth = HTTPBasicAuth()


# Copied from model_datastore.py
builtin_list = list # idk what this does 

user_crud = Blueprint('user_crud', __name__)




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


@user_crud.route('/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user['email'] })

# START AUTH 
def hash_password(password):
    return pwd_context.encrypt(password)

def verify_password_helper(password_plain, password_hash):
    return pwd_context.verify(password_plain, password_hash)


@auth.verify_password
def verify_password(email_or_token, password):

    # first try to authenticate by token
    user = verify_auth_token(email_or_token)
    print("HERE HERE HERE HERE {}".format(email_or_token))


    if not user:
        # try to authenticate with username/password

        ds = get_client()
        print "this shit should be {}".format(email_or_token)
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

# Copied from model_datastore.py
def read(id):
    ds = get_client()
    key = ds.key('User', str(id))
    results = ds.get(key)
    return from_datastore(results)


# Copied from model_datastore.py
def delete_helper(id):
    ds = get_client()
    key = ds.key('User', str(id))
    ds.delete(key)


# This is data-model agnostic, uses google_storage.
# [START upload_image_file]
def upload_image_file(file):
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
# [END upload_image_file]



@user_crud.route("/")
def list():
    token = request.args.get('page_token', None)
    
    # added to fit code below
    limit = 10 
    # Copied from model_datastore.py
    ds = get_client()
    query = ds.query(kind='User', order=['email'])
    it = query.fetch(limit=limit, start_cursor=token)
    entities, more_results, cursor = it.next_page()
    entities = builtin_list(map(from_datastore, entities))

    # End copy
    users = entities

    # This is the old get.
    # users, next_page_token = get_model().list(cursor=token)

    # return render_template(
    #     "list.html",
    #     users=users,
    #     next_page_token=next_page_token)
    return jsonify(users = json.dumps(users))




@user_crud.route('/<id>')
def view(id):
    # Copied from model_datastore.py
    ds = get_client()
    key = ds.key('User', str(id))
    results = ds.get(key)
    # End copy.

    # below was modified from: return from_datastore(results)
    user = from_datastore(results)


    #user = get_model().read(id)
    # return render_template("view.html", user=user)
    return jsonify(status="success", user= json.dumps(user))


@user_crud.route('/add', methods=['GET', 'POST'])
def add():
    
    #data = request.form.to_dict(flat=True)
    data = request.json
    print(data)
    print(data['email'])
    print(data['password'])

    ds = get_client()
    key = ds.key('User', str(data['email']))
    results = ds.get(key)
    user = from_datastore(results)
    print(user)
    if user != None:
        return jsonify( status= "fail", error= "Email already exists.")

    # If an image was uploaded, update the data to point to the new image.
    # [START image_url]
    image_url = upload_image_file(request.files.get('image'))
    # [END image_url]

    # [START image_url2]
    if image_url:
        data['imageUrl'] = image_url
    # [END image_url2]

    # hash user password 
    data['password'] = hash_password(data['password'])
    data['devices'] = '{}'
    data['device_count'] = 0
    user = upsert(data)

    # return redirect(url_for('.view', id=user['id']))
    return jsonify( status= "success", id= user['email'])

    


@user_crud.route('/signin', methods=['GET', 'OPTIONS'])
@cross_origin()
@auth.login_required
def get_auth_token():
    email = g.user['email']
    token = generate_auth_token(email)

    ds = get_client()
    key = ds.key('User', str(email))
    results = ds.get(key)

    # below was modified from: return from_datastore(results)
    user = from_datastore(results)
    device_count = user['device_count'] 
    devices = json.loads(user['devices'])
    return jsonify(status='success', email=email, token=token.decode('ascii'), device_count=device_count, devices=devices)
# END AUTH 


@user_crud.route('/edit', methods=['GET', 'POST'])
def edit():
    data = request.json

    ds = get_client()
    key = ds.key('User', str(data['email']))
    results = ds.get(key)
    user = from_datastore(results)

    property_key = data['property_key']
    property_value = data['property_value']

    if user.get(property_key):
        
        user[property_key] = property_value

        # image_url = upload_image_file(request.files.get('image'))
        # if image_url:
        #     data['imageUrl'] = image_url

        user = upsert(data, id)

        return jsonify( status= "success", id= user['email'])
    else: 
        return jsonify( status="fail", message= "Needs to be POST")


@user_crud.route('/delete')
def delete():
    data = request.json

    ds = get_client()
    key = ds.key('User', str(data['email']))
    ds.delete(key)
    # results = ds.get(key)
    # user = from_datastore(results)
    # delete_helper(data['email'])
    # return redirect(url_for('.list'))
    return jsonify( status= "success")


@user_crud.route('/list_devices')
@auth.login_required

def list_devices():
    #return jsonify(data=request.args)
    data = request.json
    email = g.user['email']
    print(data)
    #print(data['email'])
   

    ds = get_client()
    key = ds.key('User', str(email))
    results = ds.get(key)
    # End copy.

    # below was modified from: return from_datastore(results)
    user = from_datastore(results)

    
    if user.get('device_count') and user['device_count'] > 0:
        return jsonify( status="success", message="true", device_count=user['device_count'], devices=json.loads(user['devices']))
    else:
        return jsonify( status="success", message="no devices", device_count=0)
    

    return jsonify(status="none")

@user_crud.route('/create_device')
@auth.login_required
def create_device():
    data = request.json
    email = g.user['email']
    device_name = data['device_name']
    random_id = device_name + '_' + email

    # datastore = get_client()
    # req = datastore.LookupRequest()
    # req.key.extend([employee_key])

    # resp = self.datastore.lookup(req)
    # employee = resp.found[0].entity

    ds = get_client()
    key = ds.key('User', str(email))
    results = ds.get(key)
    # End copy.

    # below was modified from: return from_datastore(results)
    user = from_datastore(results)

    if user != None:
        if not user.get('devices'):
            user['devices'] = "{}"

        user['devices'] = json.loads(user['devices'])
        if random_id in user['devices']:
            return jsonify(status='error, random_id already taken')
        else:
            user['device_count'] += 1
            user['devices'][random_id] = {'random_id':random_id, 'device_name': device_name}
            user['devices'] = json.dumps(user['devices'])
        user = upsert(user, email)
        return jsonify(status="success", email=user['email'], device_count=user['device_count'], devices=json.loads(user['devices']), random_id=random_id)
    else:
        return jsonify(status="failure", email=user['email'], message='no user found')




