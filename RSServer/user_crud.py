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

from RSServer.storage import *
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
import base64
from flask import send_file
from gcloud import storage
import uuid
import datetime

from RSServer import get_sql_model


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


def get_user(email):
    ds = get_client()
    key = ds.key('User', str(email))
    results = ds.get(key)
    user = from_datastore(results)
    return user

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
    if user == None:
        return jsonify(status='failure', 
            message="no user entity found with email {}".format(email))


    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])
    
    if user['user_type'] == "company":
          
        company_struct_id = email + "_Company_struct"
        blob = bucket.get_blob(company_struct_id)
        
        if blob == None:
            return jsonify(status='failure', message="no company_struct blob found.")

        company_struct_str = blob.download_as_string()
        company_struct = json.loads(company_struct_str)

        # notifications = get_sql_model().list_notifications(email)

        return jsonify(status='success', user=user, 
            token=token.decode('ascii'), 
            company_struct=company_struct, user_type="company", 
            notifications=None)
    else:

        investor_struct_id = email + "_Investor_struct"
        blob = bucket.get_blob(investor_struct_id)

        if blob == None:
            return jsonify(status='failure', message="no investor_struct blob found.")

        investor_struct_str = blob.download_as_string()
        investor_struct = json.loads(investor_struct_str)
        return jsonify(status="success", user=user, token=token.decode('ascii'), 
            investor_struct=investor_struct)


# END AUTH 


@user_crud.route('/add', methods=['GET', 'POST'])
def add():
    data = request.json

    ds = get_client()

    email = str(data['email'])
    key = ds.key('User', email)
    results = ds.get(key)
    user = from_datastore(results)

    if user != None:
        return jsonify( status= "fail", error= "Email already exists.")

    data['password'] = hash_password(data['password'])
    user = upsert(data)
    token = generate_auth_token(user['email'])


    # return redirect(url_for('.view', id=user['id']))
    return jsonify( status= "success", id= user['email'], token=token, user=user)


@user_crud.route('/add_company', methods=['GET', 'POST'])
def add_company():
    data = request.json

    ds = get_client()

    email = str(data['email'])
    key = ds.key('User', email)
    results = ds.get(key)
    user = from_datastore(results)

    if user != None:
        return jsonify( status= "fail", error= "Email already exists.")

    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])

    # CREATE THE DEFAULT PROFILE PIC IN STORAGE
    f = open('polygons.png', 'r+')
    image_data = f.read()
    blob = bucket.blob("profile_pic " + email)

    blob.upload_from_string(
        image_data)
    blob.make_public()

    url = blob.public_url
    if isinstance(url, six.binary_type):
        url = url.decode('utf-8')
    print "url is {}".format(url) 

    data['profile_pic'] = url
    data['password'] = hash_password(data['password'])
    user = upsert(data)


    

    company_stuct_id = email + "_Company_struct"
    blob = bucket.get_blob(company_stuct_id)
    if blob == None:
            blob = storage.blob.Blob(company_stuct_id, bucket)

    company_stuct = {
        'members': {
            'board_members': { 'invited': {}, 'members': {} }, 
            'investors': { 'invited': {}, 'members': {} }, 
            'employees': { 'invited': {}, 'members': {} }
        },
        'member_permissions': {
            'investor_permissions': 
                {'create_events': False, 'upload_documents': False, 
                'sign_documents': False, 'send_create_reminders': False, 'wire_money': False,
                'view_documents_presentations_financials': False},
            'external_services_permissions' :
                {'create_events': False, 'upload_documents': False, 
                'sign_documents': False, 'send_create_reminders': False, 'wire_money': False,
                'view_documents_presentations_financials': False},
            'team_member_permissions' :
                {'create_events': False, 'upload_documents': False, 
                'sign_documents': False, 'send_create_reminders': False, 'wire_money': False,
                'view_documents_presentations_financials': False}
        },
        'presentation_items': {
            'photos': {},
            'presentation_title': "Hi! We're " + user['company_name'].upper()
        },
        'deal_flow_management': {},
        'funding_rounds': []
    }

    company_stuct_str = json.dumps(company_stuct)
    blob.upload_from_string(company_stuct_str)

    token = generate_auth_token(user['email'])

    # return redirect(url_for('.view', id=user['id']))
    return jsonify( status= "success", id= user['email'], token=token, user=user,
        company_struct=company_stuct)


@user_crud.route('/add_investor', methods=['GET', 'POST'])
def add_investor():
    data = request.json

    ds = get_client()

    email = str(data['email'])
    key = ds.key('User', email)
    results = ds.get(key)
    user = from_datastore(results)

    if user != None:
        return jsonify( status= "fail", error= "Email already exists.")


    # CREATE THE INVESTOR STRUCT IN STORAGE
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])

    investor_struct_id = email + "_Investor_struct"
    blob = bucket.get_blob(investor_struct_id)
    if blob == None:
            blob = storage.blob.Blob(investor_struct_id, bucket)

    investor_struct = {
        'jobs': [],
        'boards': [],
        'investments': [],
    }

    investor_struct_str = json.dumps(investor_struct)
    blob.upload_from_string(investor_struct_str)


    # CREATE THE DEFAULT PROFILE PIC IN STORAGE
    f = open('polygons.png', 'r+')
    image_data = f.read()
    blob = bucket.blob("profile_pic " + email)

    blob.upload_from_string(
        image_data)
    blob.make_public()

    url = blob.public_url
    if isinstance(url, six.binary_type):
        url = url.decode('utf-8')
    print "url is {}".format(url) 

    data['description'] = ""
    data['primary_role'] = ""
    data['website'] = ""
    data['facebook_link'] = ""
    data['instagram_link'] = ""
    data['linkedin_link'] = ""
    data['twitter_link'] = ""
    data['profile_pic'] = url

    data['password'] = hash_password(data['password'])
    user = upsert(data)


    token = generate_auth_token(user['email'])

    # return redirect(url_for('.view', id=user['id']))
    return jsonify( status= "success", id= user['email'], token=token, user=user,
        investor_struct=investor_struct)



@user_crud.route('/get_notifications', methods=['GET'])
@cross_origin()
@auth.login_required
def get_notifications():
    email = g.user['email']

    notifications, page = get_sql_model().list_notifications(email)

    for note in notifications:
        note['created_date'] = str(note['created_date'])
        print note['created_date']
    
    return jsonify(status= "success", notifications= notifications)




@user_crud.route('/set_profile_pic', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def set_profile_pic():
    email = g.user['email']
    data = request.json
    print "data is".format(data)

    user = get_user(email)

    if user == None:
        return jsonify(status="failure", message="user with email {} not found".format(email))
    
    uploaded_file =request.files['file']

    image_data = uploaded_file.read()
    #print image_data
    print type(image_data)
    #return jsonify(status="failure", message="user with email {} not found".format(email))

    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])
    
    profile_pic_id = "profile_pic " + email
    blob = bucket.get_blob(profile_pic_id)
    if blob == None:
            blob = storage.blob.Blob(profile_pic_id, bucket)

    blob.upload_from_string(
        image_data)
    blob.make_public()

    url = blob.public_url
    if isinstance(url, six.binary_type):
        url = url.decode('utf-8')
    print "url is {}".format(url) 

    user['profile_pic'] = url
    upsert(user)
    return jsonify(status='success', user=user, url=url)


@user_crud.route('/set_carousel_image', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def set_carousel_image():
    email = g.user['email']
    data = request.json
    print "data is".format(data)

    user = get_user(email)

    if user == None:
        return jsonify(status="failure", message="user with email {} not found".format(email))
    
    uploaded_file =request.files['file']
    image_data = uploaded_file.read()
    #print image_data
    print type(image_data)
    #return jsonify(status="failure", message="user with email {} not found".format(email))

    # Upload the image to a storage object
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])
    unique_id = email + str(uuid.uuid1())
    blob = bucket.blob(unique_id)

    blob.upload_from_string(
        image_data)
    blob.make_public()

    url = blob.public_url
    if isinstance(url, six.binary_type):
        url = url.decode('utf-8')
    print "url is {}".format(url) 

    # save the url to the company struct
    company_stuct_id = email + "_Company_struct"
    blob = bucket.get_blob(company_stuct_id)
    if blob == None:
        return jsonify(status='failure', message="no company_struct blob found.")
    
        
    company_struct_str = blob.download_as_string()
    company_struct = json.loads(company_struct_str)

    # add the url to the struct
    image_struct = {'url': url, 'id': unique_id, 'caption': ""}
    company_struct['presentation_items']['photos'][unique_id] = image_struct


    company_struct_str = json.dumps(company_struct)
    blob.upload_from_string(company_struct_str)
    
    return jsonify(status='success', company_struct=company_struct)



@user_crud.route('/delete_carousel_image', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def delete_carousel_image():
    email = g.user['email']
    data = request.json


    
    try:
        unique_id = data['unique_id']
    except KeyError, e:
        return jsonify(status="failure", message="no unique_id param.")

    # Upload the image to a storage object
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])
    
    try:
        bucket.delete_blob(unique_id)
    except NotFound:
        pass

    # delete the reference in the company struct
    company_stuct_id = email + "_Company_struct"
    blob = bucket.get_blob(company_stuct_id)
    if blob == None:
        return jsonify(status='failure', message="no company_struct blob found.")
    
        
    company_struct_str = blob.download_as_string()
    company_struct = json.loads(company_struct_str)

    try:
        del company_struct['presentation_items']['photos'][unique_id]
    except KeyError, e:
        return jsonify(status='failure', message="no picture struct exists with unique_id {}.".format(unique_id))
   
    company_struct_str = json.dumps(company_struct)
    blob.upload_from_string(company_struct_str)
    
    return jsonify(status='success', company_struct_presentation_items=company_struct['presentation_items'])


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
    

def get_profile_pic(email):
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket('ready-set-files-bucket')

    user_pic_id = "{}_{}".format(email, "prof_pic")
    blob = bucket.get_blob(user_pic_id)

    blob.download_as_string()





@user_crud.route('/edit', methods=['GET', 'POST'])
@cross_origin()
@auth.login_required
def edit():
    email = g.user['email']
    data = request.json

    try:
        user_data = data['user']
    except KeyError, e:
        return jsonify(status="failure", message="no file_id param.")


    user_data = json.loads(user_data)

    ds = get_client()
    key = ds.key('User', email)
    results = ds.get(key)
    user = from_datastore(results)

    user = get_user(email)

    if user == None:
        return jsonify( status="fail", message= "User not found.")


    user = upsert(user_data, email)


    try:
        new_presentation_title = data['presentation_title']
    except KeyError, e:
        return jsonify(status="failure", message="no presentation_title param.")

    try:
        new_member_permissions_str = data['member_permissions']
    except KeyError, e:
        return jsonify(status="failure", message="no member_permissions param.")


    new_member_permissions = json.loads(new_member_permissions_str)


    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])
    
    company_struct_id = email + "_Company_struct"
    blob = bucket.get_blob(company_struct_id)
    
    if blob == None:
        return jsonify(status='failure', message="no company_struct blob found.")

    company_struct_str = blob.download_as_string()
    company_struct = json.loads(company_struct_str)

    company_struct['presentation_items']['presentation_title'] = new_presentation_title
    company_struct['member_permissions'] = new_member_permissions

    
    company_struct_str = json.dumps(company_struct)
    blob.upload_from_string(company_struct_str)

    return jsonify(status= "success", id= user['email'])
   




@user_crud.route('/investor_edit', methods=['GET', 'POST'])
@cross_origin()
@auth.login_required
def investor_edit():
    email = g.user['email']
    data = request.json

    try:
        user_data = data['user_data']
    except KeyError, e:
        return jsonify(status="failure", message="no user_data param.")


    print user_data

    ds = get_client()
    key = ds.key('User', email)
    results = ds.get(key)
    user = from_datastore(results)

    user = get_user(email)

    if user == None:
        return jsonify( status="fail", message= "User not found.")

    user = upsert(user_data, email)


    return jsonify(status= "success", user=user)
   

@user_crud.route('/investor_add_job', methods=['GET', 'POST'])
@cross_origin()
@auth.login_required
def investor_add_job():
    email = g.user['email']

    form_data = request.form

    print "print request.files is " 
    print request.files 
    
    try:
        new_job_company = form_data['new_job_company']
    except KeyError, e:
        return jsonify(status="failure", message="no new_job_company param.")

    try:
        new_job_role = form_data['new_job_role']
    except KeyError, e:
        return jsonify(status="failure", message="no new_job_role param.")

    
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])

    # UPLOAD THE IMAGE 
    uploaded_file =request.files['file']
    image_data = uploaded_file.read()

    job_pic_id = email + "_" + new_job_company + "_" + new_job_role
    blob = bucket.get_blob(job_pic_id)
    if blob == None:
            blob = storage.blob.Blob(job_pic_id, bucket)

    blob.upload_from_string(
        image_data)
    blob.make_public()

    url = blob.public_url
    if isinstance(url, six.binary_type):
        url = url.decode('utf-8')
    print "url is {}".format(url) 
    # END UPLOAD IMAGE
    

    investor_struct_id = email + "_Investor_struct"
    blob = bucket.get_blob(investor_struct_id)
    if blob == None:
            return jsonify(status="failure", message="no investor blob found.")
    
    investor_stuct_str = blob.download_as_string()
    investor_struct = json.loads(investor_stuct_str)

    if type(investor_struct['jobs']) == dict:
        investor_struct['jobs'] = []

    investor_struct['jobs'].append({"company_name": new_job_company, "company_role": new_job_role, 
        "company_pic_url": url})

    investor_struct_str = json.dumps(investor_struct)
    blob.upload_from_string(investor_stuct_str)

    return jsonify(status= "success", jobs=investor_struct['jobs'])



@user_crud.route('/investor_add_board', methods=['GET', 'POST'])
@cross_origin()
@auth.login_required
def investor_add_board():
    email = g.user['email']
    data = request.json

    try:
        new_board_role = data['new_board_role']
    except KeyError, e:
        return jsonify(status="failure", message="no new_board_role param.")

    try:
        new_board_company = data['new_board_company']
    except KeyError, e:
        return jsonify(status="failure", message="no new_board_company param.")
    


    # CREATE THE INVESTOR STRUCT IN STORAGE
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])

    investor_struct_id = email + "_Investor_struct"
    blob = bucket.get_blob(investor_struct_id)
    if blob == None:
            return jsonify(status="failure", message="no investor blob found.")
    
    investor_stuct_str = blob.download_as_string()
    investor_struct = json.loads(investor_stuct_str)

    print investor_struct['boards']

    if type(investor_struct['boards']) == dict:
        investor_struct['boards'] = []

    investor_struct['boards'].append({"company_name": new_board_company, "company_role": new_board_role})

    investor_struct_str = json.dumps(investor_struct)
    blob.upload_from_string(investor_struct_str)

    return jsonify(status= "success", boards=investor_struct['boards'])




@user_crud.route('/investor_add_investment', methods=['GET', 'POST'])
@cross_origin()
@auth.login_required
def investor_add_investment():
    email = g.user['email']
    data = request.json

    try:
        new_investment_date = data['new_investment_date']
    except KeyError, e:
        return jsonify(status="failure", message="no new_investment_date param.")

    try:
        new_investment_company = data['new_investment_company']
    except KeyError, e:
        return jsonify(status="failure", message="no new_investment_company param.")

    try:
        new_investment_round = data['new_investment_round']
    except KeyError, e:
        return jsonify(status="failure", message="no new_investment_round param.")

    try:
        new_investment_details = data['new_investment_details']
    except KeyError, e:
        return jsonify(status="failure", message="no new_investment_details param.")
    


    # CREATE THE INVESTOR STRUCT IN STORAGE
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])

    investor_struct_id = email + "_Investor_struct"
    blob = bucket.get_blob(investor_struct_id)
    if blob == None:
            return jsonify(status="failure", message="no investor blob found.")
    
    investor_stuct_str = blob.download_as_string()
    investor_struct = json.loads(investor_stuct_str)


    if type(investor_struct['investments']) == dict:
        investor_struct['investments'] = []

    investor_struct['investments'].append({"date": new_investment_date, "amount": new_investment_company, 
        "round": new_investment_round, "details": new_investment_details})

    investor_struct_str = json.dumps(investor_struct)
    blob.upload_from_string(investor_struct_str)

    return jsonify(status= "success", investments=investor_struct['investments'])


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



@user_crud.route('/invite_member', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def invite_member():
    email = g.user['email']
    data = request.json

    try:
        member_type = data['member_type']
    except KeyError, e:
        return jsonify(status="failure", message="no member_type param.")

    try:
        invite_email = data['invite_email']
    except KeyError, e:
        return jsonify(status="failure", message="no invite_email param.")

    try:
        company_name = data['company_name']
    except KeyError, e:
        return jsonify(status="failure", message="no company_name param.")

    try:
        inviter_name = data['inviter_name']
    except KeyError, e:
        return jsonify(status="failure", message="no inviter_name param.")


    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])
    
    company_struct_id = email + "_Company_struct"
    blob = bucket.get_blob(company_struct_id)
    
    if blob == None:
        return jsonify(status='failure', message="no company_struct blob found.")

    company_struct_str = blob.download_as_string()
    company_struct = json.loads(company_struct_str)

    a = datetime.date.today()
    date = str(a.year) + "-" + str(a.month) + "-" + str(a.day)

    notification = {
        'invited_email': invite_email, 
        'message': "has have been added to {} for".format(member_type.upper()), 
        'notif_type': "invite" , 'member_type': member_type,
        'seen': 0, 
        'action_taken': None, 'action_required': True,
        'company_name': company_name, 'company_email': email,
        'created_date': date, 'created_by_name': inviter_name, 'created_by_email': email,
        }

    get_sql_model().create(notification)

    company_struct['members'][member_type]['invited'][invite_email] = True

    company_struct_str = json.dumps(company_struct)
    blob.upload_from_string(company_struct_str)
    
    return jsonify(status='success', company_struct=company_struct)



@user_crud.route('/update_member_invite', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def update_member_invite():
    email = g.user['email']
    data = request.json

    try:
        notification = data['notification']
    except KeyError, e:
        return jsonify(status="failure", message="no notification param.")

    try:
        action_taken = data['action_taken']
    except KeyError, e:
        return jsonify(status="failure", message="no action_taken param.")

    
    user = get_user(email)
    
    if user == None:
        return jsonify(status="failure", message="no user found param.")
    
    try:
        name = user['firstname'] + " " + user['lastname']
    except KeyError, e:
        raise "can't access name of user"

    notification['seen'] = 1
    notification['action_taken'] = action_taken
    get_sql_model().update(notification, notification['id'])



    company_email = notification['company_email']
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket(current_app.config['CLOUD_STORAGE_BUCKET'])


    company_struct_id = company_email + "_Company_struct"
    blob = bucket.get_blob(company_struct_id)

    if blob == None:
        return jsonify(status='failure', message="no company_struct blob found.")

    company_struct_str = blob.download_as_string()
    company_struct = json.loads(company_struct_str)

    
    if action_taken == "accept":
        
        email_suffix_url = email.replace("@", "%40")
        profile_pic_url = "https://storage.googleapis.com/readyset-files/profile_pic%20" + email_suffix_url
        member_type = notification['member_type']
        company_struct['members'][member_type]['accepted'][notification['invited_email']] = {"name": name, 
            'user_photo_url': profile_pic_url} 

        company_struct_str = json.dumps(company_struct)
        blob.upload_from_string(company_struct_str)

        company_struct_str = json.dumps(company_struct)
        blob.upload_from_string(company_struct_str)


        # investor_struct_id = email + "_Investor_struct"
        # blob = bucket.get_blob(investor_struct_id)

        # investor_struct_str = blob.download_as_string()
        # investor_struct = json.loads(investor_struct_str)

        # if member_type == "employees"
        #     role = "jobs"
        #     entry = {"company_email": company_email, }
        # elif member_type == "board_members":
        #     role = "boards"
        # elif member_type == "investors":
        #     role = "investments"

        # investor_struct[role] = {}

           
    return jsonify(status='success', company_struct=company_struct)



@user_crud.route('/get_profile_pic', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def get_profile_pic():
    email = g.user['email']

    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket('ready-set-files-bucket')
    print bucket
    prof_pic_id = "profile_picture_{}".format(email)
    blob = bucket.get_blob(prof_pic_id)
    print type(blob)
    if blob == None:
        return jsonify(status="failure", message="No prof_pic data blob found.")

    b64_data = blob.download_as_string()

    
    return jsonify(status='success', data=b64_data)



@user_crud.route('/upload_files', methods=['GET', 'OPTIONS', 'POST'])
@cross_origin()
@auth.login_required
def upload_files():
    email = g.user['email']
    token = generate_auth_token(email)
    print request.files
    # data = request.json
    # print data
    uploaded_file =request.files['file']
    print type(uploaded_file)

    return jsonify(status='success')


    try:
        file_id = data['file_id']
    except KeyError, e:
        return jsonify(status="failure", message="no file_id param.")

    
    entity_file_id = "{}_{}".format(device_id, file_id)
    _file = get_file(entity_file_id)

    if _file == None:
        return jsonify(status="failure", message="file not found")

    ds = get_client()
    chunk_id = "{}_{}_{}".format(device_id, file_id, current_chunk)
    
    # Check if file already exists
    chunk = get_chunk(entity_file_id)

    if chunk != None:
        return jsonify(status="failure", message="chunk {} already exists".format(chunk_id))

    
    # Create the Chunk Entity
    key = ds.key('Chunk', chunk_id)
    entity = datastore.Entity(key=key)

    print storage
    client = storage.Client(project=current_app.config['PROJECT_ID'])
    bucket = client.bucket('parachute-server')
    print bucket
    blob = bucket.get_blob(chunk_id)
    print blob 
    print type(blob)
    if blob == None:
        blob = storage.blob.Blob(chunk_id, bucket)

    blob.upload_from_string(str(file_data))
    print blob.path


    chunk = {'device_id': device_id, 'file_id': file_id, 'num_chunks': num_chunks,
        'current_chunk': current_chunk, 'file_data_url': blob.path, 'chunk_size': chunk_size}
    #device_string = str(device)
    chunk_json = json.dumps(chunk)
    entity.update(chunk)
    ds.put(entity)

    result = from_datastore(entity)

    _file['chunk_sizes'][current_chunk] = chunk_size
    _file['chunk_ids'][current_chunk] = chunk_id
    complete = True
    for i in range(num_chunks):
        print _file['chunk_sizes'][i]
        if _file['chunk_sizes'][i] == 0:
            complete = False 
            _file['complete'] = False
            break

    if complete:
        _file['complete'] = True

    file_upsert(_file, entity_file_id)

    return jsonify(status="true", chunk_id=chunk_id, complete=_file['complete'])