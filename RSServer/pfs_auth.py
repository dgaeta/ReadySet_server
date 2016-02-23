#### pfs_auth.py

import ast 
from RSServer import storage
from gcloud import datastore
from passlib.apps import custom_app_context as pwd_context
from flask import Blueprint, current_app, redirect, render_template, request, \
    url_for, json, jsonify, g 
from flask.ext.httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


auth = HTTPBasicAuth()
# Copied from model_datastore.py
builtin_list = list # idk what this does 

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
	return datastore.Client(dataset_id=current_app.config['DATASTORE_DATASET_ID'])

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