import ast 
from PFSServer import storage
from gcloud import datastore
from passlib.apps import custom_app_context as pwd_context
from flask import Blueprint, current_app, redirect, render_template, request, \
    url_for, json, jsonify, g 
from flask.ext.httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from user_crud import *

auth = HTTPBasicAuth()
# Copied from model_datastore.py
builtin_list = list # idk what this does 
device_crud = Blueprint('device_crud', __name__)


# # START AUTH 
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
  # if isinstance(entity, builtin_list):
  #     entity = entity.pop()

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


def device_upsert(data, id=None):
	ds = get_client()
	if id:
		key = ds.key('Device', id)
	else:
		key = ds.key('Device', data['id'])

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


@device_crud.route('/list_devices')
@auth.login_required
# PARAMS= None
# RETURNS= device_count: Int, devices: dict 
def list_devices(data = None, mode="production"):

	if mode == "testing":
		email = data['email']
   	else:
   		email = g.user['email']
   	
   	user = get_user(email)

   	if user != None:
   	    return jsonify( status="success", device_count=user['device_count'], devices=str(user['devices']))
   	else:
   	    return jsonify( status="failure", message="user not found")
    
 
@device_crud.route('/get_root')
@auth.login_required
# PARAMS= device_id, device_name
# RETURNS=  device_root: dict
def get_root(data= None):
	data = request.json

	email = g.user['email']

	user = get_user(email)
	if user == None:
		return jsonify(status="failure", message="user with email: {}, not found".format(email))
	
	device = get_device(data['device_id'])

	if device != None:
		device_root = ast.literal_eval(device['children'])
		return jsonify(status="success", device_root= device_root, last_sync=device['last_sync'])
	else:
		return jsonify(status="failure", message="device with id: {}, not found.")
	

def get_device(device_id):
	ds = get_client()
	key = ds.key('Device', device_id)
 	results = ds.get(key)
 	device = from_datastore(results)
 	return device

def get_user(email):
	ds = get_client()
	key = ds.key('User', str(email))
	results = ds.get(key)
 	user = from_datastore(results)
 	user['devices'] = ast.literal_eval(user['devices'])
 	return user

@device_crud.route('/create_device')
@auth.login_required
def create_device():
  	data = request.json
  	email = g.user['email']
  	device_name = data['device_name']

  	ds = get_client()
    
	# Get the current user
  	user = get_user(email)

  	# Check if user exists
  	if user != None:
  		# Just in case 
	    if device_name in user['devices']:
	    	return jsonify(status='failure', message='device name already exists.')
	    else:

	    	# Create the Device root 'Folder' Entity
	    	key = ds.key('Device')
	    	entity = datastore.Entity(key=key)
	    	device = {'name': device_name, 'children': '{}', 'last_sync': 0}
	    	#device_string = str(device)
	    	device_json = json.dumps(device)
	    	entity.update(device_json)
	    	ds.put(entity)

	    	result = from_datastore(entity)

	    	device["id"] = result["id"]
	    	device = device_upsert(device)

	    	user['device_count'] += 1
	    	user['devices'][device_name] = {'id': device['id'], 'name': device['name']}
	    	user_json = json.dumps(user['devices'])
	    	user['devices'] = user_json
	    	user = upsert(user, email)
	    	return jsonify(status="success", email=user['email'], device_count=user['device_count'], devices=user['devices'], device_id=device['id'])
  	else:
  		return jsonify(status="failure", email=user['email'], message='no user found')




@device_crud.route('/sync')
@auth.login_required
def sync():
	data = request.json

	# Get Params safely
	try:
		email = g.user['email']
	except KeyError, e:
		return jsonify(status="failure", message="No authentication data.")
	
	try:
		device_id = data['device_id']
	except KeyError, e:
		return jsonify(status="failure", message="No device_id param.")
 	
 	try:
		commands_array = data['commands_array']
	except KeyError, e:
		return jsonify(status="failure", message="No commands_array param.")
 	
 	
 	
 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  	# Sanity check
  	if user == None:
 		return jsonify(status="failure", message="User entity not found.")
 	if device == None:
 		return jsonify(status="failure", message="Device entity not found.")



 	try:
		device['children'] = json.loads(device['children'])
	except KeyError, e:
		return jsonify(status="failure", message="Device entity has no children property.")

 	
 	try:
		last_sync = device['last_sync']
	except KeyError, e:
		return jsonify(status="failure", message="Device entity has no last_sync property.")
 	
 	
 	for command in commands_array:
 		c_id = command[0]
 		instr = command[3]
 		instr = json.loads(instr)

 		if c_id < last_sync:
 			pass
 		if c_id != last_sync + 1:
 			return jsonify(status="failure", error_occurence=c_id, last_sync=last_sync)

 		c_type = instr['type']

 		curr_folder = device

 		
 		path = instr['path']
 		path_array = path.split('/')
 		path_array = remove_null(path_array)

 		# recurse to final path level
	   	if len(path_array) > 1: 
	   		# recurse to the correct folder 
	   		# Assumes device is not included in path 
	   		for i in range(len(path_array)-1):
	   			# if isinstance(curr_folder['children'], str):
	   			if type(curr_folder['children']) == str or type(curr_folder['children']) == unicode:
	   				curr_folder['children'] = json.loads(curr_folder['children'])
	   			if type(curr_folder) == str or type(curr_folder) == unicode:
	   				curr_folder = json.loads(curr_folder)
	   			
	   			curr_folder = curr_folder['children'][path_array[i]]

	   		if type(curr_folder) == str or type(curr_folder) == unicode:
	   				curr_folder = json.loads(curr_folder)
	   		

	   	if type(curr_folder['children']) == str or type(curr_folder['children']) == unicode:
	   		curr_folder['children'] = json.loads(curr_folder['children'])
	   	# else:		
	   	
	   	# 	curr_folder = json.loads(curr_folder)
	   	print( device['children'])
		print "curr folder type is {}".format(type(curr_folder))
	   	# print(type(curr_folder))
	   	# if isinstance(curr_folder, unicode):
	   	# 	curr_folder = json.loads(curr_folder)
	   	# if isinstance(curr_folder, str):
	   	# 	curr_folder = json.loads(curr_folder)
	   	# if isinstance(curr_folder['children'], unicode):
	   	# 	curr_folder['children'] = json.loads(curr_folder['children'])
	   	# if isinstance(curr_folder['children'], str):
	   	# 			curr_folder['children'] = json.loads(curr_folder['children'])

	 	if c_type == "create":
			node = {'name': path_array[-1], "is_file": 1, 'is_dir': 0, "mode": instr['mode'],
				"file_id": instr['inserted_id'],'children': json.dumps({})}
			curr_folder['children'][node['name']] = node

	  		# device['children'] = json.dumps(device['children'])
	  		# device = device_upsert(device, device['id'])
			# curr_folder['children'][path_array[-1]] = {'name': path_array[-1], "is_file": 1, 'is_dir': 0,"mode": instr['mode'], "file_id": instr['inserted_id'],'children': '{}'}
	 		print("curr_folder is {}".format(curr_folder))
	 		print("Device is now {}".format(str(device)))
	 		

	  	elif c_type == "utimens":
	  		curr_folder['children'][path_array[-1]]["m_time"] = instr["m_time"]
	  		curr_folder['children'][path_array[-1]]["a_time"] = instr["a_time"]


	  	elif c_type == "chmod":
	  		curr_folder['children'][path_array[-1]]["mode"] = instr['mode']
	  		
	  	elif c_type == "rmdir":
	  		del curr_folder['children'][path_array[-1]]
	  		
		elif c_type == "rename":
			new_path = instr['new_path']
	 		new_path_array = new_path.split('/')
	 		new_path_array = remove_null(new_path_array)

	 		# print("in path, new path is {}".format(new_path_array))
	 		# print("current_folder is: {}".format(str(curr_folder)))

	 		# print("type of children is: {}".format(type(curr_folder['children'])))
	 		# # if isinstance(curr_folder['children'][path_array[-1]], unicode):
	   # # 				curr_folder['children'][path_array[-1]] = json.loads(curr_folder['children'][path_array[-1]])



	 		# save, then delete the old director 
	 		curr_folder['children'][path_array[-1]]['name'] = new_path_array[-1]
	 		curr_folder['children'][new_path_array[-1]] = curr_folder['children'][path_array[-1]]
	 		
	 		del curr_folder['children'][path_array[-1]]
		

			if new_path_array[-1] not in curr_folder['children']:
				return jsonify(status="Rename error, new_name not found after renaming.", error_occurence=c_id, last_sync=last_sync)

		elif c_type == "unlink":		
			del curr_folder['children'][node_name]
			print "deleted node {}".format(node_name)

	  	elif c_type == "mkdir":
	  		#curr_folder['children'] = json.loads(curr_folder['children'])
	   		curr_folder['children'][path_array[-1]] = {'name': path_array[-1], "is_file": 0, 'is_dir': 1, "mode": instr['mode'], 'children': json.dumps({}) }

	  	elif c_type == "symlink":
			target_path = instr['target'] # this is the path where the symlink will be created

	   		curr_folder['children'][path_array[-1]] = {'name': path_array[-1], 
	   			'target_path': target_path, "is_symlink": 1,"is_file": 0, 'is_dir': 0}
			# print("symlink created from {} to {}".format(symlink_path, path

		last_sync = c_id
		device['last_sync'] = last_sync
		device = recursive_dict_to_json(device)
		#print("c_id: {}, completed. device is now {}".format(c_id, device))
		device_upsert(device, device_id)

	return jsonify(status="success", last_sync=last_sync)


@device_crud.route('/reset')
@auth.login_required
def reset():
	data = request.json
 	email = g.user['email']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")
 	else:
 		device['children'] = '{}'
 		device['last_sync'] = 0
 		device_upsert(device, device_id)
 		return jsonify(status="success", last_sync=device['last_sync'])

