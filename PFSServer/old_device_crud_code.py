@device_crud.route('/get_device')
@auth.login_required
def get_device(data = None, mode="production"):
  if data == None:
    data = request.json

  if mode == "testing":
    email = data['email']
    else:
      email = g.user['email']
    
    user = get_user(email)
    device_id = data['device_id']
    device_name = data['device_name']
 

    if device_name in user['devices']:
      device = get_device(device_id)

      # Sanity check
      if device == None:
        return jsonify(status="failure", message="no device entity found with id: {}".format(device_id))
      else:
        return jsonify(status="success", device=device)
  else:
    return jsonify(status="failure", message="device id: {}, does not belong to user: {}".format(device_id, email))



@device_crud.route('/delete_device')
@auth.login_required
def delete_device():
	data = request.json
 	email = g.user['email']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  	# Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

	if device_name in user['devices']:
		del user['devices'][device_name]
		user['devices'] = json.dumps(user['devices'])
		upsert(user, email)
		key = ds.key('Device', device_id)
		ds.delete(key)
		return jsonify(status="success", message="Device id: {}, successfully deleted.".format(device_id))
	else:
		return jsonify(status="failure", message="Device name: {}, does not belong to user: {}".format(device_name, email))

# A node can be a folder or file 
@device_crud.route('/create_node')
@auth.login_required
def create_node():
  data = request.json
  email = g.user['email']
  path = data['path']
  mode = data['mode']
  node = data['node']
  device_id = data['device_id']


  ds = get_client()
  user = get_user(email)
  user['devices'] = ast.literal_eval(user['devices'])

  if user != None:

  	# Check if the device exists for this user
  	if device_unique_id not in user['devices']:
  		return jsonify(status='error, device_id not found')

  		# Get the device 
     	device = get_device(device_id)

     	# Sanity check
     	if device == None:
     		return jsonify(status="failure", message="device entity not found")
      
     	# Go to end of path 
     	node['children'] = {}
     	device['children'] = ast.literal_eval(device['children'])
     	curr_folder = device
     	if len(path) > 1: 
     		# Split the path string and create array 
     		path_array = path.split('/')
     		path_array = remove_null(path_array)

     		# recurse to the correct folder 
     		# Assumes device is not included in path 
       	for item in path_array:
       		curr_folder = curr_folder['children'][item]

     	
  	# Next, take the appropriate action
  	if mode == "Create":
  		curr_folder['children'][node['name']] = node

  		device['children'] = json.dumps(device['children'])
  		device = device_upsert(device, device['id'])
  		return jsonify(status="success", email=user['email'], current_folder=curr_folder)
  	else:
  		return jsonify(status="failure", message="node method not found.")
      
  else:
   	return jsonify(status="failure", email=user['email'], message='no user found')



def recurse_to_path(curr_folder, path):
	if len(path) > 1: 
		# Split the path string and create array 
		path_array = path.split('/')
		path_array = remove_null(path_array)

		# recurse to the correct folder 
		# Assumes device is not included in path 
		print path_array
		for item in path_array:
			if item in curr_folder['children']:
				curr_folder = curr_folder['children'][item]
			else:
				return "Error"
	return curr_folder

# A node can be a folder or file 
# PARAMS= path: string, device_id: int, device_name: String, path: String
# RETURNS= device_count: Int, devices: dict 
@device_crud.route('/list_children')
@auth.login_required
def list_children():
	data = request.json
 	email = g.user['email']
 	path = data['path']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)

 	if data['device_name'] not in user['devices']:
 		return jsonify(status="failure", message="device_name: {}, does not belong to user: {}".format(data['device_name'], email))
  # Get the device 
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	# Recurse to path
 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} not valid on device id: {}".format(path, device_id))
  
 	children = json.dumps(curr_folder['children'])
 	return jsonify(status="success", children=children)

# A node can be a folder or file 
@device_crud.route('/delete_node')
@auth.login_required
def delete_node():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		del curr_folder['children'][node_name]
 		device['children'] = json.dumps(device['children'])
 		device_upsert(device, device_id)
 		return jsonify(status="success", message="deleted node {}".format(node_name))
 	else:
 		return jsonify(status="failure", message="node does not exist at this path.")


#PARAMS: old_name: String, new_name: String, device_id: String, device_name: String
@device_crud.route('/rename_node')
@auth.login_required
def rename_node():
	data = request.json
 	email = g.user['email']
 	old_name = data['old_name']
 	new_name = data['new_name']
 	path = data['path']
 	device_id = data['device_id']


 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if old_name in curr_folder['children']:
 		curr_folder['children'][new_name] = curr_folder['children'][old_name]
 		curr_folder['children'][new_name]['name'] = new_name
 		curr_folder['children'][new_name]['name'] = new_name
 		del curr_folder['children'][old_name]
 		device['children'] = json.dumps(device['children'])
 		device_upsert(device, device_id)
 		return jsonify(status="success", message="node renamed from {} to {}".format(old_name, new_name) )
 	else:
 		return jsonify(status="failure", message="node does not exist at this path.")


@device_crud.route('/create_symlink')
@auth.login_required
def create_symlink():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path'] # this is the path of where the actual node exists
 	symlink_path = data['symlink_path'] # this is the path where the symlink will be created
 	symlink_name = data['symlink_name']
 	device_id = data['device_id']
 	device_name = data['device_name']


 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		# Flag real node, that it has a symlink
 		curr_folder['children'][node_name]['symlink_exists'] = 1
 		curr_folder['children'][node_name]['symlink_path'] = symlink_path

 		# Flag the symlink as a symlink
 		symlink_folder = recurse_to_path(device, symlink_path)
 		if symlink_folder == "Error":
 			return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(symlink_path, device_id))

 		symlink_folder['children'][symlink_name] = {'is_symlink': 1, 'actual_path': path, 'actual_name': node_name}
 		device['children'] = json.dumps(device['children'])
 		device_upsert(device)
 		return jsonify(status="success", message="symlink created from {} to {}".format(symlink_path, path))
 	else:
 		return jsonify(status="failure", message="path not valid")





@device_crud.route('/get_node')
@auth.login_required
def get_node():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path'] # this is the path of where the actual node exists
 	device_id = data['device_id']
 	device_name =data['device_name']


 	ds = get_client()
 	user = get_user(email)
 	if data['device_name'] not in user['devices']:
 		return jsonify(status="failure", message="device_name: {}, does not belong to user: {}".format(data['device_name'], email))
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		return jsonify(status="success", node=curr_folder['children'][node_name])
 	else:
 		return jsonify(status="failure", message="node does not exist at this path", path=path, node_name=node_name)

@device_crud.route('/edit_node')
@auth.login_required
def edit_node():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path'] # this is the path of where the actual node exists
 	device_id = data['device_id']
 	prop_name = data['prop_name']
 	prop_value = data['prop_value']


 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		curr_folder[children][node_name][prop_name] = prop_value
 		device['children'] = str(device['children'])
 		device_upsert(device)
 		return jsonify(status="success", message="node updated")
 	else:
 		return jsonify(status="failure", message="path not valid")