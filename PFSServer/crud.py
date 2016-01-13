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
from flask import Blueprint, current_app, redirect, render_template, request, \
    url_for


# Copied from model_datastore.py
builtin_list = list # idk what this does 

crud = Blueprint('crud', __name__)


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
        key = ds.key('Book', int(id))
    else:
        key = ds.key('Book')

    entity = datastore.Entity(
        key=key,
        exclude_from_indexes=['description'])

    entity.update(data)
    ds.put(entity)
    return from_datastore(entity)

# Copied from model_datastore.py
def read(id):
    ds = get_client()
    key = ds.key('Book', int(id))
    results = ds.get(key)
    return from_datastore(results)


# Copied from model_datastore.py
def delete_helper(id):
    ds = get_client()
    key = ds.key('Book', int(id))
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



@crud.route("/")
def list():
    token = request.args.get('page_token', None)
    
    # added to fit code below
    limit = 10 
    # Copied from model_datastore.py
    ds = get_client()
    query = ds.query(kind='Book', order=['title'])
    it = query.fetch(limit=limit, start_cursor=token)
    entities, more_results, cursor = it.next_page()
    entities = builtin_list(map(from_datastore, entities))

    # End copy
    books = entities
    next_page_token = cursor if len(entities) == limit else None

    # This is the old get.
    # books, next_page_token = get_model().list(cursor=token)

    return render_template(
        "list.html",
        books=books,
        next_page_token=next_page_token)




@crud.route('/<id>')
def view(id):
    # Copied from model_datastore.py
    ds = get_client()
    key = ds.key('Book', int(id))
    results = ds.get(key)
    # End copy.

    # below was modified from: return from_datastore(results)
    book = from_datastore(results)


    #book = get_model().read(id)
    return render_template("view.html", book=book)


@crud.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        data = request.form.to_dict(flat=True)

        # If an image was uploaded, update the data to point to the new image.
        # [START image_url]
        image_url = upload_image_file(request.files.get('image'))
        # [END image_url]

        # [START image_url2]
        if image_url:
            data['imageUrl'] = image_url
        # [END image_url2]

        book = upsert(data)

        return redirect(url_for('.view', id=book['id']))

    return render_template("form.html", action="Add", book={})


@crud.route('/<id>/edit', methods=['GET', 'POST'])
def edit(id):
    book = read(id)

    if request.method == 'POST':
        data = request.form.to_dict(flat=True)

        image_url = upload_image_file(request.files.get('image'))

        if image_url:
            data['imageUrl'] = image_url

        book = upsert(data, id)

        return redirect(url_for('.view', id=book['id']))

    return render_template("form.html", action="Edit", book=book)


@crud.route('/<id>/delete')
def delete(id):
    delete_helper(id)
    return redirect(url_for('.list'))
