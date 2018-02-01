from flask import Flask, render_template, request
from flask import redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Categories, Products, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/catalog/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value for the server access token
        then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used
        directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['facebook_id']
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


@app.route('/')
@app.route('/categories/')
def showCategories():
    categories = session.query(Categories).all()
    return render_template('categories.html', categories=categories)


# Create New Categories
@app.route('/categories/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return render_template("route_login.html")
    if request.method == 'POST':
        new_category = Categories(name=request.form['categname'],
                                  user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash("New Category Created!")
        return redirect(url_for('showCategories'))
    else:
        return render_template("newcategory.html")


# Edit Category
@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    editedcateg = session.query(Categories).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return render_template("not_auth.html")
    if request.method == 'POST':
        if request.form['editcategname']:
            editedcateg.name = request.form['editcategname']
        session.add(editedcateg)
        session.commit()
        flash("Category has Successfully been Edited!")
        return redirect(url_for('showCategories'))
    else:
        return render_template('editcategory.html',
                               category_id=category_id, categ=editedcateg)


# Delete Category
@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    deletedcateg = session.query(Categories).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return render_template("not_auth.html")
    if request.method == 'POST':
        session.delete(deletedcateg)
        session.commit()
        flash("Category has Successfully been Deleted!")
        return redirect(url_for('showCategories'))
    else:
        return render_template('deletecategory.html',
                               category_id=category_id, categ=deletedcateg)


# All Products for selected Category
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/products/')
def showProducts(category_id):
    category = session.query(Categories).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    prods = session.query(Products).filter_by(category_id=category.id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicproducts.html', prods=prods,
                               category=category, creator=creator)
    else:
        return render_template("products.html", category=category, prods=prods)


# Create New Product
@app.route('/categories/<int:category_id>/products/new/',
           methods=['GET', 'POST'])
def newProduct(category_id):
    category = session.query(Categories).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return render_template("not_auth.html")
    if request.method == 'POST':
        newprod = Products(name=request.form['prodname'],
                           description=request.form['proddesc'],
                           category_id=category_id)
        session.add(newprod)
        session.commit()
        flash("New Product Created!")
        return redirect(url_for('showProducts', category_id=category_id))
    else:
        return render_template("newproduct.html", category_id=category_id)


# Edit Product
@app.route('/categories/<int:category_id>/products/<int:id>/edit/',
           methods=['GET', 'POST'])
def editProduct(category_id, id):
    editingprod = session.query(Products).filter_by(id=id).one()
    if 'username' not in login_session:
        return render_template("not_auth.html")
    if request.method == 'POST':
        if request.form['editprodname']:
            editingprod.name = request.form['editprodname']
        if request.form['editproddesc']:
            editingprod.description = request.form['editproddesc']
        session.add(editingprod)
        session.commit()
        flash("Product has successfully been Edited!")
        return redirect(url_for('showProducts', category_id=category_id))
    else:
        return render_template("editproduct.html",
                               category_id=category_id,
                               id=id, editingprod=editingprod)


# Delete Product
@app.route('/categories/<int:category_id>/products/<int:id>/delete/',
           methods=['GET', 'POST'])
def deleteProduct(category_id, id):
    deletingprod = session.query(Products).filter_by(id=id).one()
    if 'username' not in login_session:
        return render_template("not_auth.html")
    if request.method == 'POST':
        session.delete(deletingprod)
        session.commit()
        flash("Product has Successfully been Deleted!")
        return redirect(url_for('showProducts', category_id=category_id))
    else:
        return render_template("deleteproduct.html",
                               category_id=category_id,
                               id=id, deletingprod=deletingprod)


# Making an API Endpoint(Get Request)
@app.route("/categories/JSON")
def categoriesJSON():
    categs = session.query(Categories).all()

    return jsonify(Categories=[c.serialize for c in categs])


@app.route("/categories/<int:category_id>/products/JSON/")
def productsJSON(category_id):
    category = session.query(Categories).filter_by(id=category_id).one()
    prods = session.query(Products).filter_by(category_id=category.id)

    return jsonify(Products=[p.serialize for p in prods])


@app.route("/categories/<int:category_id>/products/<int:id>/JSON/")
def restandprodJSON(category_id, id):
    prod = session.query(Products).filter_by(id=id).one()

    return jsonify(Products=prod.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
