from flask import (
    flash,
    g,
    jsonify,
    redirect,
    request,
    Response,
    session,
    url_for,
    )
from functools import wraps
import re

from lastuserapp.models import AuthToken, Client


# Bearer token, as per http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-15#section-2.1
auth_bearer_re = re.compile("^Bearer ([a-zA-Z0-9_.~+/-]+=*)$")


def requires_login(f):
    """
    Decorator to require a login for the given view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash(u"You need to be logged in for that page")
            session['next'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def requires_client_login(f):
    """
    Decorator to require a client login via HTTP Basic Authorization.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.authorization is None:
            return Response(u"Client credentials required.", 401,
                {'WWW-Authenticate': 'Basic realm="Client credentials"'})
        client = Client.query.filter_by(key=request.authorization.username).first()
        if client is None or not client.active or not client.secret_is(request.authorization.password):
            return Response(u"Invalid client credentials.", 401,
                {'WWW-Authenticate': 'Basic realm="Client credentials"'})
        g.client = client
        return f(*args, **kwargs)
    return decorated_function


def provides_resource(name):
    """
    Decorator for resource functions.
    """
    def resource_auth_error(message):
        return Response(message, 401,
            {'WWW-Authenticate': 'Bearer realm="Token Required" scope="%s"' % name})

    def wrapper(f):
        @wraps(f)
        def decorated_function():
            if request.method == 'GET':
                args = request.args
            elif request.method in ['POST', 'PUT', 'DELETE']:
                args = request.form
            if 'Authorization' in request.headers:
                token_match = auth_bearer_re.search(request.headers['Authorization'])
                if token_match:
                    token = token_match.group(1)
                else:
                    # Unrecognized Authorization header
                    return resource_auth_error(u"A Bearer token is required in the Authorization header.")
                if 'access_token' in args:
                    return resource_auth_error(u"Access token specified in both header and body.")
            else:
                token = args.get('access_token')
                if not token:
                    # No token provided in Authorization header or in request parameters
                    return resource_auth_error(u"An access token is required to access this resource.")
            authtoken = AuthToken.query.filter_by(token=token).first()
            if not authtoken:
                return resource_auth_error(u"Unknown access token.")
            if name not in authtoken.scope:
                return resource_auth_error(u"Token does not provide access to this resource.")
            # All good. Return the result value
            try:
                result = f(authtoken, args, request.files)
                response = jsonify({'status': 'ok', 'result': result})
            except Exception as exception:
                response = jsonify({'status': 'error',
                                    'error': exception.__class__.__name__,
                                    'error_description': unicode(exception)
                                    })
            # XXX: Let resources control how they return?
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Pragma'] = 'no-cache'
            return response

        global __resources
        __resources[name] = f
        return decorated_function
    return wrapper
