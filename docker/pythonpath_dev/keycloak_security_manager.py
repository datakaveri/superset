from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask import (
    redirect,
    request

)
from flask import current_app, session
import logging
from flask.sessions import SecureCookieSessionInterface
import os


logger = logging.getLogger()


class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))

            if user is None:
                info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
                user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),
                                   info.get('email'), sm.find_role('Gamma'))

            login_user(user, remember=False)

            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):

        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        # redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login
        
        cookie_value = request.cookies.get('session')
        session_serializer = SecureCookieSessionInterface() \
                        .get_signing_serializer(current_app)
        decoded_session = session_serializer.loads(cookie_value)
        id_token = decoded_session['oidc_auth_token']['id_token']

        session.clear()

        redirect_url = os.getenv('SUPERSET_REDIRECT_URL')
        return redirect(
            f"{oidc.client_secrets.get('issuer')}/protocol/openid-connect/logout"
            f"?post_logout_redirect_uri={quote(redirect_url)}"
            f"&id_token_hint={quote(id_token)}"
        )
            