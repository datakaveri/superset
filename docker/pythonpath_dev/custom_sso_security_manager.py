import logging
from superset.security import SupersetSecurityManager

class CustomSsoSecurityManager(SupersetSecurityManager):

    def oauth_user_info(self, provider, response=None):
        #In case if userDetail url is nor working case use response attribute to get the user details like name,mail etc
        logging.debug("Oauth2 provider: {0}.".format(provider))
        if provider == 'egaSSO':
            # As example, this line request a GET to base_url + '/' + userDetails with Bearer  Authentication,
            # and expects that authorization server checks the token, and response with user details
            me = self.appbuilder.sm.oauth_remotes[provider].get('userDetails').data
            logging.debug("user_data: {0}".format(me))
            #check the values of user_name, mail and others values in me variable
            return { 'name' : me['User_name'], 'email' : me['mail'], 'id' : me['user_name'], 'username' : me['user_name'], 'first_name':'', 'last_name':''}