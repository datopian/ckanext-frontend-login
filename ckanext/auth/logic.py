import logging

import ckan.lib.authenticator as authenticator
from ckan.common import _, config
from ckan.plugins import toolkit


log = logging.getLogger(__name__)


def user_login(context, data_dict):
    session = context['session']

    # Adapted from  https://github.com/ckan/ckan/blob/master/ckan/views/user.py#L203-L211
    generic_error_message = {
        'errors': {'auth': [_('Username or password entered was incorrect')]},
        'error_summary': {_('auth'): _('Incorrect username or password')},
    }

    if not data_dict.get('id') or not data_dict.get('password'):
        return generic_error_message

    model = context['model']
    if "@" in data_dict.get("id", ""):
        user = session.query(model.User).filter(model.User.email == data_dict.get("id", "")).first()
    else:
        user = model.User.get(data_dict['id'])

    if not user:
        return generic_error_message

    user = user.as_dict()

    if config.get('ckanext.auth.include_frontend_login_token', False):
        user = generate_token(context, user)

    if data_dict['password']:
        identity = {'login': user['name'], 'password': data_dict['password']}

        auth = authenticator

        try:
            authUser = auth.default_authenticate(identity)
            authUser_name = model.User.get(authUser.id).name

            if authUser_name != user['name']:
                return generic_error_message
            else:
                return user
        except Exception as e:
            log.error(e)
            return generic_error_message


def generate_token(context, user):
    context['ignore_auth'] = True
    user['frontend_token'] = None

    try:
        api_tokens = toolkit.get_action('api_token_list')(
            context, {'user_id': user['name']}
        )

        for token in api_tokens:
            if token['name'] == 'frontend_token':
                toolkit.get_action('api_token_revoke')(context, {'jti': token['id']})

        frontend_token = toolkit.get_action('api_token_create')(
            context, {'user': user['name'], 'name': 'frontend_token'}
        )

        user['frontend_token'] = frontend_token.get('token')

    except Exception as e:
        log.error(e)

    return user
