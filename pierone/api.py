import codecs
import json
import os
from clickclick import Action
import yaml
from zign.api import get_named_token


def docker_login(url, realm, name, user, password, token_url=None, use_keyring=True):
    with Action('Getting OAuth2 token "{}"..'.format(name)):
        token = get_named_token(['uid'], realm, name, user, password, url=token_url, use_keyring=use_keyring)
    access_token = token.get('access_token')
    path = os.path.expanduser('~/.dockercfg')
    try:
        with open(path) as fd:
            dockercfg = yaml.safe_load(fd)
    except:
        dockercfg = {}
    basic_auth = codecs.encode('oauth2:{}'.format(access_token).encode('utf-8'), 'base64').strip().decode('utf-8')
    dockercfg[url] = {'auth': basic_auth,
                      'email': 'no-mail-required@example.org'}
    with Action('Storing Docker client configuration in {}..'.format(path)):
        with open(path, 'w') as fd:
            json.dump(dockercfg, fd)
