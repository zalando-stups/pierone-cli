import codecs
import json
import os
from clickclick import Action
import collections
import requests
from zign.api import get_named_token, get_existing_token


adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
session = requests.Session()
session.mount('http://', adapter)
session.mount('https://', adapter)


class Unauthorized(Exception):
    def __str__(self):
        return 'Unauthorized: token missing or invalid'


class DockerImage(collections.namedtuple('DockerImage', 'registry team artifact tag')):
    @classmethod
    def parse(cls, image: str):
        '''
        >>> DockerImage.parse('x')
        Traceback (most recent call last):
        ValueError: Invalid docker image "x" (format must be [REGISTRY/]TEAM/ARTIFACT:TAG)
        >>> DockerImage.parse('foo/bar')
        DockerImage(registry=None, team='foo', artifact='bar', tag='')
        >>> DockerImage.parse('registry/foo/bar:1.9')
        DockerImage(registry='registry', team='foo', artifact='bar', tag='1.9')
        '''
        parts = image.split('/')
        if len(parts) == 3:
            registry = parts[0]
        elif len(parts) < 2:
            raise ValueError('Invalid docker image "{}" (format must be [REGISTRY/]TEAM/ARTIFACT:TAG)'.format(image))
        else:
            registry = None
        team = parts[-2]
        artifact, sep, tag = parts[-1].partition(':')
        return DockerImage(registry=registry, team=team, artifact=artifact, tag=tag)

    def __str__(self):
        '''
        >>> str(DockerImage(registry='registry', team='foo', artifact='bar', tag='1.9'))
        'registry/foo/bar:1.9'
        '''
        return '{}/{}/{}:{}'.format(*tuple(self))


def docker_login(url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False):
    with Action('Getting OAuth2 token "{}"..'.format(name)):
        token = get_named_token(['uid', 'application.write'],
                                realm, name, user, password, url=token_url,
                                use_keyring=use_keyring, prompt=prompt)
    access_token = token.get('access_token')
    docker_login_with_token(url, access_token)


def docker_login_with_token(url, access_token):
    '''Configure docker with existing OAuth2 access token'''

    path = os.path.expanduser('~/.docker/config.json')
    try:
        with open(path) as fd:
            dockercfg = json.load(fd)
    except:
        dockercfg = {}
    basic_auth = codecs.encode('oauth2:{}'.format(access_token).encode('utf-8'), 'base64').strip().decode('utf-8')
    if 'auths' not in dockercfg:
        dockercfg['auths'] = {}
    dockercfg['auths'][url] = {'auth': basic_auth,
                               'email': 'no-mail-required@example.org'}
    with Action('Storing Docker client configuration in {}..'.format(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fd:
            json.dump(dockercfg, fd)


def request(url, path, access_token) -> requests.Response:
    return session.get('{}{}'.format(url, path),
                       headers={'Authorization': 'Bearer {}'.format(access_token)}, timeout=10)


def image_exists(token_name: str, image: DockerImage) -> bool:
    token = get_existing_token(token_name)
    if not token:
        raise Unauthorized()

    url = 'https://{}'.format(image.registry)
    path = '/v1/repositories/{team}/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    try:
        r = request(url, path, token['access_token'])
    except:
        return False
    result = r.json()
    return image.tag in result


def get_latest_tag(token: str, image: DockerImage) -> bool:
    url = 'https://{}'.format(image.registry)
    path = '/teams/{team}/artifacts/{artifact}/tags'.format(team=image.team, artifact=image.artifact)

    try:
        r = request(url, path, token)
        r.raise_for_status()
    except:
        return None
    result = r.json()
    if result:
        return sorted(result, key=lambda x: x['created'])[-1]['name']
    else:
        return None
