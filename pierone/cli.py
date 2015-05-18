import codecs
import datetime
import json
import click
import os
import requests
import yaml

import pierone

from zign.api import get_named_token

from clickclick import error, AliasedGroup, print_table, OutputFormat, Action

KEYRING_KEY = 'pierone'
CONFIG_DIR_PATH = click.get_app_dir('pierone')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'pierone.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Pier One CLI {}'.format(pierone.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx, config_file):
    path = os.path.expanduser(config_file)
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    ctx.obj = data


@cli.command()
@click.option('--url', help='Pier One URL', metavar='URI')
@click.option('--realm', help='Use custom OAuth2 realm', metavar='NAME')
@click.option('-n', '--name', help='Custom token name (will be stored)', metavar='TOKEN_NAME', default='pierone')
@click.option('-U', '--user', help='Username to use for authentication', envvar='USER', metavar='NAME')
@click.option('-p', '--password', help='Password to use for authentication', envvar='PIERONE_PASSWORD', metavar='PWD')
@click.pass_obj
def login(obj, url, realm, name, user, password):
    '''Login to Pier One Docker registry (generates ~/.dockercfg'''
    try:
        with open(CONFIG_FILE_PATH) as fd:
            config = yaml.safe_load(fd)
    except:
        config = {}

    url = url or config.get('url')

    while not url:
        url = click.prompt('Please enter the Pier One URL')
        if not url.startswith('http'):
            url = 'https://{}'.format(url)

        try:
            requests.get(url, timeout=5)
        except:
            error('Could not reach {}'.format(url))
            url = None

        config['url'] = url

    os.makedirs(CONFIG_DIR_PATH, exist_ok=True)
    with open(CONFIG_FILE_PATH, 'w') as fd:
        yaml.dump(config, fd)

    with Action('Getting OAuth2 token "{}"..'.format(name)):
        token = get_named_token(['uid'], realm, name, user, password)

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


def request(url, path, access_token):
    return requests.get(url + path, headers={'Authorization': 'Bearer {}'.format(access_token)})


@cli.command()
@output_option
@click.pass_obj
def teams(config, output):
    '''List all teams having artifacts in Pier One'''
    token = get_named_token(['uid'], None, 'pierone', None, None)

    r = request(config.get('url'), '/teams', token['access_token'])
    rows = [{'name': name} for name in sorted(r.json())]
    with OutputFormat(output):
        print_table(['name'], rows)


def get_artifacts(url, team, access_token):
    r = request(url, '/teams/{}/artifacts'.format(team), access_token)
    return r.json()


@cli.command()
@click.argument('team')
@output_option
@click.pass_obj
def artifacts(config, team, output):
    '''List all team artifacts'''
    token = get_named_token(['uid'], None, 'pierone', None, None)

    result = get_artifacts(config.get('url'), team, token['access_token'])
    rows = [{'team': team, 'artifact': name} for name in sorted(result)]
    with OutputFormat(output):
        print_table(['team', 'artifact'], rows)


@cli.command()
@click.argument('team')
@click.argument('artifact', nargs=-1)
@output_option
@click.pass_obj
def tags(config, team, artifact, output):
    '''List all tags'''
    token = get_named_token(['uid'], None, 'pierone', None, None)

    if not artifact:
        artifact = get_artifacts(config.get('url'), team, token['access_token'])

    rows = []
    for art in artifact:
        r = request(config.get('url'), '/teams/{}/artifacts/{}/tags'.format(team, art), token['access_token'])
        rows.extend([{'team': team,
                      'artifact': art,
                      'tag': row['name'],
                      'created_by': row['created_by'],
                      'created_time': datetime.datetime.strptime(row['created'], '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()}
                     for row in r.json()])

    rows.sort(key=lambda row: (row['team'], row['artifact'], row['tag']))
    with OutputFormat(output):
        print_table(['team', 'artifact', 'tag', 'created_time', 'created_by'], rows,
                    titles={'created_time': 'Created', 'created_by': 'By'})


def main():
    cli()
