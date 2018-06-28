import os
import re
import tarfile
import tempfile

import click
import pierone
import requests
import stups_cli.config
import zign.api
import sys
from clickclick import (AliasedGroup, OutputFormat, UrlType, error,
                        fatal_error, print_table)
from requests import RequestException

from .api import (DockerImage, Unauthorized, docker_login, get_image_tags,
                  get_latest_tag, parse_time, request)
from .exceptions import PieroneException

KEYRING_KEY = 'pierone'

CONTEXT_SETTINGS = {'help_option_names': ['-h', '--help']}

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')

url_option = click.option('--url', help='Pier One URL', metavar='URI')

TEAM_PATTERN_STR = r'[a-z][a-z0-9-]+'
TEAM_PATTERN = re.compile(r'^{}$'.format(TEAM_PATTERN_STR))


def validate_team(ctx, param, value):
    if not TEAM_PATTERN.match(value):
        msg = 'Team ID must satisfy regular expression pattern "{}"'.format(TEAM_PATTERN_STR)
        raise click.BadParameter(msg)
    return value


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Pier One CLI {}'.format(pierone.__version__))
    ctx.exit()


def validate_pierone_url(url: str) -> None:
    ping_url = url.rstrip('/') + '/swagger.json'
    try:
        response = requests.get(ping_url, timeout=5)
        response.raise_for_status()
        if 'Pier One API' not in response.text:
            fatal_error('ERROR: Did not find a valid Pier One registry at {}'.format(url))
    except RequestException:
        fatal_error('ERROR: Could not reach {}'.format(ping_url))


def set_pierone_url(config: dict, url: str) -> None:
    '''Read Pier One URL from cli, from config file or from stdin.'''
    url = url or config.get('url')

    while not url:
        url = click.prompt('Please enter the Pier One URL', type=UrlType())

        try:
            requests.get(url, timeout=5)
        except Exception as e:
            error('Could not reach {}'.format(url))
            url = None

    if '://' not in url:
        # issue 63: gracefully handle URLs without scheme
        url = 'https://{}'.format(url)

    validate_pierone_url(url)
    config['url'] = url
    return url


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx):
    ctx.obj = stups_cli.config.load_config('pierone')


@cli.command()
@url_option
@click.option('--realm', help='Use custom OAuth2 realm', metavar='NAME')
@click.option('-n', '--name', help='Custom token name (will be stored)', metavar='TOKEN_NAME', default='pierone')
@click.option('-U', '--user', help='Username to use for authentication', envvar='PIERONE_USER', metavar='NAME')
@click.option('-p', '--password', help='Password to use for authentication', envvar='PIERONE_PASSWORD', metavar='PWD')
@click.pass_obj
def login(config, url, realm, name, user, password):
    '''Login to Pier One Docker registry (generates docker configuration in ~/.docker/config.json)'''
    url_option_was_set = url
    url = set_pierone_url(config, url)
    user = user or zign.api.get_config().get('user') or os.getenv('USER')

    if not url_option_was_set:
        stups_cli.config.store_config(config, 'pierone')

    docker_login(url, realm, name, user, password, prompt=True)


def get_token():
    try:
        token = zign.api.get_token('pierone', ['uid'])
    except Exception as e:
        raise click.UsageError(str(e))
    return token


@cli.command()
@url_option
@output_option
@click.pass_obj
def teams(config, output, url):
    '''List all teams having artifacts in Pier One'''
    set_pierone_url(config, url)
    token = get_token()

    r = request(config.get('url'), '/teams', token)
    rows = [{'name': name} for name in sorted(r.json())]
    with OutputFormat(output):
        print_table(['name'], rows)


def get_artifacts(url, team: str, access_token):
    r = request(url, '/teams/{}/artifacts'.format(team), access_token)
    return r.json()


def get_tags(url, team, art, access_token):
    r = request(url, '/teams/{}/artifacts/{}/tags'.format(team, art), access_token, True)
    if r is None:
        # empty list of tags (artifact does not exist)
        return []
    return r.json()


def get_clair_features(clair_details_url, access_token):
    if not clair_details_url:
        return []

    r = request(clair_details_url, '?vulnerabilities&features', access_token, True)
    if r is None:
        # empty list of tags (layer does not exist)
        return []

    return r.json()['Layer'].get('Features', [])


@cli.command()
@click.argument('team', callback=validate_team)
@url_option
@output_option
@click.pass_obj
def artifacts(config, team, url, output):
    '''List all team artifacts'''
    set_pierone_url(config, url)
    token = get_token()

    result = get_artifacts(config.get('url'), team, token)
    rows = [{'team': team, 'artifact': name} for name in sorted(result)]
    with OutputFormat(output):
        print_table(['team', 'artifact'], rows)


@cli.command()
@click.argument('team', callback=validate_team)
@click.argument('artifact', nargs=-1)
@url_option
@output_option
@click.option('-l', '--limit', type=int, help='Limit number of versions to show per artifact')
@click.pass_obj
def tags(config, team: str, artifact, url, output, limit):
    '''List all tags for a given team'''
    set_pierone_url(config, url)
    token = get_token()

    if limit is None:
        # show 20 rows if artifact was given, else show only 3
        limit = 20 if artifact else 3

    if not artifact:
        artifact = get_artifacts(config.get('url'), team, token)
        if not artifact:
            raise click.UsageError('The Team you are looking for does not exist or '
                                   'we could not find any artifacts registered in Pierone! '
                                   'Please double check for spelling mistakes.')

    registry = config.get('url')
    if registry.startswith('https://'):
        registry = registry[8:]

    slice_from = - limit

    rows = []
    for art in artifact:
        image = DockerImage(registry=registry, team=team, artifact=art, tag=None)
        try:
            tags = get_image_tags(image, token)
        except Unauthorized as e:
            raise click.ClickException(str(e))
        else:
            if not tags:
                raise click.UsageError('Artifact or Team does not exist! '
                                       'Please double check for spelling mistakes.')
            rows.extend(tags[slice_from:])

    # sorts are guaranteed to be stable, i.e. tags will be sorted by time (as returned from REST service)
    rows.sort(key=lambda row: (row['team'], row['artifact']))

    with OutputFormat(output):
        titles = {
            'created_time': 'Created',
            'created_by': 'By'
        }
        print_table(['team', 'artifact', 'tag', 'created_time', 'created_by', 'trusted'], rows, titles=titles)


@cli.command()
@click.argument('team', callback=validate_team)
@click.argument('artifact')
@click.argument('tag')
@url_option
@output_option
@click.pass_obj
def cves(config, team, artifact, tag, url, output):
    '''List all CVE's found by Clair service for a specific artifact tag'''
    print('\x1b[1;33m' + '!! THIS FUNCTIONALITY IS DEPRECATED !!' + '\x1b[0m', file=sys.stderr)


@cli.command()
@click.argument('team', callback=validate_team)
@click.argument('artifact')
@url_option
@output_option
@click.pass_obj
def latest(config, team, artifact, url, output):
    '''Get latest tag/version of a specific artifact'''
    # validate that the token exists!
    set_pierone_url(config, url)
    token = get_token()

    registry = config.get('url')
    if registry.startswith('https://'):
        registry = registry[8:]
    image = DockerImage(registry=registry, team=team, artifact=artifact, tag=None)

    latest_tag = get_latest_tag(image, token)
    if latest_tag:
        print(latest_tag)
    else:
        raise PieroneException('Latest tag not found')


@cli.command('scm-source')
@click.argument('team', callback=validate_team)
@click.argument('artifact')
@click.argument('tag', nargs=-1)
@url_option
@output_option
@click.pass_obj
def scm_source(config, team, artifact, tag, url, output):
    '''Show SCM source information such as GIT revision'''
    set_pierone_url(config, url)
    token = get_token()

    tags = get_tags(config.get('url'), team, artifact, token)
    if not tags:
        raise click.UsageError('Artifact or Team does not exist! '
                               'Please double check for spelling mistakes.')

    if not tag:
        tag = [t['name'] for t in tags]

    rows = []
    for t in tag:
        r = request(config.get('url'), '/teams/{}/artifacts/{}/tags/{}/scm-source'.format(team, artifact, t),
                    token, True)
        if r is None:
            row = {}
        else:
            row = r.json()
        row['tag'] = t
        matching_tag = [d for d in tags if d['name'] == t]
        row['created_by'] = ''.join([d['created_by'] for d in matching_tag])
        if matching_tag:
            row['created_time'] = parse_time(''.join([d['created'] for d in matching_tag]))
        rows.append(row)

    rows.sort(key=lambda row: (row['tag'], row.get('created_time')))
    with OutputFormat(output):
        print_table(['tag', 'author', 'url', 'revision', 'status', 'created_time', 'created_by'], rows,
                    titles={'tag': 'Tag', 'created_by': 'By', 'created_time': 'Created',
                            'url': 'URL', 'revision': 'Revision', 'status': 'Status'},
                    max_column_widths={'revision': 10})


@cli.command('mark-trusted')
@click.argument('team', callback=validate_team)
@click.argument('artifact')
@click.argument('tag')
@url_option
@output_option
@click.pass_obj
def mark_trusted(config, team, artifact, tag, url, output):
    '''Mark untrusted image as trusted in Docker Registry'''
    set_pierone_url(config, url)
    token = get_token()

    tags = get_tags(config.get('url'), team, artifact, token)

    if not tags:
        raise click.UsageError('Artifact or Team does not exist! '
                               'Please double check for spelling mistakes.')

    if tag not in [t['name'] for t in tags]:
        raise click.UsageError('Provided Tag does not exist!'
                               'Please double check for spelling mistakes.')

    r = request(config.get('url'), '/teams/{}/artifacts/{}/tags/{}/scm-source'.format(team, artifact, tag),
                token, True)
    if r is None:
        raise click.ClickException('No SCM source available for tag, cannot mark as trusted.')
    else:
        row = r.json()
        tag_info = [d for d in tags if d['name'] == tag][0]
        row['tag'] = tag
        row['created_by'] = tag_info['created_by']
        row['created_time'] = parse_time(tag_info['created'])

        with OutputFormat(output):
            print_table(['tag', 'author', 'url', 'revision', 'status', 'created_time', 'created_by', 'valid'], [row],
                        titles={'tag': 'Tag', 'created_by': 'By', 'created_time': 'Created',
                                'url': 'URL', 'revision': 'Revision', 'status': 'Status', 'valid': 'Valid'},)

        valid = row.get('valid')

        if not valid:
            raise click.ClickException('SCM source information is not valid, cannot mark as trusted.')
        else:
            if click.confirm('Do you want to mark this image as trusted?'):
                request(config.get('url'), '/teams/{}/artifacts/{}/tags/{}/approval'.format(team, artifact, tag),
                        access_token=token, method='POST', data=None)
                click.secho('Marked image as trusted.', fg='green')
            else:
                click.secho('Canceled.', fg='red')


@cli.command('image')
@click.argument('image')
@url_option
@output_option
@click.pass_obj
def image(config, image, url, output):
    '''List tags that point to this image'''
    set_pierone_url(config, url)
    token = get_token()

    try:
        resp = request(config.get('url'), '/tags/{}'.format(image), token)
    except requests.HTTPError as error:
        status_code = error.response.status_code
        if status_code == 404:
            click.echo('Image {} not found'.format(image))
        elif status_code == 412:
            click.echo('Prefix {} matches more than one image.'.format(image))
        else:
            raise error
        return

    tags = resp.json()

    with OutputFormat(output):
        print_table(['team', 'artifact', 'name'],
                    tags,
                    titles={'name': 'Tag', 'artifact': 'Artifact', 'team': 'Team'})


@cli.command('inspect-contents')
@click.argument('team', callback=validate_team)
@click.argument('artifact')
@click.argument('tag', nargs=-1)
@click.option('-l', '--limit', type=int, default=1)
@url_option
@output_option
@click.pass_obj
def inspect_contents(config, team, artifact, tag, url, output, limit):
    '''List image contents (files in tar layers)'''
    set_pierone_url(config, url)
    token = get_token()

    tags = get_tags(config.get('url'), team, artifact, token)

    if not tag:
        tag = [t['name'] for t in tags]

    CHUNK_SIZE = 8192
    TYPES = {b'5': 'D', b'0': ' '}

    rows = []
    for t in tag:
        row = request(config.get('url'), '/v2/{}/{}/manifests/{}'.format(team, artifact, t),
                      token).json()
        if row.get('layers'):
            layers = reversed([lay.get('digest') for lay in row.get('layers')])
        else:
            layers = [lay.get('blobSum') for lay in row.get('fsLayers')]
        if layers:
            found = 0
            for i, layer in enumerate(layers):
                layer_id = layer
                if layer_id:
                    response = request(config.get('url'), '/v2/{}/{}/blobs/{}'.format(team, artifact, layer_id), token)
                    with tempfile.NamedTemporaryFile(prefix='tmp-layer-', suffix='.tar') as fd:
                        for chunk in response.iter_content(CHUNK_SIZE):
                            fd.write(chunk)
                        fd.flush()
                        with tarfile.open(fd.name) as archive:
                            has_member = False
                            for member in archive.getmembers():
                                rows.append({'layer_index': i, 'layer_id': layer_id, 'type': TYPES.get(member.type),
                                             'mode': oct(member.mode)[-4:],
                                             'name': member.name, 'size': member.size, 'created_time': member.mtime})
                                has_member = True
                            if has_member:
                                found += 1
                if found >= limit:
                    break

    rows.sort(key=lambda row: (row['layer_index'], row['name']))
    with OutputFormat(output):
        print_table(['layer_index', 'layer_id', 'mode', 'name', 'size', 'created_time'], rows,
                    titles={'created_time': 'Created', 'layer_index': 'Idx'},
                    max_column_widths={'layer_id': 16})


def main():
    cli()
