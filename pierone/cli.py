import sys
import tarfile
import tempfile
import shutil

import click
import requests
import stups_cli.config
import zign.api
from clickclick import AliasedGroup, OutputFormat, UrlType, error, fatal_error, print_table, ok
from requests import RequestException

import pierone
from .api import PierOne, DockerMeta, docker_login_with_credhelper, get_latest_tag, parse_time, request
from .exceptions import PieroneException, ArtifactNotFound
from .types import DockerImage
from .ui import DetailsBox, format_full_image_name, markdown_2_cli
from .utils import get_registry
from .validators import validate_team

KEYRING_KEY = 'pierone'

CONTEXT_SETTINGS = {'help_option_names': ['-h', '--help']}

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')

url_option = click.option('--url', help='Pier One URL', metavar='URI')


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Pier One CLI {}'.format(pierone.__version__))
    ctx.exit()


def set_pierone_url(config: dict, url: str) -> str:
    '''Read Pier One URL from cli, from config file or from stdin.'''
    url = url or config.get('url')

    while not url:
        url = click.prompt('Please enter the Pier One URL', type=UrlType())

        try:
            requests.get(url, timeout=5)
        except Exception:
            error('Could not reach {}'.format(url))
            url = None

    if '://' not in url:
        # issue 63: gracefully handle URLs without scheme
        url = 'https://{}'.format(url)

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
@click.pass_obj
def login(config, url):
    '''Login to Pier One Docker registry (generates docker configuration in ~/.docker/config.json)'''
    url_option_was_set = url
    url = set_pierone_url(config, url)

    if not url_option_was_set:
        stups_cli.config.store_config(config, 'pierone')

    # Check if the credential helper is available
    if shutil.which("docker-credential-pierone") is None:
        fatal_error("docker-credential-pierone executable is not available. "
                    "If you've installed `pierone` to a virtual environment, make sure to add it to to the PATH.")

    docker_login_with_credhelper(url)
    ok("Authentication configured for {}, you don't need to run pierone login anymore!".format(url))


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


def get_tags(url, team, art, access_token):
    r = request(url, '/teams/{}/artifacts/{}/tags'.format(team, art), access_token, True)
    if r is None:
        # empty list of tags (artifact does not exist)
        return []
    return r.json()


@cli.command()
@click.argument('team', callback=validate_team)
@url_option
@output_option
@click.pass_obj
def artifacts(config, team, url, output):
    """List all team artifacts"""
    url = set_pierone_url(config, url)
    api = PierOne(url)
    result = api.get_artifacts(team)
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
    registry = set_pierone_url(config, url)
    api = PierOne(registry)

    if limit is None:
        # show 20 rows if artifact was given, else show only 3
        limit = 20 if artifact else 3

    if not artifact:
        artifact = api.get_artifacts(team)
        if not artifact:
            raise click.UsageError('The Team you are looking for does not exist or '
                                   'we could not find any artifacts registered in Pierone! '
                                   'Please double check for spelling mistakes.')

    slice_from = - limit

    rows = []
    for art in artifact:
        image = DockerImage(registry=registry, team=team, artifact=art, tag=None)
        try:
            tags = api.get_image_tags(image)
        except ArtifactNotFound:
            raise click.UsageError("Artifact or Team does not exist! "
                                   "Please double check for spelling mistakes.")
        else:
            rows.extend(tags[slice_from:])

    # sorts are guaranteed to be stable, i.e. tags will be sorted by time (as returned from REST service)
    rows.sort(key=lambda row: (row['team'], row['artifact']))

    with OutputFormat(output):
        titles = {
            "created_time": "Created",
            "created_by": "By",
        }
        print_table(
            [
                "team",
                "artifact",
                "tag",
                "created_time",
                "created_by",
                "status",
                "status_reason",
            ],
            rows,
            titles=titles
        )


@cli.command()
@click.argument("team", callback=validate_team)
@click.argument("artifact")
@click.argument("tag")
@url_option
@output_option
@click.pass_obj
def cves(config, team, artifact, tag, url, output):
    """DEPRECATED"""
    print("\x1b[1;33m!! THIS FUNCTIONALITY IS DEPRECATED !!\x1b[0m", file=sys.stderr)


@cli.command("mark-production-ready")
@click.argument("incident")
@click.argument("team", callback=validate_team)
@click.argument("artifact")
@click.argument("tag")
@url_option
@click.pass_obj
def mark_production_ready(config, incident, team, artifact, tag, url):
    """
    Manually mark image as production ready.
    """
    pierone_url = set_pierone_url(config, url)
    registry = get_registry(pierone_url)
    image = DockerImage(registry, team, artifact, tag)
    if incident.startswith("INC-"):
        # if it's a JIRA ticket, mark image as production ready in Pierone
        api = PierOne(pierone_url)
        api.mark_production_ready(image, incident)
    else:
        meta = DockerMeta()
        meta.mark_production_ready(image, incident)
    if team in ["ci", "automata", "torch"]:
        click.echo("🧙 ", nl=False)
    click.echo(
        "Marked {} as `production_ready` due to incident {}.".format(
            format_full_image_name(image), incident
        )
    )


@cli.command()
@click.argument("team", callback=validate_team)
@click.argument("artifact")
@click.argument("tag")
@url_option
@click.pass_obj
def describe(config, team, artifact, tag, url):
    """Describe docker image."""
    url = set_pierone_url(config, url)
    registry = get_registry(url)
    api = PierOne(url)
    meta = DockerMeta()

    image = DockerImage(registry=registry, team=team, artifact=artifact, tag=tag)

    tag_info = api.get_tag_info(image)

    image_metadata = meta.get_image_metadata(image)
    ci_info = image_metadata.get("ci")
    compliance = image_metadata.get("compliance")
    base_image_info = image_metadata.get("base_image")

    status_details = markdown_2_cli(compliance.get("checker", {}).get("details", ""))

    details_box = DetailsBox()
    details_box.set("General Information", "Team", team)
    details_box.set("General Information", "Artifact", artifact)
    details_box.set("General Information", "Tag", tag)
    details_box.set("General Information", "Author", tag_info["created_by"])
    details_box.set("General Information", "Created in", tag_info["created"])
    if ci_info:
        details_box.set("Commit Information", "Repository", ci_info["url"])
        details_box.set("Commit Information", "Hash", ci_info["revision"])
        commit_created = ci_info.get("created")
        if commit_created:
            details_box.set("Commit Information", "Time", commit_created)
        details_box.set("Commit Information", "Author", ci_info["author"])
    else:
        details_box.set("Compliance Information", "Valid SCM Source", "No SCM Source")
    details_box.set(
        "Compliance Information",
        "Effective Status",
        compliance.get("status", "Not Processed"),
    )
    details_box.set(
        "Compliance Information",
        "Checker Status",
        compliance.get("checker", {}).get("status", "Not Processed"),
    )
    details_box.set(
        "Compliance Information",
        "Checker Status Date",
        compliance.get("checker", {}).get("received_at", "NOT SET"),
    )
    details_box.set(
        "Compliance Information",
        "Checker Status Reason",
        compliance.get("checker", {}).get("reason", "NOT SET"),
    )
    # TODO make markdown function return a string
    details_box.set(
        "Compliance Information",
        "Checker Status Details",
        status_details if status_details else "",
    )
    if compliance.get("user"):
        user_status = compliance["user"]
        details_box.set("Compliance Information", "User Status", user_status["status"])
        details_box.set(
            "Compliance Information",
            "User Status Date",
            user_status["received_at"],
        )
        details_box.set(
            "Compliance Information",
            "User Status Reason",
            user_status["reason"],
        )
        details_box.set(
            "Compliance Information",
            "User Status Issue",
            # TODO make non-optional after PR merge
            user_status.get("incident", "NOT SET"),
        )
        details_box.set(
            "Compliance Information",
            "User Status Set by",
            user_status["set_by"],
        )
    else:
        details_box.set("Compliance Information", "User Status", "Not Set")
    if compliance.get("emergency"):
        emergency_status = compliance["emergency"]
        details_box.set(
            "Compliance Information", "Emergency Status", emergency_status["status"]
        )
        details_box.set(
            "Compliance Information",
            "Emergency Status Date",
            emergency_status["received_at"],
        )
        details_box.set(
            "Compliance Information",
            "Emergency Status Reason",
            emergency_status["reason"],
        )
    else:
        details_box.set("Compliance Information", "Emergency Status", "Not Set")

    base_image = base_image_info.get("name") or "UNKNOWN"
    details_box.set("Compliance Information", "Base Image Name", base_image)
    details_box.set(
        "Compliance Information",
        "Base Image Allowed",
        "Yes" if base_image_info["allowed"] else "No",
    )
    details_box.set(
        "Compliance Information", "Base Image Details", base_image_info["message"]
    )

    details_box.render()


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

    registry = get_registry(config.get('url'))
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
    url = set_pierone_url(config, url)
    api = PierOne(url)
    token = get_token()

    tags = get_tags(url, team, artifact, token)
    if not tags:
        raise click.UsageError('Artifact or Team does not exist! '
                               'Please double check for spelling mistakes.')

    if not tag:
        tag = [t['name'] for t in tags]

    rows = []
    for t in tag:
        image = DockerImage(url, team, artifact, t)
        try:
            scm_source = api.get_scm_source(image)
            row = scm_source
        except ArtifactNotFound:
            row = {}
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


@cli.command('image')
@click.argument('image')
@url_option
@output_option
@click.pass_obj
def image(config, image, url, output):
    """
    List tags that point to this image
    NOTE: this is broken for large namespaces
    """
    # TODO reimplement with `GET /v2/_catalog` and `GET /v2/<name>/tags/list`
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
