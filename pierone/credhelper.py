import json
import sys

import click
import zign.api


@click.command()
@click.argument("cmd")
def main(cmd):
    if cmd == "get":
        token = zign.api.get_token("pierone", ["uid", "application.write"])
        response = {
            "Username": "oauth2",
            "Secret": token,
        }
        print(json.dumps(response))
    else:
        print("Unsupported command: {}".format(cmd), file=sys.stderr)
