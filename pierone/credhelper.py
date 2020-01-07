import json
import zign.api


def main():
    token = zign.api.get_token("pierone", ["uid", "application.write"])
    response = {
        "Username": "oauth2",
        "Secret": token,
    }
    print(json.dumps(response))
