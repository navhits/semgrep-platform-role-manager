import hashlib
import http.client
import json
import os


USER_DATA = "data/users.json"


def check_env() -> None:
    """check_env will check if all the required environment variables are set.

    Raises:
        Exception: If any of the required environment variables are not set.
    """
    required_envs = [
        "SEMGREP_HOST",
        "SEMGREP_TOKEN",
        "SEMGREP_DEPLOYMENT_ID"
    ]
    for env in required_envs:
        if not os.getenv(env):
            raise Exception(f"Environment variable {env} is not set.")

def load_json(file_path: str) -> dict:
    """load_json will load JSON data from a file.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: The JSON data from the file.
    """
    try:
        with open(file_path, "r") as f:
            content = f.read()
            return json.loads(content) if content.strip() else {"users": {}}
    except FileNotFoundError:
        return {"users": {}}
    except json.JSONDecodeError:
        return {"users": {}}


def save_json(file_path: str, data: dict) -> None:
    """save_json will save JSON data to a file.

    Args:
        file_path (str): The path to the JSON file.
        data (dict): The JSON data to be saved.
    """
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

def hash_str(text: str) -> str:
    """hash_str converts string to a SHA-256 hash.

    Args:
        text (str): The string to be hashed.

    Returns:
        str: The SHA-256 hash of the input string.
    """
    return hashlib.sha256(text.encode()).hexdigest()


def update_membership(user_id: int | str, role: str) -> None:
    """update_membership will update the role of a user in Semgrep Appsec Platform.

    HTTP Request:
        PATCH /api/agent/deployments/{deploymentId}/users/{userId}/roles

    HTTP Headers:
        Accept: application/json
        Authorization: Bearer {token}

    HTTP Body:
        {
            "deploymentId": {deploymentId},
            "userId": {userId},
            "newRole": {role} (ORG_ROLE_ADMIN / ORG_ROLE_MEMBER)
        }

    Args:
        user_id (int | str): User ID for a member in Semgrep Appsec Platform.
        role (str): The new role for the user. Should be one of "ORG_ROLE_ADMIN" or "ORG_ROLE_MEMBER".

    Raises:
        Exception: If the request to update the membership fails.
    """
    conn = http.client.HTTPSConnection(
        os.getenv('SEMGREP_HOST', 'semgrep.dev'))

    payload = json.dumps(
        {
            "deploymentId": int(os.getenv('SEMGREP_DEPLOYMENT_ID')),
            "userId": int(user_id),
            "newRole": role
        }
    )

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.getenv('SEMGREP_TOKEN')}"
    }

    conn.request(
        "PATCH", f"/api/agent/deployments/{os.getenv('SEMGREP_DEPLOYMENT_ID')}/users/{user_id}/roles", payload, headers)

    res = conn.getresponse()
    data = res.read()
    if res.status != 200:
        raise Exception(
            f"Failed to update membership: {data.decode('utf-8')}")
    return


def get_users() -> dict:
    """get_users will return a list of users in Semgrep Appsec Platform.

    HTTP Request:
        GET /api/agent/deployments/{deploymentId}/users

    HTTP Headers:
        Accept: application/json
        Authorization: Bearer {token}

    Raises:
        Exception: If the request to get users fails.

    Returns:
        dict: A dictionary containing the list of users.
    """
    conn = http.client.HTTPSConnection(
        os.getenv('SEMGREP_HOST', 'semgrep.dev'))

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {os.getenv('SEMGREP_TOKEN')}"
    }
    conn.request(
        "GET", f"/api/agent/deployments/{os.getenv('SEMGREP_DEPLOYMENT_ID')}/users", None, headers)
    res = conn.getresponse()
    data = res.read()
    if res.status != 200:
        raise Exception(f"Failed to get users: {data.decode('utf-8')}")
    return json.loads(data.decode("utf-8"))
