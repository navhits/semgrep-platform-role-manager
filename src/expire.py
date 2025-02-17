from datetime import datetime, timezone

from commons import (USER_DATA, check_env, load_json, save_json,
                     update_membership)


def process_expired_admins(file_path: str) -> None:
    """process_expired_admins will check all the admins with their time of expiry and update their role to ORG_ROLE_MEMBER if expired.

    Args:
        file_path (str): The path to the JSON file containing user data.
    """
    data = load_json(file_path)
    expired_users = []

    for user_hash, user_data in data.get("users", {}).items():
        if user_data.get("permission") == "ORG_ROLE_ADMIN" and not user_data.get("exception", False):
            until_str = user_data.get("until")
            if until_str:
                until_time = datetime.fromisoformat(
                    until_str).replace(tzinfo=timezone.utc)
                if until_time < datetime.now(timezone.utc):
                    expired_users.append(
                        {"hash": user_hash, "id": user_data.get("id"), "name": user_data.get("name"), "role": user_data.get("permission")})

    if expired_users:
        for user in expired_users:
            user_hash = user["hash"]
            user_id = user["id"]
            user_name = user["name"]
            user_role = user["role"]
            update_membership(user_id, "ORG_ROLE_MEMBER")
            print(
                f"Updated user: {user_name}, role: {user_role} -> ORG_ROLE_MEMBER")
            if user_hash in data["users"]:
                data["users"][user_hash]["permission"] = "ORG_ROLE_MEMBER"
                data["users"][user_hash].pop("until", None)
                data["users"][user_hash].pop("exception", None)

        save_json(file_path, data)
    else:
        print("No expired admins found.")


if __name__ == "__main__":
    check_env()
    process_expired_admins(USER_DATA)
