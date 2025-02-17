import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from commons import (USER_DATA, check_env, hash_str, load_json, save_json,
                     update_membership)


def update_permission(email: str, user_id: str, name: str, permission: str,
                      is_exception: bool = False, days: Optional[int] = None,
                      file_path: str = USER_DATA) -> None:
    """update_permission will update the permission of a user in Semgrep Platform and add it to the user data file.
    Args:
        email (str): Email ID of the user as in Semgrep Platform.
        user_id (str): User ID of user in Semgrep Platform.
        name (str): Name of the user.
        permission (str): The permission to be assigned to the user. Use 'ORG_ROLE_ADMIN' or 'ORG_ROLE_MEMBER'.
        is_exception (bool, optional): Where exception to keep the permission forever. Applies to admin only. Defaults to False.
        days (Optional[int], optional): No. of days to keep a role. Applies to admin only. Required value if [permission='ORG_ROLE_ADMIN' and is_exception=False]. Defaults to None.
        file_path (str, optional): The path to user data. Defaults to `USER_DATA`.
    """
    if permission not in ["ORG_ROLE_ADMIN", "ORG_ROLE_MEMBER"]:
        print("Invalid permission. Use 'ORG_ROLE_ADMIN' or 'ORG_ROLE_MEMBER'.")
        return

    data = load_json(file_path)
    email_hash = hash_str(email)

    if email_hash in data["users"]:
        existing_user = data["users"][email_hash]
        existing_permission = existing_user["permission"]

        if existing_permission == "ORG_ROLE_ADMIN" and permission == "ORG_ROLE_MEMBER":
            data["users"][email_hash] = {
                "permission": "ORG_ROLE_MEMBER", "id": user_id, "name": name}
            update_membership(user_id, permission)
            print(
                f"Updated user: {name}, role: {existing_permission} -> {permission}")
        elif existing_permission == "ORG_ROLE_MEMBER" and permission == "ORG_ROLE_ADMIN":
            if not is_exception and days is None:
                print(
                    "For ORG_ROLE_ADMIN, 'days' is mandatory unless 'exception' is true.")
                return
            new_user_data = {"permission": "ORG_ROLE_ADMIN",
                             "id": user_id, "name": name, "exception": is_exception}
            if not is_exception:
                new_user_data["until"] = (datetime.now(
                    timezone.utc) + timedelta(days=days)).isoformat()
            data["users"][email_hash] = new_user_data
            update_membership(user_id, permission)
            print(
                f"Updated user: {name}, role: {existing_permission} -> {permission}")
        elif existing_permission == "ORG_ROLE_ADMIN" and permission == "ORG_ROLE_ADMIN":
            if existing_user.get("exception") and not is_exception:
                if days is None:
                    print(
                        "'days' is required when removing exception")
                    return
                until_date = (datetime.now(
                    timezone.utc) + timedelta(days=days)).isoformat()
                data["users"][email_hash]["exception"] = False
                data["users"][email_hash]["until"] = until_date
                print(
                    f"Updated user: {name}, role: {existing_permission} -> {permission}, until: {until_date}")
            elif not existing_user.get("exception") and is_exception:
                data["users"][email_hash]["exception"] = True
                data["users"][email_hash].pop("until", None)
                print(
                    f"Updated user: {name}, role: {existing_permission} -> {permission}, with exception")
            else:
                print(
                    f"{name} is already assigned as ORG_ROLE_ADMIN with the same settings.")
                return
        save_json(file_path, data)
        return

    user_data = {"permission": permission, "id": user_id, "name": name}
    if permission == "ORG_ROLE_ADMIN":
        user_data["exception"] = is_exception
        if not is_exception:
            until = (datetime.now(
                timezone.utc) + timedelta(days=days)).isoformat()
            user_data["until"] = until
            print(
                f"Added user: {name}, role: {permission}, until: {until}")
        else:
            print(
                f"Added user: {name}, role: {permission}, with exception")

    data["users"][email_hash] = user_data
    update_membership(user_id, permission)
    save_json(file_path, data)


if __name__ == "__main__":
    check_env()
    
    if len(sys.argv) < 5:
        print(
            "Usage: python update.py <email> <id> <name> <permission: ORG_ROLE_ADMIN|ORG_ROLE_MEMBER> [exception=<true/false>] [days=<number>]"
        )
        sys.exit(1)

    email_id: str = sys.argv[1]
    user_id: str = sys.argv[2]
    user_name: str = sys.argv[3]
    permission_type: str = sys.argv[4]

    kwargs = {}
    for arg in sys.argv[5:]:
        if arg.startswith("exception="):
            kwargs["is_exception"] = arg.split("=")[1].lower() == "true"
        elif arg.startswith("days="):
            kwargs["days"] = int(arg.split("=")[1])

    update_permission(email_id, user_id, user_name, permission_type, **kwargs)
