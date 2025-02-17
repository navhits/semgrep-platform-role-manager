import os
from datetime import datetime, timedelta, timezone

from commons import (USER_DATA, check_env, get_users, hash_str, load_json,
                     save_json)


def update_permissions(file_path: str, user_id: str, name: str,
                       email: str, role: str) -> None:
    """update_permissions will update the role of a user in Semgrep Platform and add it to the user data file.

    Args:
        file_path (str): The path to the JSON file containing user data.
        user_id (str): User ID in Semgrep Platform.
        name (str): Name of the user
        email (str): Email of the user as in Semgrep Platform
        role (str): The role to be assigned to the user. Use 'ORG_ROLE_ADMIN' or 'ORG_ROLE_MEMBER'.
    """
    data = load_json(file_path)
    user_hash = hash_str(email)
    default_days = int(os.getenv("SEMGREP_DEFAULT_ADMIN_DAYS", 15))
    until_date = (datetime.now(timezone.utc) +
                  timedelta(days=default_days)).isoformat()

    if user_hash not in data["users"]:
        data["users"][user_hash] = {
            "id": user_id,
            "name": name,
            "permission": role
        }
        if role == "ORG_ROLE_ADMIN":
            # Always true for new admins
            data["users"][user_hash]["exception"] = True

        print(f"Added user: {name}, role: {role}")
    else:
        existing_role = data["users"][user_hash]["permission"]
        if existing_role != role:
            if existing_role == "ORG_ROLE_ADMIN" and role == "ORG_ROLE_MEMBER":
                # When local data says admin and platform says member
                # Best case scenario is to honor the role in platform
                # Because user can be made admin any time
                data["users"][user_hash].pop("until", None)
                data["users"][user_hash].pop("exception", None)

                print(f"Updated user: {name}, role: {existing_role} -> {role}")
            elif existing_role == "ORG_ROLE_MEMBER" and role == "ORG_ROLE_ADMIN":
                # Always false when upgrading to admin
                # This is because if someone was made admin from the platform
                # without consent or approval, then their role must change back automatically
                # You can change this behaviour by setting SEMGREP_HONOR_UKNONWN_PLATFORM_ADMIN to true
                if os.getenv("SEMGREP_HONOR_UKNONWN_PLATFORM_ADMIN"):
                    data["users"][user_hash]["exception"] = True
                else:
                    data["users"][user_hash]["exception"] = False
                    data["users"][user_hash]["until"] = until_date

                print(
                    f"[ROLE_DISCREPANCY] Updated user: {name}, role: {existing_role} -> {role}, until: {until_date}.")

            data["users"][user_hash]["permission"] = role

    save_json(file_path, data)


if __name__ == "__main__":
    check_env()
    users = get_users()
    for user in users["users"]:
        update_permissions(
            USER_DATA, user["id"], user["name"], user["email"], user["orgRole"])
