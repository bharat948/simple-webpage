import os
import random
import string

import requests


def random_username(prefix="user"):
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}_{suffix}"


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def run_tests(base_url: str):
    username = random_username()
    password = "test-password"
    name = "Test User"

    # Sign up
    signup_response = requests.post(
        f"{base_url}/auth/signup",
        json={"username": username, "password": password, "name": name},
        timeout=5,
    )
    expect(signup_response.status_code == 201, "Signup request failed.")
    signup_body = signup_response.json()
    expect("user" in signup_body, "Signup response missing user data.")
    user = signup_body["user"]
    user_id = user["id"]
    expect(user["username"] == username, "Username mismatch after signup.")
    expect("password" not in user, "Password leaked in signup response.")

    # Sign in
    signin_response = requests.post(
        f"{base_url}/auth/signin",
        json={"username": username, "password": password},
        timeout=5,
    )
    expect(signin_response.status_code == 200, "Signin request failed.")
    expect(
        signin_response.json().get("user", {}).get("id") == user_id,
        "Signin did not return the expected user.",
    )

    # Sign in with wrong password
    bad_signin_response = requests.post(
        f"{base_url}/auth/signin",
        json={"username": username, "password": "wrong"},
        timeout=5,
    )
    expect(
        bad_signin_response.status_code == 401,
        "Signin with wrong password should fail with 401.",
    )

    # List users
    users_response = requests.get(f"{base_url}/users", timeout=5)
    expect(users_response.status_code == 200, "Fetching users failed.")
    users_body = users_response.json()
    expect("users" in users_body, "Users response missing users field.")
    expect(any(candidate["id"] == user_id for candidate in users_body["users"]),
           "Created user missing from users list.")

    # Fetch specific user
    user_response = requests.get(f"{base_url}/users/{user_id}", timeout=5)
    expect(user_response.status_code == 200, "Fetching user by id failed.")
    fetched_user = user_response.json().get("user", {})
    expect(fetched_user.get("id") == user_id, "Incorrect user returned by id.")

    print("All tests passed!")


if __name__ == "__main__":
    base_url = os.environ.get("BASE_URL", "http://localhost:3000")
    run_tests(base_url)
