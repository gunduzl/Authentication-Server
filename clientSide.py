import requests
import base64
import rsa

# Load the server public key
with open("public.pem", "rb") as f:
    PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())

def encrypt_and_send_credentials(username, password, public_key):
    credentials = f"username={username}&password={password}"
    encrypted_credentials = base64.b64encode(rsa.encrypt(credentials.encode(), public_key)).decode()
    return encrypted_credentials


def login(username, password):
    base_url = "http://127.0.0.1:8000"
    token_url = f"{base_url}/token"
    
    try:
        encrypted_credentials = encrypt_and_send_credentials(username, password, PUBLIC_KEY)
        form_data = {"username": username, "password": encrypted_credentials}
    except Exception as e:
        print(f"Error: {e}")
        return None

    response = requests.post(token_url, data=form_data)

    if response.status_code == 200:
        access_token = response.json()["access_token"]
        print("\n\033[1;36m Username and password validated \033[0m \n")
        print("\033[1;36m Ticket Granting Ticket Is Generating ....\033[0m \n")
        print(f"\033[1;36m Ticket Granting Ticket: \033[0m {access_token}")
        return access_token
    else:
        print(f"Login failed. Status Code: {response.status_code}")
        print(response.json())
        return None

def is_admin_user(token):
    base_url = "http://127.0.0.1:8000"
    user_url = f"{base_url}/users"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(user_url, headers=headers)

    if response.status_code == 200:
        user_data = response.json()
        is_admin = user_data.get("is_admin", False)
        return is_admin
    else:
        print(f"Failed to get user data. Status Code: {response.status_code}")
        print(response.json())
        return False

def update_server_key(token):
    base_url = "http://127.0.0.1:8000"
    update_server_key_url = f"{base_url}/update-server-key"

    headers = {"Authorization": f"Bearer {token}"}

    # Provide an empty string for new_server_key
    data = {"new_server_key": ""}

    response = requests.post(update_server_key_url, headers=headers, json=data)

    if response.status_code == 200:
        print("\n\033[1;36m Ticket Granting Ticket Is Validated\033[0m \n\n")
        result = response.json()
        print(result)
        return result
    else:
        print(f"Failed to update server key. Status Code: {response.status_code}")
        print(response.json())
        return None

def get_current_user(token):
    base_url = "http://127.0.0.1:8000"
    user_url = f"{base_url}/users/me"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(user_url, headers=headers)

    if response.status_code == 200:
        print("\n\033[1;36m Ticket Granting Ticket Is Validated\033[0m \n\n")
        current_user = response.json()
        print("\nCurrent User Information:")
        print(f"Username: {current_user.get('username')}")
        print(f"Full Name: {current_user.get('full_name')}")
        print(f"Email: {current_user.get('email')}\n")
    else:
        print(f"Failed to get current user. Status Code: {response.status_code}")
        print(response.json())
        return None


def encrypt_and_send_client_key(client_key, public_key):
    encrypted_client_key = base64.b64encode(rsa.encrypt(client_key.encode(), public_key)).decode()
    return encrypted_client_key


def update_client_key(token, new_client_key):
    base_url = "http://127.0.0.1:8000"
    update_client_key_url = f"{base_url}/update-client-key"

    headers = {"Authorization": f"Bearer {token}"}
    form_data=encrypt_and_send_client_key(new_client_key, PUBLIC_KEY)
    data = {"new_client_key": form_data}
    response = requests.post(update_client_key_url, headers=headers, json=data)

    if response.status_code == 200:
        print("\n\033[1;36m Ticket Granting Ticket Is Validated\033[0m \n\n")
        print("\033[1;36m User Client Key Is Updated\033[0m \n")
        result = response.json()
        return result
    else:
        print(f"Failed to update client key. Status Code: {response.status_code}")
        print(response.json())
        return None

def get_current_time(token):
    base_url = "http://127.0.0.1:8000"
    current_time_url = f"{base_url}/current-time"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(current_time_url, headers=headers)

    if response.status_code == 200:
        print("\n\033[1;36m Ticket Granting Ticket Is Validated\033[0m \n\n")
        current_time_utc_plus_3 = response.json()["current_time_utc_plus_3"]
        print(f"Current Time (UTC+3): {current_time_utc_plus_3}")
        return current_time_utc_plus_3
    else:
        print(f"Failed to get current time. Status Code: {response.status_code}")
        print(response.json())
        return None




    
def validate_tgt(tgt):
    base_url = "http://127.0.0.1:8000"
    validate_tgt_adn_tgs_url = f"{base_url}/tgt-validation-and-tgs"
    
    headers = {"Authorization": f"Bearer {tgt}"}
    data = {"tgt": tgt}
    response = requests.post(validate_tgt_adn_tgs_url, headers=headers, json=data)

    if response.status_code == 200:
        access_token = response.json()["access_token"]
        print("\n\033[1;36m Ticket Granting Ticket Is Validated\033[0m \n")
        print("\033[1;36m Ticket Granting Service Is Generating ....\033[0m \n")
        print("\033[1;36m Ticket Granting Service Is Generated \033[0m \n")
        return access_token
    else:
        print(f"Login failed. Status Code: {response.status_code}")
        print(response.json())
        return None

def log_out(token):
    base_url = "http://127.0.0.1:8000"
    user_url = f"{base_url}/logout"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(user_url, headers=headers)

    if response.status_code == 200:
        print("\n\033[1;36m Logging Out ... \033[0m \n\n")
    else:
        print(f"Failed will logging out ... {response.status_code}")
        print(response.json())
        return None


class AuthenticationService:
    def __init__(self):
        self.username = None
        self.tgt = None
        self.tgs_token = None

    def login(self):
        self.username = input("Enter username: ")
        password = input("Enter password: ")
        self.tgt = login(self.username, password)
        return self.tgt is not None

    def choose_service(self):
        print("\n\033[1;36m1. Enter TGT for getting a TGS to access services\033[0m")
        print("\033[1;36m2. Exit\033[0m")
        return input("\nChoose an option: ")

    def execute_service(self, choice):
        if choice == "1":
            self.handle_tgt_service()
        elif choice == "2":
            print("Logging out.")
            exit()
        else:
            print("Invalid service number. Please try again.")

    def handle_tgt_service(self):
        scanf_tgt = input("Enter TGT: ")
        self.tgs_token = validate_tgt(scanf_tgt)
        if self.tgs_token:
            while True:
                self.display_menu()
                choice = input("\nChoose a service: ")
                self.execute_menu_choice(choice)

    def display_menu(self):
        print("\n\033[1;36m1. Get Current User Information\033[0m")
        print("\033[1;36m2. Update Current User Client Key\033[0m")
        print("\033[1;36m3. Get Current Time\033[0m")
        if is_admin_user(self.tgs_token):
            print("\033[1;36m4. Generate and Update Server Key (Admin Only)\033[0m")
        print("\033[1;36m5. Exit\033[0m")

    def execute_menu_choice(self, choice):
        if choice == "1":
            get_current_user(self.tgs_token)
        elif choice == "2":
            new_client_key = input("Enter new client key: ")
            update_client_key(self.tgs_token, new_client_key)
        elif choice == "3":
            get_current_time(self.tgs_token)
        elif choice == "4" and is_admin_user(self.tgs_token):
            update_server_key(self.tgs_token)
        elif choice == "5":
            log_out(self.tgt)
            #print("Logging out.")
            exit()
        else:
            print("Invalid service number. Please try again.")


def main():
    auth_service = AuthenticationService()

    while not auth_service.login():
        print("Login failed. Please try again.")

    while True:
        choice = auth_service.choose_service()
        auth_service.execute_service(choice)


if __name__ == "__main__":
    main()
