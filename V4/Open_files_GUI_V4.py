import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk, font as tkfont, PhotoImage
from tkinterdnd2 import TkinterDnD, DND_FILES, DND_TEXT
import json, subprocess, os, sys, winshell, re, time, winreg, pyautogui, base64, win32security
from cryptography.fernet import Fernet
from pynput import mouse
from pynput.mouse import Listener
import keyboard, os, ctypes, smtplib, socket, traceback, wmi, uuid, pygetwindow as gw
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from hashlib import sha256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key_from_password(password, salt):
    """Derive a key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_with_password(data, password):
    """Encrypt data with a password-derived key."""
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    return base64.b64encode(salt + encrypted_data).decode()

def decrypt_with_password(encrypted_data, password):
    """Decrypt data with a password-derived key."""
    data = base64.b64decode(encrypted_data)
    salt, encrypted_data = data[:16], data[16:]
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(encrypted_data).decode())

class AppWithInactivityTimeout:
    def __init__(self, root):
        self.root = root
        self.last_activity_time = time.time()  # Track the last activity time

        # Bind events to detect user activity
        self.root.bind("<Motion>", self.reset_timer)  # Mouse movement
        self.root.bind("<KeyPress>", self.reset_timer)  # Keypress
        self.root.bind("<FocusIn>", self.reset_timer)  # App window focus

        # Start the inactivity checker
        self.check_inactivity()

    def reset_timer(self, event=None):
        """Reset the inactivity timer."""
        self.last_activity_time = time.time()

    def check_inactivity(self):
        """Check for inactivity and exit the application if the timeout is reached."""
        current_time = time.time()
        if current_time - self.last_activity_time > INACTIVITY_TIMEOUT:
            self.exit_app()

        # Recheck after 1 second
        self.root.after(1000, self.check_inactivity)

    def exit_app(self):
        """Exit the application due to inactivity."""
        print("Application is closing due to inactivity.")
        self.root.destroy()  # Close the Tkinter window
        sys.exit()
        
def add_uuid_to_entry(entry):
    """
    Ensures that each entry has a unique identifier (UUID).
    """
    if "uuid" not in entry:
        entry["uuid"] = str(uuid.uuid4())
    return entry

def disable_features():
    """Disable all interactive features until user logs in."""
    # Disable listboxes
    app_listbox.config(state="disabled")
    url_listbox.config(state="disabled")
    # Disable buttons
    add_app_button.config(state="disabled")
    add_folder_button.config(state="disabled")
    delete_app_button.config(state="disabled")
    add_url_button.config(state="disabled")
    delete_url_button.config(state="disabled")
    run_button.config(state="disabled")
    save_button.config(state="disabled")
    clear_log_button.config(state="disabled")
    # Unregister drag-and-drop
    app_listbox.drop_target_unregister()
    url_listbox.drop_target_unregister()

def enable_features():
    """Enable all interactive features after user logs in."""
    # Enable listboxes
    app_listbox.config(state="normal")
    url_listbox.config(state="normal")
    # Enable buttons
    add_app_button.config(state="normal")
    add_folder_button.config(state="normal")
    delete_app_button.config(state="normal")
    add_url_button.config(state="normal")
    delete_url_button.config(state="normal")
    run_button.config(state="normal")
    save_button.config(state="normal")
    clear_log_button.config(state="normal")  # Add clear log button
    # Register drag-and-drop
    app_listbox.drop_target_register(DND_FILES)
    app_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, app_listbox, "application"))

    url_listbox.drop_target_register(DND_TEXT)
    url_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, url_listbox, "url"))

def authenticate_user():
    """Prompt the user to authenticate themselves."""
    current_user = os.getlogin()
    password = simpledialog.askstring("Authentication Required", f"Enter password for {current_user}:", show="*")
    if not password:
        messagebox.showerror("Authentication Failed", "No password entered!")
        return False
    
    # Validate credentials
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    handle = ctypes.c_void_p()

    success = advapi32.LogonUserW(
        ctypes.c_wchar_p(current_user),
        ctypes.c_wchar_p(None),
        ctypes.c_wchar_p(password),
        2,  # LOGON32_LOGON_INTERACTIVE
        0,  # LOGON32_PROVIDER_DEFAULT
        ctypes.byref(handle)
    )
    if not success:
        messagebox.showerror("Authentication Failed", "Invalid password!")
        return False
    else:
        messagebox.showinfo("Authentication Successful", f"Welcome, {current_user}!")
        kernel32.CloseHandle(handle)
        return True

def update_settings_menu():
    """Update the Settings menu based on the login state."""
    if is_authenticated:
        # Get current menu labels
        menu_labels = [settings_menu.entrycget(i, "label") for i in range(settings_menu.index("end") + 1)]
        
        if "Set Alert Email" not in menu_labels:
            settings_menu.add_command(label="Set Alert Email", command=set_alert_email)

        if "Export Data" not in menu_labels:
            settings_menu.add_command(label="Export Data", command=export_data)

        if "Import Data" not in menu_labels:
            settings_menu.add_command(label="Import Data", command=import_data)
    else:
        # Remove all authenticated menu items
        for i in range(settings_menu.index("end"), -1, -1):
            label = settings_menu.entrycget(i, "label")
            if label in {"Set Alert Email", "Export Data", "Import Data"}:
                settings_menu.delete(i)
            
def login():
    """Handle user login."""
    global is_authenticated
    if authenticate_user():
        is_authenticated = True
        enable_features()
        log_message("User authenticated. Access granted.")
        load_paths()
        update_settings_menu()
    else:
        log_message("User authentication failed. Access restricted.")

# Generate and save encryption key if it doesn't exist
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)

# Load the encryption key
def load_key():
    with open(KEY_FILE, 'rb') as key_file:
        return key_file.read()

def get_fernet_key():
    """Create a Fernet key from the machine-specific composite key."""
    dynamic_key = generate_dynamic_key()
    return base64.urlsafe_b64encode(dynamic_key[:32])

# Encrypt the password
def encrypt_password(password):
    fernet = Fernet(load_key())
    return fernet.encrypt(password.encode()).decode()

# Decrypt the password
def decrypt_password(encrypted_password):
    fernet = Fernet(load_key())
    return fernet.decrypt(encrypted_password.encode()).decode()

def encrypt_json(data):
    """Encrypt JSON data with a machine-specific key."""
    fernet = Fernet(get_fernet_key())
    json_data = json.dumps(data)
    return fernet.encrypt(json_data.encode()).decode()

def decrypt_json(encrypted_data):
    """Decrypt JSON data with a machine-specific key."""
    fernet = Fernet(get_fernet_key())
    decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
    return json.loads(decrypted_data)

def encrypt_alert_email(email):
    """Encrypt the alert email address."""
    fernet = Fernet(load_key())
    return fernet.encrypt(email.encode()).decode()

def decrypt_alert_email(encrypted_email):
    """Decrypt the alert email address."""
    fernet = Fernet(load_key())
    return fernet.decrypt(encrypted_email.encode()).decode()

def get_machine_sid():
    """Get the machine SID for tying JSON to a specific machine."""
    sid_obj, _, _ = win32security.LookupAccountName(None, os.getlogin())
    return win32security.ConvertSidToStringSid(sid_obj)
def get_processor_id():
    """Fetch the CPU ID for the current machine."""
    try:
        w = wmi.WMI()
        for processor in w.Win32_Processor():
            return processor.ProcessorId.strip()
    except Exception as e:
        print(f"Error fetching processor ID: {e}")
        return None

def get_disk_serial_number():
    """Retrieve the serial number of the system drive."""
    try:
        output = subprocess.check_output("wmic diskdrive get SerialNumber", shell=True)
        serial = output.decode().split("\n")[1].strip()
        return serial
    except Exception as e:
        print(f"Error fetching disk serial number: {e}")
        return None

def get_os_uuid():
    """Retrieve the OS installation UUID."""
    try:
        output = subprocess.check_output("wmic csproduct get UUID", shell=True)
        uuid = output.decode().split("\n")[1].strip()
        return uuid
    except Exception as e:
        print(f"Error fetching OS UUID: {e}")
        return None
    
def generate_dynamic_key():
    """Generate a machine-specific encryption key."""
    machine_sid = get_machine_sid()
    processor_id = get_processor_id()
    disk_serial = get_disk_serial_number()
    os_uuid = get_os_uuid()

    composite_string = f"{machine_sid}{processor_id}{disk_serial}{os_uuid}"
    return sha256(composite_string.encode()).digest()

def send_alert_email(subject, body, receiver_email):
    """Send an alert email for unauthorized JSON access using an unauthenticated SMTP server."""
    smtp_server = "Mercury.swlauriersb.qc.ca"
    smtp_port = 25
    sender_email = "Auto_Launch_Security@swlauriersb.qc.ca"

    try:
        # Create MIME message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message["Importance"] = "High"

        # Email body content
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: red; text-align: center;">Unauthorized Access Detected</h2>
            <p>
                <strong>Details of the unauthorized access attempt:</strong>
            </p>
            <pre style="
                background-color: #f9f9f9;
                padding: 10px;
                border: 1px solid #ddd;
                font-family: Courier, monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
            ">
            {body}
            </pre>
            <p>
                Please take immediate action to investigate this issue.
            </p>
        </body>
        </html>
        """
        message.attach(MIMEText(html_content, "html"))

        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.sendmail(sender_email, receiver_email, message.as_string())

        log_message(f"Alert email sent to {receiver_email}.")
    except Exception as e:
        log_message(f"Failed to send alert email: {e}")

def get_system_info():
    """Collect system information to include in the alert email."""
    username = os.getlogin()
    machine_name = socket.gethostname()
    ip_address = socket.gethostbyname(machine_name)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    return f"""
    Username: {username}
    Machine Name: {machine_name}
    IP Address: {ip_address}
    Timestamp (UTC): {timestamp}
    """

def alert_on_invalid_json(recipient_email):
    """Send an alert email for unauthorized JSON access."""
    try:
        # Prepare email subject and body
        subject = "Auto Launch Interface Alert"
        body = get_system_info()  # System information for debugging

        # Send the alert email
        send_alert_email(subject, body, recipient_email)

    except Exception as e:
        log_message(f"Failed to send alert email: {traceback.format_exc()}")
    
# File to save application & URL paths
user_appdata = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Auto Launch Interface")
SAVE_FILE = os.path.join(user_appdata, "application_configurations_test.dat")
KEY_FILE = os.path.join(user_appdata, "secret.key")

# Create the directory if it doesn't exist
os.makedirs(user_appdata, exist_ok=True)
generate_key()
changes_made = False  # Track if any changes have been made
INACTIVITY_TIMEOUT = 300
is_authenticated = False
apps = None

def find_browser_path(possible_paths):
    """Check multiple paths and return the first existing one."""
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

BROWSER_EXECUTABLES = {
    "chrome": find_browser_path([
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    ]),
    "edge": find_browser_path([
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    ]),
    "firefox": find_browser_path([
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    ]),
    "firefox_incognito": find_browser_path([
        r"C:\Program Files\Mozilla Firefox\private_browsing.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\private_browsing.exe"
    ])
}

# Regex to validate URLs
URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

def log_message(message):
    """Log messages to the error log area."""
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, message + "\n")
    log_text.config(state=tk.DISABLED)

def open_application(app_uuid, args=None, first_url=True):
    try:
        # Locate the app entry using the UUID
        app_entry = next((item for item in apps if item["uuid"] == app_uuid), None)
        if not app_entry:
            log_message(f"App with ID '{app_uuid}' not found.")
            return

        app_path = app_entry["path"]
        start_in = start_in_paths.get(app_path, os.path.dirname(app_path))
        actions = app_entry.get("actions", [])
        
        if app_entry["type"] == "url":
            # Handle URLs based on browser and mode
            browser = app_entry.get("browser", "edge")
            mode = app_entry.get("mode", "regular")
            url = app_entry["path"]

            # Use the correct path for Firefox incognito
            if browser == "firefox" and mode == "incognito":
                browser_path = BROWSER_EXECUTABLES.get("firefox_incognito")
            else:
                browser_path = BROWSER_EXECUTABLES.get(browser)

            # NEW: Check if the browser path exists
            if not browser_path:
                log_message(f"Error: {browser.capitalize()} is not installed or not found in standard locations.")
                messagebox.showerror("Browser Not Found", f"{browser.capitalize()} is not installed or cannot be found.")
                return  # Exit function safely

            # Construct command based on mode
            command = [browser_path]
            if mode == "incognito" and browser != "firefox":
                # Only add mode-specific flags for non-firefox browsers
                if browser == "chrome":
                    command.append("--incognito")
                elif browser == "edge":
                    command.append("--inprivate")
            if first_url:
                command.append("--new-window")
            command.append(url)

            # Open the URL
            subprocess.Popen(command)
            log_message(f"Opened URL: {url} in {browser.capitalize()} ({mode.capitalize()})")
            time.sleep(1.3)

        # Handle folders and applications
        elif app_entry["type"] == "folder":
            os.startfile(app_path)
            time.sleep(1.3)
        elif app_path.endswith(".exe"):
            if args:
                subprocess.Popen([app_path] + args, cwd=start_in)
            else:
                subprocess.Popen(app_path, cwd=start_in)
            time.sleep(2)
        else:
            os.startfile(app_path)
            time.sleep(1.5)
            
        # Execute actions for all types
        for action in actions:
            execute_action(action)

        log_message(f"Successfully opened {app_path}")

    except Exception as e:
        log_message(f"Failed to open {app_path}: {e}")

def is_window_maximized(window_title):
    """
    Check if the window with the given title is maximized.
    """
    try:
        window = next(win for win in gw.getWindowsWithTitle(window_title) if win.title.strip())
        return window.isMaximized
    except StopIteration:
        return False  # No matching window found
    except Exception as e:
        print(f"Error checking window state: {e}")
        return False

def execute_action(action):
    action_type = action.get("type")
    position = action.get("position", None)  # Position for mouse actions
    click_type = action.get("click_type", "left")  # Default to left click

    print(f"Executing action: {action_type} with details: {action}")

    if action_type == "Mouse Move" and position:
        pyautogui.moveTo(position[0], position[1], duration=0.2)
        print(f"Moved mouse to {position}")

    elif action_type == "Mouse Clicks" and position:
        pyautogui.moveTo(position[0], position[1], duration=0.2)
        if click_type == "left":
            pyautogui.click()
            print(f"Left click at {position}")
        elif click_type == "right":
            pyautogui.rightClick()
            print(f"Right click at {position}")

    elif action_type == "Password":
        decrypted_password = decrypt_password(action.get("value", ""))
        pyautogui.write(decrypted_password)
        print("Typed password")

    elif action_type == "Tab":
        pyautogui.press("tab")
        print("Pressed Tab")

    elif action_type == "Enter":
        pyautogui.press("enter")
        print("Pressed Enter")

    elif action_type == "Input Field":
        pyautogui.write(action.get("value", ""))
        print(f"Typed input: {action.get('value', '')}")

    elif action_type == "Sleep":
        time.sleep(int(action.get("value", 1)))
        print(f"Paused for {action.get('value', 1)} seconds")

    elif action_type == "Escape":
        pyautogui.press("esc")
        print("Pressed Escape")

    elif action_type == "Space":
        pyautogui.press("space")
        print("Pressed Space")

    elif action_type == "Left Arrow":
        pyautogui.press("left")
        print("Pressed Left Arrow")

    elif action_type == "Right Arrow":
        pyautogui.press("right")
        print("Pressed Right Arrow")

    elif action_type == "Up Arrow":
        pyautogui.press("up")
        print("Pressed Up Arrow")

    elif action_type == "Down Arrow":
        pyautogui.press("down")
        print("Pressed Down Arrow")

    elif action_type == "Full Screen":
        # Check if the window is already maximized
        current_window_title = gw.getActiveWindow().title
        if not is_window_maximized(current_window_title):
            pyautogui.hotkey("win", "up")
            print("Set window to full screen")
        else:
            print("Window is already in full screen")

    time.sleep(0.8)  # Add a delay between actions
    
def load_saved_data():
    """Load and validate saved application data."""
    if not os.path.exists(SAVE_FILE):
        return []
    try:
        with open(SAVE_FILE, 'r') as file:
            # Read the file lines: first line contains the encrypted alert email (if any)
            lines = file.readlines()
            if lines:
                encrypted_email = lines[0].strip()  # First line is the encrypted email

                # Skip decryption if the first line contains "none"
                if encrypted_email.lower() == "none" or not encrypted_email:
                    alert_email = "Araza@swlauriersb.qc.ca"  # Use fallback email if first line is "none" or empty
                    print(encrypted_email)
                else:
                    try:
                        alert_email = decrypt_alert_email(encrypted_email)
                        print(alert_email)
                    except Exception as e:
                        log_message(f"Failed to decrypt alert email: {traceback.format_exc()}")
                        alert_email = "Araza@swlauriersb.qc.ca"  # Fallback email if decryption fails
            else:
                alert_email = "Araza@swlauriersb.qc.ca"  # Default email if no lines are found

            # Second line is the encrypted JSON data
            encrypted_data = lines[1].strip() if len(lines) > 1 else None

        # Decrypt the main JSON data
        try:
            data = decrypt_json(encrypted_data)
            print(data)
        except Exception:
            # If JSON decryption fails, attempt to send an alert using the decrypted or fallback email
            alert_on_invalid_json(alert_email)
            messagebox.showerror(
                "Access Denied",
                "Failed to decrypt JSON file. This file does not belong to this machine."
            )
            raise SystemExit()
        
        # Validate metadata
        try:
            validate_metadata(data.get("_metadata", {}))
        except ValueError as validation_error:
            alert_on_invalid_json(alert_email)
            messagebox.showerror("Access Denied", str(validation_error))
            raise SystemExit()

        # Process and load items into the application
        items = data.get("items", [])
        for item in items:
            item = add_uuid_to_entry(item)  # Ensure every item has a UUID
            if "password" in item and item.get("is_encrypted", False):
                item["password"] = decrypt_password(item["password"])
                item["is_encrypted"] = False

            display_name = item.get("name", item["path"])
            if item["type"] in ["application", "folder"]:
                app_listbox.insert(tk.END, display_name)
                start_in_paths[item["path"]] = item.get("start_in", "")
            elif item["type"] == "url":
                url_listbox.insert(tk.END, display_name)

            apps.append(item)  # Add the item (with UUID and actions) to the apps list
        return items

    except Exception as e:
        log_message(f"Error loading data: {traceback.format_exc()}")
        raise

def validate_metadata(metadata):
    """Validate the JSON metadata against the current machine and user."""
    if (
        metadata.get("created_by") != os.getlogin() or
        metadata.get("machine_sid") != get_machine_sid() or
        metadata.get("cpu_id") != get_processor_id() or
        metadata.get("disk_serial") != get_disk_serial_number() or
        metadata.get("os_uuid") != get_os_uuid()
    ):
        raise ValueError("This JSON file was not created on this machine.")

def save_data(data):
    encrypted_data = []  # Temporarily hold encrypted items for saving

    for item in data:
        item_copy = item.copy()  # Create a copy of the item to encrypt and save
        
        # Encrypt the password only if it's not already encrypted
        if "password" in item and not item.get("is_encrypted", False):
            item_copy["password"] = encrypt_password(item["password"])
            item_copy["is_encrypted"] = True  # Set the encryption flag to True
        
        encrypted_data.append(item_copy)  # Append the encrypted copy

    # Save the encrypted data to the file
    with open(SAVE_FILE, 'w') as file:
        json.dump(encrypted_data, file)

    # Restore decrypted passwords in `data` after saving
    for item in data:
        if "password" in item and item.get("is_encrypted", False):
            item["password"] = decrypt_password(item["password"])  # Keep passwords decrypted in memory
            item["is_encrypted"] = False  # Reset the encryption flag

def validate_url(url):
    """Validate if the string is a proper URL."""
    return re.match(URL_REGEX, url) is not None

# Function to get both the target and "start-in" path from a shortcut
def get_shortcut_details(shortcut_path):
    if shortcut_path.endswith(".lnk"):
        shortcut = winshell.shortcut(shortcut_path)
        target = shortcut.path
        start_in = shortcut.working_directory
        return target, start_in
    return shortcut_path, os.path.dirname(shortcut_path)

# Update add_application to detect and set the "start-in" path for shortcuts
def add_application():
    global changes_made
    
    file_path = filedialog.askopenfilename()
    if file_path:
        unique_id = str(uuid.uuid4())  # Generate a unique ID for the item

        # Get the base display name
        display_name = os.path.basename(file_path)
        original_name = display_name
        counter = 1

        # Check for existing names in apps to avoid duplicates
        while any(item['name'] == display_name for item in apps):
            display_name = f"{original_name} ({counter})"
            counter += 1
            
        # Insert the display name into the listbox
        app_listbox.insert(tk.END, display_name)
        
        # Add the app with its unique ID and other details
        if file_path.endswith(".lnk"):  # If it's a shortcut
            target_path, start_in_path = get_shortcut_details(file_path)
            apps.append({"uuid": unique_id, "type": "application", "path": target_path, "start_in": start_in_path, "name": display_name})
            log_message(f"Added shortcut: {display_name} with Start-In: {start_in_path}")

        elif file_path.endswith(".exe"):  # If it's an executable
            target_path = file_path
            start_in_path = os.path.dirname(file_path)
            apps.append({"uuid": unique_id, "type": "application", "path": target_path, "start_in": start_in_path, "name": display_name})
            log_message(f"Added executable: {display_name}")

        else:  # Other file types
            target_path = file_path
            start_in_path = ""
            apps.append({"uuid": unique_id, "type": "application", "path": target_path, "start_in": start_in_path, "name": display_name})
            log_message(f"Added file: {display_name}")

        # Mark changes made
        changes_made = True

def add_folder():
    global changes_made
    
    folder_path = filedialog.askdirectory()
    if folder_path:
        display_name = os.path.basename(folder_path)
        original_name = display_name
        counter = 1

        while any(item['name'] == display_name for item in apps):
            display_name = f"{original_name} ({counter})"
            counter += 1

        app_listbox.insert(tk.END, display_name)
        apps.append(add_uuid_to_entry({"type": "folder", "path": folder_path, "start_in": "", "name": display_name}))
        log_message(f"Added folder: {display_name}")
        changes_made = True

def add_url():
    global changes_made
    
    url = url_entry.get()
    if url:
        if validate_url(url):
            display_name = url
            original_name = display_name
            counter = 1

            # Check for existing names in apps to avoid duplicates
            while any(item['name'] == display_name for item in apps):
                display_name = f"{original_name} ({counter})"
                counter += 1

            # Create the URL entry
            url_entry_data = add_uuid_to_entry({"type": "url","path": url,"name": display_name,"browser": "edge","mode": "regular"})

            # Add to the apps list
            apps.append(url_entry_data)

            # Insert display name with browser and mode into the listbox
            url_listbox.insert(
                tk.END,
                f"{display_name} [{url_entry_data['browser'].capitalize()}/{'Incognito' if url_entry_data['mode'] == 'incognito' else 'Regular'}]"
            )

            # Clear the entry field
            url_entry.delete(0, tk.END)
            log_message(f"Added URL: {display_name}")
            changes_made = True
        else:
            log_message(f"Invalid URL: {url}")
            messagebox.showerror("Invalid URL", "The URL provided is invalid.")


def save_paths():
    """Save application data with machine-specific metadata."""
    global changes_made  # Access the global changes_made flag

    try:
        # Fetch machine-specific identifiers
        machine_sid = get_machine_sid()
        processor_id = get_processor_id()
        disk_serial = get_disk_serial_number()
        os_uuid = get_os_uuid()

        # Load existing configuration if it exists to retrieve alert email
        existing_metadata = {}
        alert_email_encrypted = None  # Default value for alert email

        if os.path.exists(SAVE_FILE):
            with open(SAVE_FILE, 'r') as file:
                lines = file.readlines()
                if len(lines) > 0:
                    alert_email_encrypted = lines[0].strip()  # First line is the encrypted alert email
                if len(lines) > 1:
                    encrypted_data = lines[1].strip()  # Second line is the encrypted JSON data

        # Prepare the metadata without the alert email
        metadata = {
            "created_by": os.getlogin(),
            "machine_sid": machine_sid,
            "cpu_id": processor_id,
            "disk_serial": disk_serial,
            "os_uuid": os_uuid,
        }

        # Prepare the full data to save
        data_to_save = {
            "items": apps,  # List of applications
            "_metadata": metadata,  # Store the metadata without alert email
        }

        # Encrypt the JSON data
        encrypted_data = encrypt_json(data_to_save)

        # Write the alert email and the encrypted JSON data to the file
        with open(SAVE_FILE, 'w') as file:
            # Write the encrypted alert email as the first line, followed by the encrypted JSON data
            file.write(f"{alert_email_encrypted}\n{encrypted_data}")

        # Reset changes_made flag after successful save
        changes_made = False
        log_message("Data saved successfully!")

    except Exception as e:
        log_message(f"Failed to save data: {traceback.format_exc()}")
        messagebox.showerror("Error", f"Failed to save data: {e}")

def load_paths():
    saved_data = load_saved_data()
    
    # Clear listboxes and apps to avoid duplicates
    app_listbox.delete(0, tk.END)
    url_listbox.delete(0, tk.END)
    apps.clear()

    for item in saved_data:
        # Use name if it exists, otherwise fallback to path
        display_name = item.get("name", "").strip() or item["path"]

        if item["type"] in ["application", "folder"]:
            app_listbox.insert(tk.END, display_name)
            start_in_paths[item["path"]] = item.get("start_in", "")
        elif item["type"] == "url":
            url_listbox.insert(tk.END, display_name)
        
        # If actions exist, save them in the `apps` list
        item["actions"] = item.get("actions", [])  # Set default to empty list if no actions field
        apps.append(item)  # Add the item (with actions) to the apps list
        
        update_url_listbox()

def run_all():
    first_url = True  # To handle the first URL as a new window

    for item in apps:
        if item["type"] in ["application", "folder", "url"]:
            open_application(item["uuid"], first_url=first_url)
            if item["type"] == "url":
                first_url = False  # Switch to opening new tabs after the first URL

def run_selected(listbox):
    selected_indices = listbox.curselection()
    if not selected_indices:
        log_message("No items selected to run.")
        return

    first_url = True  # Handle the first URL as a new window

    for selected_index in selected_indices:
        display_name = listbox.get(selected_index)
        actual_name = get_actual_name(display_name)

        # Find the corresponding app entry from the `apps` list
        selected_app = next((item for item in apps if item["name"] == actual_name), None)

        if selected_app:
            open_application(selected_app["uuid"], first_url=first_url)
            if selected_app["type"] == "url":
                first_url = False  # Open subsequent URLs in new tabs
        else:
            log_message(f"Selected item '{actual_name}' not found in the app list.")

def delete_selected_application():
    global changes_made
    selected_indices = app_listbox.curselection()
    if selected_indices:
        # Reverse the indices to avoid shifting issues during deletion
        selected_indices = sorted(selected_indices, reverse=True)

        # Remove from `apps` by matching UUIDs
        for index in selected_indices:
            selected_item = app_listbox.get(index)
            app_entry = next((app for app in apps if app["name"] == selected_item), None)
            if app_entry:
                apps.remove(app_entry)  # Remove the matching app
                app_listbox.delete(index)  # Also remove from the listbox

        changes_made = True
        log_message("Selected application(s) deleted.")
        
def delete_selected_url():
    global changes_made
    selected_indices = url_listbox.curselection()
    if selected_indices:
        # Reverse the indices to avoid shifting issues during deletion
        selected_indices = sorted(selected_indices, reverse=True)

        # Remove from `apps` by matching UUIDs
        for index in selected_indices:
            selected_item = url_listbox.get(index)
            name = get_actual_name(selected_item)
            url_entry = next((app for app in apps if app["name"] == name), None)
            if url_entry:
                apps.remove(url_entry)  # Remove the matching URL
                url_listbox.delete(index)  # Also remove from the listbox

        changes_made = True
        log_message("Selected URL(s) deleted.")

def on_drop_file(event, listbox, item_type):
    global changes_made
    file_paths = listbox.tk.splitlist(event.data)  # Split if multiple items are dropped
    for path in file_paths:
        if item_type == "url":
            url = event.data.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            if validate_url(url):  # Ensure it's a valid URL
                # Add counter logic for duplicates
                original_name = url
                counter = 1
                display_name = original_name

                while any(item['name'] == display_name for item in apps):
                    display_name = f"{original_name} ({counter})"
                    counter += 1

                entry = add_uuid_to_entry({"type": "url", "path": url, "name": display_name, "browser": "edge", "mode": "regular"})
                apps.append(entry)
                formatted_display_name = f"{display_name} [{entry['browser'].capitalize()}/{'Incognito' if entry['mode'] == 'incognito' else 'Regular'}]"
                listbox.insert(tk.END, formatted_display_name)
                log_message(f"Added URL: {formatted_display_name}")
            else:
                log_message(f"Invalid URL: {url}")
            return
        
        # Handle application and shortcut logic
        if item_type == "application":
            if path.endswith(".lnk"):  # If it's a shortcut
                target_path, start_in_path = get_shortcut_details(path)
                # Add counter logic for duplicates
                original_name = os.path.basename(target_path)
                counter = 1
                display_name = original_name

                while any(item['name'] == display_name for item in apps):
                    display_name = f"{original_name} ({counter})"
                    counter += 1

                entry = add_uuid_to_entry({"type": item_type, "path": target_path, "start_in": start_in_path, "name": display_name})
                listbox.insert(tk.END, display_name)
                apps.append(entry)
                log_message(f"Added shortcut: {display_name} with Start-In: {start_in_path}")
            elif path.endswith(".exe"):  # If it's an executable
                target_path = path
                start_in_path = os.path.dirname(path)  # Set Start-In to the directory of the executable
                # Add counter logic for duplicates
                original_name = os.path.basename(target_path)
                counter = 1
                display_name = original_name

                while any(item['name'] == display_name for item in apps):
                    display_name = f"{original_name} ({counter})"
                    counter += 1

                entry = add_uuid_to_entry({"type": item_type, "path": target_path, "start_in": start_in_path, "name": display_name})
                listbox.insert(tk.END, display_name)
                apps.append(entry)
                log_message(f"Added executable: {display_name} with Start-In: {start_in_path}")
            else:  # Not a shortcut or executable, just add it without a Start-In
                target_path = path

                original_name = os.path.basename(target_path)
                counter = 1
                display_name = original_name

                while any(item['name'] == display_name for item in apps):
                    display_name = f"{original_name} ({counter})"
                    counter += 1

                entry = add_uuid_to_entry({"type": item_type, "path": target_path, "start_in": "", "name": display_name})
                listbox.insert(tk.END, display_name)
                apps.append(entry)
                log_message(f"Added file: {display_name}")

        changes_made = True

def clear_log():
    """Clear the error log area."""
    log_text.config(state=tk.NORMAL)
    log_text.delete(1.0, tk.END)  # Clear all text
    log_text.config(state=tk.DISABLED)
    log_message("Messages log cleared.")

def set_start_in_path(listbox):
    selected = listbox.curselection()
    if selected:
        # Get the currently selected item’s display name
        display_name = listbox.get(selected)

        current_start_in = ""
        app_to_update = None

        for app in apps:
            if app.get("name", app["path"]) == display_name:
                current_start_in = app.get("start_in", "")
                app_to_update = app  # Keep reference to the app being updated
                break

        # If the app was found, proceed to ask for the new Start In path
        if app_to_update:
            start_in = simpledialog.askstring("Start In Path", f"Enter the 'Start In' directory for {display_name}:", initialvalue=current_start_in)

            if start_in is not None:  # Check if the dialog was canceled
                # Update the Start In path
                app_to_update["start_in"] = start_in  # Update the Start In path
                start_in_paths[app_to_update["path"]] = start_in  # Update the start_in_paths dictionary

                # Log the changes
                log_message(f"Set 'Start In' path for {display_name}: {start_in}")
                global changes_made
                changes_made = True
                # Refresh the listbox to reflect changes
                listbox.delete(selected)  # Remove the old entry
                listbox.insert(selected, display_name)  # Insert updated name

# exit application confirmation
def on_closing():
    if changes_made:
        answer = messagebox.askyesnocancel("Unsaved Changes", "You have unsaved changes. Do you want to save before exiting?")
        if answer:
            save_paths()
            root.destroy()
        elif answer is False:
            root.destroy()
    else:
        root.destroy()

# Function to handle renaming an item
def rename_item(event, listbox, item_type):
    selected_index = listbox.curselection()
    if not selected_index:
        return
    selected_index = selected_index[0]
    selected_item = listbox.get(selected_index)

    name = get_actual_name(selected_item)
    # Find the item in the apps list to fetch details
    item = next((i for i in apps if i.get("name", i["path"]) == name), None)
    if item:
        original_name = item.get("name", os.path.basename(item["path"]))
        original_path = item["path"]
    else:
        original_name = os.path.basename(selected_item)
        original_path = selected_item

    # Rename dialog
    rename_dialog = tk.Toplevel(root)
    rename_dialog.title("Rename Item")
    rename_dialog.update_idletasks()
    rename_dialog.minsize(450, 180)

    # Label and Entry for custom name
    tk.Label(rename_dialog, text="Custom Name:").pack(pady=5)
    name_entry = ttk.Entry(rename_dialog)
    name_entry.insert(0, original_name)
    name_entry.pack(pady=5, fill=tk.X)

    # Label and non-editable Entry for original path
    tk.Label(rename_dialog, text="Original Path:").pack(pady=5)
    path_display = ttk.Entry(rename_dialog)
    path_display.insert(0, original_path)
    path_display.pack(pady=5, fill=tk.X)

    style = ttk.Style()
    style.configure('ReadOnly.TEntry', fieldbackground='#D3D3D3', foreground='black')
    # Apply the style to the path_display entry
    path_display.configure(style='ReadOnly.TEntry')
    path_display.bind("<Button-1>", lambda e: "break")  # Disable click selection
    
    # Define save_name function to save the custom name
    def save_name():
        custom_name = name_entry.get().strip()
        # Check if the new name already exists in the list
        if any(item['name'] == custom_name for item in apps):
            messagebox.showerror("Duplicate Name", f"The name '{custom_name}' already exists. Please choose a different name.")
            rename_dialog.lift()
            return  # Prevent saving if the name is a duplicate

        if custom_name:
            item["name"] = custom_name
            listbox.delete(selected_index)
            listbox.insert(selected_index, custom_name)
            global changes_made
            changes_made = True

        rename_dialog.destroy()
        
    # Save button to trigger save_name function
    save_button = ttk.Button(rename_dialog, text="Save", command=save_name)
    save_button.pack(pady=10)

# Load and decrypt passwords in the actions, only if necessary
def load_decrypted_actions(actions):
    """Decrypt passwords in actions if necessary."""
    for action in actions:
        if action.get("type") == "Password" and action.get("value"):
            # Decrypt only if not already decrypted
            if not action.get("decrypted_in_session", False):
                try:
                    action["value"] = decrypt_password(action["value"])
                    action["decrypted_in_session"] = True
                except Exception as e:
                    print(f"Error decrypting password: {e}")
                    action["value"] = ""  # Reset to empty if decryption fails
    return actions

# Display password as masked text in the listbox, only in session
def display_action_text(action):
    action_type = action.get("type")
    action_value = action.get("value", "")
    position = action.get("position", (None, None))
    click_type = action.get("click_type", "")

    if action_type == "Password":
        masked_password = "*" * len(action_value) if isinstance(action_value, str) else action_value
        return f"Password: {masked_password}"
    elif action_type == "Sleep":
        return f"Sleep: {action_value} sec"
    elif action_type == "Mouse Clicks":
        return f"{click_type.capitalize()} Click at {position}"
    elif action_type == "Mouse Move":
        return f"Move to {position}"
    else:
        return f"{action_type} {action_value}"

def open_action_sequence_dialog(listbox):
    sequence_dialog = tk.Toplevel(root)
    sequence_dialog.title("Edit Action Sequence")
    sequence_dialog.geometry("400x500")
    sequence_dialog.minsize(400, 500)

    temp_actions = []
    decrypted_in_session = False

    selected_index = listbox.curselection()
    if not selected_index:
        return

    selected_index = selected_index[0]
    selected_item = listbox.get(selected_index)

    # Remove display extras (e.g., [Browser/Mode]) to find the actual name
    name = get_actual_name(selected_item)

    # Match the entry in apps using the actual name
    app = next((item for item in apps if item.get("name") == name), None)

    if app:
        temp_actions.extend(load_decrypted_actions(app.get("actions", [])))
        decrypted_in_session = True

    action_list_label = tk.Label(sequence_dialog, text="Action Sequence:")
    action_list_label.pack(pady=10)

    actions_listbox = tk.Listbox(sequence_dialog, height=10, width=50)
    actions_listbox.pack(pady=5)

    for action in temp_actions:
        actions_listbox.insert(tk.END, display_action_text(action))

    selected_action = tk.StringVar()
    action_options = ["Tab", "Enter", "Input Field", "Password", "Sleep", "Escape", "Space",
                    "Left Arrow", "Right Arrow", "Up Arrow", "Down Arrow", "Mouse Clicks", "Full Screen"]

    action_dropdown = tk.OptionMenu(sequence_dialog, selected_action, *action_options)
    action_dropdown.pack(pady=10)

    add_action_button = tk.Button(sequence_dialog, text="Add Action",
                               command=lambda: add_selected_action(actions_listbox, temp_actions, selected_action, sequence_dialog))
    add_action_button.pack(pady=10)

    delete_action_button = tk.Button(sequence_dialog, text="Delete Action",
                                     command=lambda: delete_selected_action(actions_listbox, temp_actions))
    delete_action_button.pack(pady=5)

    move_up_button = tk.Button(sequence_dialog, text="Move Up",
                               command=lambda: move_action(actions_listbox, temp_actions, -1))
    move_up_button.pack(pady=5)

    move_down_button = tk.Button(sequence_dialog, text="Move Down",
                                 command=lambda: move_action(actions_listbox, temp_actions, 1))
    move_down_button.pack(pady=5)

    save_sequence_button = tk.Button(sequence_dialog, text="Save Sequence",
                                     command=lambda: save_action_sequence(temp_actions, listbox, selected_item, sequence_dialog, selected_index))
    save_sequence_button.pack(pady=10)

    sequence_dialog.protocol("WM_DELETE_WINDOW", lambda: on_close(sequence_dialog, temp_actions, app, decrypted_in_session))

def record_mouse_actions(actions_listbox, temp_actions):
    """
    Record mouse movements and clicks in a single session.
    """
    last_position = None  # Track the last significant position
    
    def on_move(x, y):
        """
        Record movement only when the position significantly changes.
        """
        nonlocal last_position
        if last_position is None or (abs(x - last_position[0]) > 50 or abs(y - last_position[1]) > 50):
            last_position = (x, y)
            print(f"Mouse moved to [{x}, {y}]")  # Log movement for debugging

    def on_click(x, y, button, pressed):
        """
        Record a click action at the current position.
        """
        if pressed:
            click_type = "left" if button == mouse.Button.left else "right"
            
            # Add a move action only if the position changed significantly
            nonlocal last_position
            if last_position and last_position != (x, y):
                action_move = {"type": "Mouse Move", "position": last_position}
                temp_actions.append(action_move)
                actions_listbox.insert(tk.END, f"Move to [{last_position[0]}, {last_position[1]}]")
                print(f"Recorded move to [{last_position[0]}, {last_position[1]}]")
            
            # Record the click action
            action_click = {
                "type": "Mouse Clicks",
                "position": (x, y),
                "click_type": click_type
            }
            temp_actions.append(action_click)
            actions_listbox.insert(tk.END, f"{click_type.capitalize()} Click at [{x}, {y}]")
            print(f"Recorded {click_type.capitalize()} Click at [{x}, {y}]")
            
            # Update last position
            last_position = (x, y)

    def stop_recording():
        """
        Stop the listener and unbind hotkeys.
        """
        listener.stop()
        keyboard.unhook_all_hotkeys()
        print("Stopped mouse recording mode.")

    # Start the listener for both movements and clicks
    listener = Listener(on_move=on_move, on_click=on_click)
    listener.start()

    # Hotkey to stop the recording
    keyboard.add_hotkey("ctrl+q", stop_recording)
    print("Mouse recording started. Press Ctrl+Q to stop.")

def add_selected_action(actions_listbox, temp_actions, selected_action, sequence_dialog=None):
    action_type = selected_action.get()
    if action_type in ["Input Field", "Password", "Sleep"]:
        open_input_dialog(action_type, actions_listbox, temp_actions)
    elif action_type == "Mouse Clicks":
        # Start recording mouse movements and clicks
        record_mouse_actions(actions_listbox, temp_actions)
    else:
        action = {"type": action_type, "decrypted_in_session": False}
        temp_actions.append(action)
        actions_listbox.insert(tk.END, display_action_text(action))
            
def open_input_dialog(action_type, actions_listbox, temp_actions):
    input_dialog = tk.Toplevel(root)
    input_dialog.title(f"Enter {action_type} Value")

    tk.Label(input_dialog, text=f"Enter value for {action_type}:").pack(pady=5)
    input_field = tk.Entry(input_dialog)
    input_field.pack(pady=5)

    if action_type == "Password":
        input_field.config(show="*")

    def submit_action():
        value = input_field.get().strip()
        if value:
            action = {"type": action_type, "value": value, "decrypted_in_session": action_type == "Password"}
            temp_actions.append(action)
            actions_listbox.insert(tk.END, display_action_text(action))
            input_dialog.destroy()

    tk.Button(input_dialog, text="Submit", command=submit_action).pack(pady=10)

def delete_selected_action(actions_listbox, temp_actions):
    selected_index = actions_listbox.curselection()
    if selected_index:
        index = selected_index[0]
        del temp_actions[index]
        actions_listbox.delete(index)

def move_action(actions_listbox, temp_actions, direction):
    selected_index = actions_listbox.curselection()
    if selected_index:
        index = selected_index[0]
        new_index = index + direction
        if 0 <= new_index < len(temp_actions):
            temp_actions[index], temp_actions[new_index] = temp_actions[new_index], temp_actions[index]
            actions_listbox.delete(index)
            actions_listbox.insert(new_index, display_action_text(temp_actions[new_index]))
            actions_listbox.select_set(new_index)

def save_action_sequence(temp_actions, listbox, selected_item, sequence_dialog, selected_index):
    # Remove display extras to find the actual name
    name = get_actual_name(selected_item)
    app = next((item for item in apps if item.get("name") == name), None)
    
    if app:
        for action in temp_actions:
            # Encrypt passwords only if necessary
            if action["type"] == "Password" and action.get("decrypted_in_session"):
                action["value"] = encrypt_password(action["value"])
                action["decrypted_in_session"] = False  # Reset after encrypting

        app["actions"] = temp_actions[:]  # Save the actions
        log_message(f"Action sequence saved for {selected_item}")

        global changes_made
        changes_made = True

    sequence_dialog.destroy()

def on_close(sequence_dialog, temp_actions, app, decrypted_in_session):
    if decrypted_in_session and app:
        # Re-encrypt only those marked as decrypted in-session
        for action in temp_actions:
            if action.get("type") == "Password" and action.get("decrypted_in_session", False):
                action["value"] = encrypt_password(action["value"])
                action["decrypted_in_session"] = False  # Reset the flag after re-encryption

    sequence_dialog.destroy()

# Example of adding the save_password function to the context menu
def show_context_menu(event, listbox):
    if not is_authenticated:
        return
    
    context_menu = tk.Menu(root, tearoff=0)
    if listbox == app_listbox:
        context_menu.add_command(label="Change Name", command=lambda: rename_item(event, listbox, "application"))
        context_menu.add_command(label="Set Start In Path", command=lambda: set_start_in_path(listbox))
        context_menu.add_command(label="Run Selected", command=lambda: run_selected(listbox))
        context_menu.add_command(label="Edit Action Sequence", command=lambda: open_action_sequence_dialog(listbox))
    elif listbox == url_listbox:
        context_menu.add_command(label="Change Name", command=lambda: rename_item(event, listbox, "application"))
        context_menu.add_command(label="Edit URL Settings", command=lambda: edit_url_settings(listbox))
        context_menu.add_command(label="Run Selected", command=lambda: run_selected(listbox))
        context_menu.add_command(label="Edit Action Sequence", command=lambda: open_action_sequence_dialog(listbox))

    context_menu.post(event.x_root, event.y_root)

def get_actual_name(display_name):
    """ Extract the actual URL or app name by removing display extras. Assumes display extras are added as '[Browser/Mode]' at the end."""
    return display_name.split(" [")[0].strip()

def edit_url_settings(listbox):
    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showerror("Error", "No URL selected!")
        return

    selected_index = selected_indices[0]
    display_name = listbox.get(selected_index)
    actual_name = get_actual_name(display_name)

    # Find the corresponding URL entry in `apps`
    url_entry = next((item for item in apps if item["name"] == actual_name), None)
    if not url_entry:
        messagebox.showerror("Error", "URL not found!")
        return

    # Create the dialog
    dialog = tk.Toplevel(root)
    dialog.title("Edit URL Settings")

    tk.Label(dialog, text="Select Browser:").pack(pady=5)
    browser_var = tk.StringVar(value=url_entry.get("browser", "edge"))
    browser_dropdown = ttk.Combobox(dialog, textvariable=browser_var, values=["edge", "chrome", "firefox"])
    browser_dropdown.pack(pady=5)

    tk.Label(dialog, text="Mode:").pack(pady=5)
    mode_var = tk.StringVar(value=url_entry.get("mode", "regular"))
    regular_radio = ttk.Radiobutton(dialog, text="Regular", variable=mode_var, value="regular")
    incognito_radio = ttk.Radiobutton(dialog, text="Incognito", variable=mode_var, value="incognito")
    regular_radio.pack()
    incognito_radio.pack()

    def save_changes():
    # Preserve existing fields, including actions
        url_entry["browser"] = browser_var.get()
        url_entry["mode"] = mode_var.get()
        # Do not reinitialize actions; just preserve them
        url_entry.setdefault("actions", [])
        update_url_listbox()
        dialog.destroy()

    tk.Button(dialog, text="Save", command=save_changes).pack(pady=10)

def update_url_listbox():
    url_listbox.delete(0, tk.END)

    for item in apps:
        if item["type"] == "url":
            browser = item["browser"].capitalize()
            mode = "Incognito" if item["mode"] == "incognito" else "Regular"
            display_name = f"{item['name']} [{browser}/{mode}]"
            url_listbox.insert(tk.END, display_name)

def set_alert_email():
    """Prompt the user to enter their email address for alerts and save it encrypted."""
    
    # Check if an email is already saved and decrypt it
    current_email = None
    global user_email
    
    if os.path.exists(SAVE_FILE):
        try:
            with open(SAVE_FILE, 'r') as file:
                lines = file.readlines()
                if lines:
                    encrypted_email = lines[0].strip()
                    if encrypted_email.lower() != "none" and encrypted_email:
                        current_email = decrypt_alert_email(encrypted_email)
        except Exception as e:
            log_message(f"Failed to load existing alert email: {traceback.format_exc()}")
   
    user_email = simpledialog.askstring(
        "Set Alert Email",
        "Enter your email address for alerts:",
        initialvalue=current_email) # Pre-fill with current email if it exists
    
    # Save the new email if provided
    if user_email is not None:
        user_email = user_email.strip()
        try:
            # Encrypt the alert email
            encrypted_email = encrypt_alert_email(user_email)
            # Read the existing file (if any) to preserve encrypted JSON data
            encrypted_data = ""
            if os.path.exists(SAVE_FILE):
                with open(SAVE_FILE, 'r') as file:
                    lines = file.readlines()
                    encrypted_data = lines[1].strip() if len(lines) > 1 else ""  # Second line is the encrypted JSON data

            with open(SAVE_FILE, 'w') as file:
                file.write(f"{encrypted_email}\n{encrypted_data}")

            log_message(f"Alert email set and encrypted: {user_email}")

        except Exception as e:
            log_message(f"Failed to save alert email: {traceback.format_exc()}")

def export_data():
    """
    Export application data with password-based encryption.
    """
    global apps

    if not authenticate_user():
        log_message("User authentication failed. Export canceled.")
        return

    try:
        # Step 1: Prepare export structure
        current_user = os.getlogin()
        export_data = {
            "created_by": current_user,
            "items": []
        }

        for item in apps:
            item_copy = item.copy()
            if "actions" in item_copy:
                for action in item_copy["actions"]:
                    if action.get("type") == "Password" and "value" in action:
                        action["value"] = decrypt_password(action["value"])  # Decrypt password
            export_data["items"].append(item_copy)

        # Step 2: Prompt for a password
        password = simpledialog.askstring("Export Password", "Enter a password for the exported file:", show='*')
        if not password:
            log_message("Export canceled. No password provided.")
            return

        # Step 3: Encrypt the JSON data with the password
        encrypted_json_data = encrypt_with_password(export_data, password)

        # Step 4: Save to file
        file_path = filedialog.asksaveasfilename(defaultextension=".dat", filetypes=[("DAT files", "*.dat")])
        if not file_path:
            log_message("Export canceled by the user.")
            return

        with open(file_path, "w") as file:
            file.write(encrypted_json_data)  # Write only the encrypted JSON data

        log_message(f"Data exported successfully to {file_path}")
        messagebox.showinfo("Export Successful", f"Data exported successfully to {file_path}")

    except Exception as e:
        log_message(f"Failed to export data: {e}")
        messagebox.showerror("Export Error", f"Failed to export data: {e}")

def import_data():
    """
    Import application data with password-based decryption.
    """
    global apps

    # fallback alert email (backend-only)
    static_alert_email = "araza@swlauriersb.qc.ca"

    if not authenticate_user():
        log_message("User authentication failed. Import canceled.")
        return

    try:
        # Step 1: Select file to import
        file_path = filedialog.askopenfilename(filetypes=[("DAT files", "*.dat")])
        if not file_path:
            log_message("Import canceled by the user.")
            return

        # Step 2: Read the file
        with open(file_path, "r") as file:
            encrypted_json_data = file.read()

        # Step 3: Prompt for the password
        password = simpledialog.askstring("Import Password", "Enter the password for the file:", show='*')
        if not password:
            log_message("Import canceled. No password provided.")
            return

        try:
            decrypted_data = decrypt_with_password(encrypted_json_data, password)
        except Exception as e:
            log_message(f"Failed to decrypt JSON data: {e}")
            messagebox.showerror("Import Error", "Failed to decrypt the JSON data. Please check the password.")
            return

        # Step 4: Validate the creator
        current_user = os.getlogin()
        created_by = decrypted_data.get("created_by")
        if created_by != current_user:
            log_message(f"Import canceled. User mismatch. Attempted by: {current_user}, Created by: {created_by}")
            messagebox.showerror("Import Error", "You are not authorized to import this file.")
            alert_on_invalid_json(static_alert_email)
            return

        # Step 5: Load data into the app
        apps.clear()
        app_listbox.delete(0, tk.END)
        url_listbox.delete(0, tk.END)

        for item in decrypted_data["items"]:
            if "actions" in item:
                for action in item["actions"]:
                    if action.get("type") == "Password" and "value" in action:
                        action["value"] = encrypt_password(action["value"])
                        action["decrypted_in_session"] = False

            if item["type"] in ["application", "folder"]:
                app_listbox.insert(tk.END, item["name"])
            elif item["type"] == "url":
                url_listbox.insert(tk.END, item["name"])

            apps.append(item)

        log_message(f"Data imported successfully from {file_path}")
        messagebox.showinfo("Import Successful", f"Data imported successfully from {file_path}")

    except Exception as e:
        log_message(f"Failed to import data: {e}")
        messagebox.showerror("Import Error", f"Failed to import data: {e}")

apps = []
start_in_paths = {}

# Create main application window
root = TkinterDnD.Tk()
root.title("Auto Launch Interface")
base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
img = PhotoImage(file=os.path.join(base_path, 'logo.png'))
root.iconbitmap(os.path.join(base_path, 'logo.ico'))
root.iconphoto(False, img)
root.update_idletasks()
root.minsize(1000, 800)
root.protocol("WM_DELETE_WINDOW", on_closing)

AppWithInactivityTimeout(root)

menu_bar = tk.Menu(root)
settings_menu = tk.Menu(menu_bar, tearoff=0)
settings_menu.add_command(label="Login", command=login)
menu_bar.add_cascade(label="Settings", menu=settings_menu)
root.config(menu=menu_bar)

frame_label_font = tkfont.Font(family="Helvetica", size=14, weight="bold", slant="italic")
button_label_font = tkfont.Font(family="Helvetica", size=10, weight="bold")
listbox_font = tkfont.Font(family="sans-serif", size=15)  # Font for listbox items

style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background="#2E2E2E")
style.configure("TLabel", background="#2E2E2E", foreground="white", font=frame_label_font)
style.configure("TButton", background="#4C4C4C", foreground="white", padding=5, font=button_label_font)
style.configure("TListbox", background="#D7C9AA", foreground="#7B2D26", font=listbox_font)  # Updated colors and font
style.configure("TEntry", fieldbackground="#F3DFC1", foreground="#000000")

# Create frames for applications, URLs, and logs
frame_apps = ttk.Frame(root)
frame_apps.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

frame_urls = ttk.Frame(root)
frame_urls.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

frame_log = ttk.Frame(root)
frame_log.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)

# Configure grid weight for responsiveness
root.configure(background="#2E2E2E")
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(1, weight=1)

# Applications frame
app_label = ttk.Label(frame_apps, text="Applications & Folders")
app_label.pack()

app_listbox = tk.Listbox(frame_apps, selectmode=tk.MULTIPLE, bg="#AE8B70", fg="#303437", font=listbox_font)  # Set colors and font
app_listbox.pack(fill=tk.BOTH, expand=True)

add_app_button = ttk.Button(frame_apps, text="Add Application", command=add_application)
add_app_button.pack(fill=tk.X)

add_folder_button = ttk.Button(frame_apps, text="Add Folder", command=add_folder)
add_folder_button.pack(fill=tk.X)

delete_app_button = ttk.Button(frame_apps, text="Delete Selected", command=delete_selected_application)
delete_app_button.pack(fill=tk.X)

# URLs frame
url_label = ttk.Label(frame_urls, text="URLs")
url_label.pack()

url_listbox = tk.Listbox(frame_urls, selectmode=tk.MULTIPLE, bg="#AE8B70", fg="#303437", font=listbox_font)  # Set colors and font
url_listbox.pack(fill=tk.BOTH, expand=True)

url_entry = ttk.Entry(frame_urls)
url_entry.pack(fill=tk.X)

add_url_button = ttk.Button(frame_urls, text="Add URL", command=add_url)
add_url_button.pack(fill=tk.X)

delete_url_button = ttk.Button(frame_urls, text="Delete Selected", command=delete_selected_url)
delete_url_button.pack(fill=tk.X)

# Log frame
log_label = ttk.Label(frame_log, text="Messages Log")
log_label.pack()


log_text = tk.Text(frame_log, height=10, wrap=tk.WORD, state=tk.DISABLED, bg="#AE8B70", fg="#303437", font=listbox_font)  # Set colors and font
log_text.pack(fill=tk.BOTH, expand=True)

log_message("Log into the application by clicking on settings")

button_frame = ttk.Frame(frame_log)
button_frame.pack(pady=5, fill=tk.X)

clear_log_button = ttk.Button(button_frame, text="Clear Logs", command=clear_log)
clear_log_button.pack(fill=tk.X, expand=True)

run_button = ttk.Button(button_frame, text="Run", command=run_all)
run_button.pack(fill=tk.X, expand=True)

save_button = ttk.Button(button_frame, text="Save", command=save_paths)
save_button.pack(fill=tk.X, expand=True)

# Add right-click event binding for showing context menu
app_listbox.bind("<Button-3>", lambda e: show_context_menu(e, app_listbox))
url_listbox.bind("<Button-3>", lambda e: show_context_menu(e, url_listbox))

#drag & drop functionality
app_listbox.drop_target_register(DND_FILES)
app_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, app_listbox, "application"))

url_listbox.drop_target_register(DND_TEXT)
url_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, url_listbox, "url"))

disable_features() # All app features are disabled on start

# Run the application
root.mainloop()
