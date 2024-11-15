import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk, font as tkfont, PhotoImage, Toplevel, Label
from tkinterdnd2 import TkinterDnD, DND_FILES, DND_TEXT
import json, subprocess, os, sys, winshell, re, time, winreg, pyautogui
from cryptography.fernet import Fernet
from pynput import mouse
from pynput.mouse import Listener
import threading
import keyboard

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

# Encrypt the password
def encrypt_password(password):
    fernet = Fernet(load_key())
    return fernet.encrypt(password.encode()).decode()

# Decrypt the password
def decrypt_password(encrypted_password):
    fernet = Fernet(load_key())
    return fernet.decrypt(encrypted_password.encode()).decode()

# File to save application & URL paths
user_appdata = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Auto Launch Interface V2")
SAVE_FILE = os.path.join(user_appdata, "application_configurations.json")
KEY_FILE = os.path.join(user_appdata, "secret.key")

# Create the directory if it doesn't exist
os.makedirs(user_appdata, exist_ok=True)
generate_key()
changes_made = False  # Track if any changes have been made

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

def open_application(app_path, args=None):
    try:
        # Get the start-in path from the app data
        start_in = start_in_paths.get(app_path, os.path.dirname(app_path))

        # Retrieve the app entry and associated actions
        app_entry = next((item for item in apps if item["path"] == app_path), None)
        actions = app_entry.get("actions", []) if app_entry else []

        if app_path.endswith(".lnk"):  # Resolve shortcut files
            app_path = winshell.shortcut(app_path).path

        # Launch the application
        if os.path.isdir(app_path):  # Open folder
            os.startfile(app_path)
            time.sleep(3)
            
            # Execute each action in the sequence
            for action in actions:
                execute_action(action)
                
        elif app_path.endswith(".exe"):  # Run executable
            if args:
                subprocess.Popen([app_path] + args, cwd=start_in)
            else:
                subprocess.Popen(app_path, cwd=start_in)
            time.sleep(2)  # Wait briefly for the app to load

            # Execute each action in the sequence
            for action in actions:
                execute_action(action)

        else:
            os.startfile(app_path)  # Open non-executable file or URL
            time.sleep(3)

        log_message(f"Successfully opened {app_path}")

    except Exception as e:
        log_message(f"Failed to open {app_path}: {e}")

def execute_action(action):
    action_type = action.get("type")
    position = action.get("position", (0, 0))
    click_type = action.get("click_type", "left")

    print(f"Executing action: {action_type} at {position}")

    if action_type == "Mouse Move":
        # Move the mouse to the position
        pyautogui.moveTo(position[0], position[1], duration=0.2)  # Smooth movement
        print(f"Moved mouse to {position}")
    elif action_type == "Mouse Clicks":
        # Move to position and click
        pyautogui.moveTo(position[0], position[1], duration=0.2)
        if click_type == "left":
            pyautogui.click()
        else:
            pyautogui.rightClick()
        print(f"{click_type.capitalize()} click at {position}")
    elif action_type == "Password":
        decrypted_password = decrypt_password(action.get("value", ""))
        pyautogui.write(decrypted_password)
        print("Typed password")
    elif action_type == "Tab":
        pyautogui.press("tab")
    elif action_type == "Enter":
        pyautogui.press("enter")
    elif action_type == "Input Field":
        pyautogui.write(action.get("value", ""))
    elif action_type == "Sleep":
        time.sleep(int(action.get("value", 1)))
    elif action_type == "Escape":
        pyautogui.press("esc")
    elif action_type == "Space":
        pyautogui.press("space")
    elif action_type == "Left Arrow":
        pyautogui.press("left")
    elif action_type == "Right Arrow":
        pyautogui.press("right")
    elif action_type == "Up Arrow":
        pyautogui.press("up")
    elif action_type == "Down Arrow":
        pyautogui.press("down")
    elif action_type == "Full Screen":
        pyautogui.hotkey("win", "up")

    time.sleep(0.5)  # Small delay between actions

def load_saved_data():
    if os.path.exists(SAVE_FILE):
        try:
            with open(SAVE_FILE, 'r') as file:
                data = json.load(file)
                
                for item in data:
                    # Only decrypt if the password is marked as encrypted
                    if "password" in item and item.get("is_encrypted", False):
                        item["password"] = decrypt_password(item["password"])
                        item["is_encrypted"] = False  # Set flag to indicate it's now decrypted

                    display_name = item["name"] if item.get("name") else item["path"]
                    if item["type"] in ["application", "folder"]:
                        app_listbox.insert(tk.END, display_name)
                        start_in_paths[item["path"]] = item.get("start_in", "")
                    elif item["type"] == "url":
                        url_listbox.insert(tk.END, display_name)
                
                apps.extend(data)
                return data
        except json.JSONDecodeError:
            log_message("Error loading data: Invalid JSON format.")
            return []  # Return an empty list on JSON error
        except Exception as e:
            log_message(f"Error loading saved data: {e}")
            return []  # Return an empty list if other errors occur
    else:
        return []  # Return an empty list if the file does not exist

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
        if file_path.endswith(".lnk"):  # If it's a shortcut
            target_path, start_in_path = get_shortcut_details(file_path)
            display_name = os.path.basename(target_path)  # Use the name from the file
            app_listbox.insert(tk.END, display_name)
            apps.append({"type": "application", "path": target_path, "start_in": start_in_path, "name": display_name})
            log_message(f"Added shortcut: {target_path} with Start-In: {start_in_path}")
        elif file_path.endswith(".exe"):  # If it's an executable
            target_path = file_path
            start_in_path = os.path.dirname(file_path)
            display_name = os.path.basename(target_path)  # Use the name from the file
            app_listbox.insert(tk.END, display_name)
            apps.append({"type": "application", "path": target_path, "start_in": start_in_path, "name": display_name})
            log_message(f"Added executable: {target_path} with Start-In: {start_in_path}")
        else:  # Other file types
            target_path = file_path
            start_in_path = ""
            display_name = os.path.basename(target_path)  # Use the name from the file
            app_listbox.insert(tk.END, display_name)
            apps.append({"type": "application", "path": target_path, "start_in": start_in_path, "name": display_name})
            log_message(f"Added file: {target_path}.")

        changes_made = True

def add_folder():
    global changes_made
    folder_path = filedialog.askdirectory()
    if folder_path:
        display_name = os.path.basename(folder_path)
        app_listbox.insert(tk.END, display_name)
        apps.append({"type": "folder", "path": folder_path, "start_in": "", "name": display_name})
        log_message(f"Added folder: {folder_path}")
        changes_made = True

def add_url():
    global changes_made
    url = url_entry.get()
    if url:
        if validate_url(url):
            display_name = url  # Use the URL itself as the name
            url_listbox.insert(tk.END, display_name)
            apps.append({"type": "url", "path": url, "name": display_name})  # Ensure name is set
            url_entry.delete(0, tk.END)
            log_message(f"Added URL: {url}")
            changes_made = True
        else:
            log_message(f"Invalid URL: {url}")
            messagebox.showerror("Invalid URL", "The URL provided is invalid.")

def save_paths():
    global changes_made
    save_data(apps)
    log_message("Applications, folders, and URLs saved!")
    changes_made = False

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

def get_default_browser_path():
    """Retrieve the default web browser executable path, checking both Program Files and Program Files (x86)."""
    try:
        # Open the registry key for the default browser
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                      r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice")
        default_browser = winreg.QueryValueEx(registry_key, "ProgId")[0]
        winreg.CloseKey(registry_key)

        # Possible installation paths for browsers
        program_files_paths = [
            r"C:\Program Files",
            r"C:\Program Files (x86)"
        ]
        
        # Browser executable paths within Program Files and Program Files (x86)
        browser_paths = {
            "Chrome": r"Google\Chrome\Application\chrome.exe",
            "Edge": r"Microsoft\Edge\Application\msedge.exe",
            "Firefox": r"Mozilla Firefox\firefox.exe",
            "Brave": r"BraveSoftware\Brave-Browser\Application\brave.exe",
        }
        
        # User-specific path for Opera -> Generally Opera is installed directly in the Local Appdata folder so in case it's not installed in program files, this is a safety net.
        opera_user_path = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\launcher.exe")

        # Map ProgId to check all possible installation directories
        for base_path in program_files_paths:
            if "Chrome" in default_browser:
                chrome_path = os.path.join(base_path, browser_paths["Chrome"])
                if os.path.isfile(chrome_path):
                    return chrome_path
            elif "Edge" in default_browser:
                edge_path = os.path.join(base_path, browser_paths["Edge"])
                if os.path.isfile(edge_path):
                    return edge_path
            elif "Firefox" in default_browser:
                firefox_path = os.path.join(base_path, browser_paths["Firefox"])
                if os.path.isfile(firefox_path):
                    return firefox_path
            elif "Brave" in default_browser:
                brave_path = os.path.join(base_path, browser_paths["Brave"])
                if os.path.isfile(brave_path):
                    return brave_path
            elif "Opera" in default_browser:
                # Check both user-specific and program files paths for Opera
                if os.path.isfile(opera_user_path):
                    return opera_user_path
                for base in program_files_paths:
                    opera_path = os.path.join(base, "Opera", "launcher.exe")
                    if os.path.isfile(opera_path):
                        return opera_path

        # If no browser found
        return None
    except Exception as e:
        print(f"Error retrieving default browser path: {e}")
        return None

def run_all():
    browser_path = get_default_browser_path()
    first_url = True
    for item in apps:
        if item["type"] == "application" or item["type"] == "folder":
            open_application(item["path"])
        elif item["type"] == "url":
            try:
                if first_url:
                    subprocess.Popen([browser_path, "--new-window", item["path"]])
                    first_url = False
                    time.sleep(0.1)
                else:
                    subprocess.Popen([browser_path, "--new-tab", item["path"]])
                log_message(f"Opened URL: {item['path']}")
            except Exception as e:
                log_message(f"Failed to open URL {item['path']}: {e}")

def delete_selected_application():
    global changes_made
    selected_indices = app_listbox.curselection()
    if selected_indices:
        for index in reversed(selected_indices):  # Reverse to handle index shifts
            display_name = app_listbox.get(index)
            print(f"Deleting from app_listbox: {display_name}")  # Debug: Check name in listbox
            # Remove from Listbox
            app_listbox.delete(index)
            # Remove from apps list by matching display_name
            before_delete_apps = apps[:]
            apps[:] = [app for app in apps if app.get("name", app["path"]) != display_name]
            after_delete_apps = apps[:]
            print(f"Apps before deletion: {before_delete_apps}")  # Debug: Apps list before deletion
            print(f"Apps after deletion: {after_delete_apps}")  # Debug: Apps list after deletion
        changes_made = True
        log_message("Selected application(s) deleted.")

def delete_selected_url():
    global changes_made
    selected_indices = url_listbox.curselection()
    if selected_indices:
        for index in reversed(selected_indices):  # Reverse to handle index shifts
            display_name = url_listbox.get(index)
            print(f"Deleting from url_listbox: {display_name}")  # Debug: Check name in listbox
            
            # Remove from Listbox
            url_listbox.delete(index)
            
            # Remove from apps list by matching the display_name or path
            before_delete_apps = apps[:]
            apps[:] = [app for app in apps if app.get("name", app["path"]) != display_name]
            after_delete_apps = apps[:]
            
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
                listbox.insert(tk.END, url)
                apps.append({"type": item_type, "path": url, "start_in": ""})
                log_message(f"Added URL: {url}.")
            else:
                log_message(f"Invalid URL: {url}")
            return
        
        # Handle application and shortcut logic
        if item_type == "application":
            if path.endswith(".lnk"):  # If it's a shortcut
                target_path, start_in_path = get_shortcut_details(path)
                listbox.insert(tk.END, target_path)
                apps.append({"type": item_type, "path": target_path, "start_in": start_in_path})
                log_message(f"Added shortcut: {target_path} with Start-In: {start_in_path}")
            elif path.endswith(".exe"):  # If it's an executable
                target_path = path
                start_in_path = os.path.dirname(path)  # Set Start-In to the directory of the executable
                listbox.insert(tk.END, target_path)
                apps.append({"type": item_type, "path": target_path, "start_in": start_in_path})
                log_message(f"Added executable: {target_path} with Start-In: {start_in_path}")
            else:  # Not a shortcut or executable, just add it without a Start-In
                target_path = path
                start_in_path = ""  # No Start-In required
                listbox.insert(tk.END, target_path)
                apps.append({"type": item_type, "path": target_path, "start_in": start_in_path})
                log_message(f"Added file: {target_path}.")
        
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

        # Find the corresponding app entry based on display name
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

    # Find the item in the apps list to fetch details
    item = next((i for i in apps if i.get("name", i["path"]) == selected_item), None)
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
    for action in actions:
        if action.get("type") == "Password" and action.get("value"):
            # Decrypt only if not already decrypted
            if isinstance(action["value"], str) and action.get("decrypted_in_session") is False:
                try:
                    action["value"] = decrypt_password(action["value"])
                    action["decrypted_in_session"] = True  # Mark this as decrypted for session
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
    else:
        return f"{action_type}: {action_value}"

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
    app = next((item for item in apps if item.get("name", item["path"]) == selected_item), None)

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
    last_position = None  # To track the last significant position
    
    def on_move(x, y):
        """Track significant mouse movements but do not add them until a click happens."""
        nonlocal last_position
        if last_position is None or (abs(x - last_position[0]) > 50 or abs(y - last_position[1]) > 50):
            last_position = (x, y)  # Update last significant position

    def on_click(x, y, button, pressed):
        """Record mouse clicks and optionally include movement before them."""
        nonlocal last_position
        if pressed:
            click_type = "left" if button == mouse.Button.left else "right"
            
            # Add a Mouse Move action to the last significant position if it exists
            if last_position:
                action_move = {
                    "type": "Mouse Move",
                    "position": last_position
                }
                temp_actions.append(action_move)
                actions_listbox.insert(tk.END, f"Move to ({last_position[0]}, {last_position[1]})")
                print(f"Mouse moved to ({last_position[0]}, {last_position[1]}) recorded.")
            
            # Add the actual click action
            action_click = {
                "type": "Mouse Clicks",
                "position": (x, y),
                "click_type": click_type
            }
            temp_actions.append(action_click)
            actions_listbox.insert(tk.END, f"{click_type.capitalize()} Click at ({x}, {y})")
            print(f"{click_type.capitalize()} Click at ({x}, {y}) recorded.")
            
            # Update the last position to the click position
            last_position = (x, y)

    def stop_recording():
        """Stop the listener and unbind hotkeys."""
        listener.stop()
        keyboard.unhook_all_hotkeys()
        print("Stopped mouse recording mode.")

    # Start the listener for both movement and clicks
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
    app = next((item for item in apps if item.get("name", item["path"]) == selected_item), None)
    if app:
        for action in temp_actions:
            if action["type"] == "Password" and action.get("decrypted_in_session"):
                action["value"] = encrypt_password(action["value"])
                action["decrypted_in_session"] = False  # Reset after encrypting

        app["actions"] = temp_actions[:]
        log_message(f"Action sequence saved for {selected_item}")

        listbox.delete(selected_index)
        listbox.insert(selected_index, selected_item)
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
    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="Change Name", command=lambda: rename_item(event, listbox, "application"))

    if listbox == app_listbox:
        context_menu.add_command(label="Edit Action Sequence", command=lambda: open_action_sequence_dialog(listbox))
        context_menu.add_command(label="Set Start In Path", command=lambda: set_start_in_path(listbox))

    context_menu.post(event.x_root, event.y_root)
    
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

app_listbox.drop_target_register(DND_FILES)
app_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, app_listbox, "application"))

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

url_listbox.drop_target_register(DND_TEXT)
url_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, url_listbox, "url"))

# Log frame
log_label = ttk.Label(frame_log, text="Messages Log")
log_label.pack()

log_text = tk.Text(frame_log, height=10, wrap=tk.WORD, state=tk.DISABLED, bg="#AE8B70", fg="#303437", font=listbox_font)  # Set colors and font
log_text.pack(fill=tk.BOTH, expand=True)

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

load_paths()
# Run the application
root.mainloop()
