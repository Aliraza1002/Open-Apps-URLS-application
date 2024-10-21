import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from tkinterdnd2 import TkinterDnD, DND_FILES  # Import drag-and-drop functionality
import json
import subprocess
import os
import winshell
import re

# File to save application paths and URLs
SAVE_FILE = "app_paths.json"

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
        # Get the start in path from the app data
        original_start_in = start_in_paths.get(app_path, os.path.dirname(app_path))
        start_in = original_start_in 

        if app_path.endswith(".lnk"):  # Resolve shortcut files
            app_path = winshell.shortcut(app_path).path

        if os.path.isdir(app_path):  # Open folder
            os.startfile(app_path)
        elif app_path.endswith(".exe"):  # Run executable
            if args:
                subprocess.Popen([app_path] + args, cwd=start_in)
            else:
                subprocess.Popen(app_path, cwd=start_in)
        else:
            os.startfile(app_path)  # Open file

        log_message(f"Successfully opened {app_path} with start-in {start_in}")
    except Exception as e:
        log_message(f"Failed to open {app_path}: {e}")

def load_saved_data():
    if os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, 'r') as file:
            return json.load(file)
    return []

def save_data(data):
    with open(SAVE_FILE, 'w') as file:
        json.dump(data, file)

def validate_url(url):
    """Validate if the string is a proper URL."""
    return re.match(URL_REGEX, url) is not None

def add_application():
    file_path = filedialog.askopenfilename()
    if file_path:
        app_listbox.insert(tk.END, file_path)
        apps.append({"type": "application", "path": file_path, "start_in": ""})
        log_message(f"Added application: {file_path}")

def add_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        app_listbox.insert(tk.END, folder_path)
        apps.append({"type": "folder", "path": folder_path, "start_in": ""})
        log_message(f"Added folder: {folder_path}")

def add_url():
    url = url_entry.get()
    if url:
        if validate_url(url):
            url_listbox.insert(tk.END, url)
            apps.append({"type": "url", "path": url})
            url_entry.delete(0, tk.END)
            log_message(f"Added URL: {url}")
        else:
            log_message(f"Invalid URL: {url}")
            messagebox.showerror("Invalid URL", "The URL provided is invalid.")

def save_paths():
    save_data(apps)
    log_message("Applications, folders, and URLs saved!")

def load_paths():
    saved_data = load_saved_data()
    for item in saved_data:
        if item["type"] == "application" or item["type"] == "folder":
            app_listbox.insert(tk.END, item["path"])
            start_in_paths[item["path"]] = item.get("start_in", "")
        else:
            url_listbox.insert(tk.END, item["path"])
    apps.extend(saved_data)

def run_all():
    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    first_url = True
    for item in apps:
        if item["type"] == "application" or item["type"] == "folder":
            open_application(item["path"])
        elif item["type"] == "url":
            try:
                if first_url:
                    subprocess.Popen([chrome_path, "--new-window", item["path"]])
                    first_url = False
                else:
                    subprocess.Popen([chrome_path, "--new-tab", item["path"]])
                log_message(f"Opened URL: {item['path']}")
            except Exception as e:
                log_message(f"Failed to open URL {item['path']}: {e}")

def delete_selected_application():
    selected_index = app_listbox.curselection()
    if selected_index:
        deleted_item = app_listbox.get(selected_index)
        app_listbox.delete(selected_index)
        del apps[selected_index[0]]
        del start_in_paths[deleted_item]
        log_message(f"Deleted application/folder: {deleted_item}")

def delete_selected_url():
    selected_index = url_listbox.curselection()
    if selected_index:
        deleted_item = url_listbox.get(selected_index)
        url_listbox.delete(selected_index)
        del apps[selected_index[0] + len(app_listbox.get(0, tk.END))]
        log_message(f"Deleted URL: {deleted_item}")

def on_drop_file(event, listbox, item_type):
    """Handle the drop event and add the file/folder to the listbox."""
    file_paths = listbox.tk.splitlist(event.data)  # Split if multiple items are dropped
    for path in file_paths:
        if item_type == "url" and not validate_url(path):
            log_message(f"Invalid URL: {path}")
            continue
        listbox.insert(tk.END, path)
        apps.append({"type": item_type, "path": path})
        log_message(f"Added {item_type}: {path}")

def clear_log():
    """Clear the error log area."""
    log_text.config(state=tk.NORMAL)
    log_text.delete(1.0, tk.END)  # Clear all text
    log_text.config(state=tk.DISABLED)
    log_message("Messages log cleared.")

def on_double_click(event):
    selected = app_listbox.curselection()
    if selected:
        app_path = app_listbox.get(selected)
        current_start_in = start_in_paths.get(app_path, "")
        start_in = simpledialog.askstring("Start In Path", f"Enter the 'Start In' directory for {app_path}:", initialvalue=current_start_in)
        
        if start_in is not None:  # Check if the dialog was canceled
            start_in_paths[app_path] = start_in
            # Update the start_in field in the corresponding app entry
            for app in apps:
                if app["path"] == app_path:
                    app["start_in"] = start_in
                    break
            log_message(f"Set 'Start In' path for {app_path}: {start_in}")
        else:
            log_message(f"No 'Start In' path set for {app_path}. Using default.")

root = TkinterDnD.Tk()
root.title("Application, Folder & URL Launcher")
root.geometry("1000x700")

style = ttk.Style()
style.theme_use("clam")

# Global fonts and padding
default_font = ("Segoe UI", 10)

apps = []
start_in_paths = {}

# Frame for applications and folders
app_frame = ttk.Frame(root, padding="10")
app_frame.pack(pady=10, fill=tk.BOTH, expand=True)

app_label = ttk.Label(app_frame, text="Applications & Folders", font=("Segoe UI", 12))
app_label.pack()

# Creating a frame for the Listbox and Scrollbar
app_listbox_frame = ttk.Frame(app_frame)
app_listbox_frame.pack(pady=5)

app_listbox = tk.Listbox(app_listbox_frame, height=10, width=150, font=default_font)
app_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

app_scrollbar = ttk.Scrollbar(app_listbox_frame, orient=tk.VERTICAL, command=app_listbox.yview)
app_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

app_listbox.config(yscrollcommand=app_scrollbar.set)

# Enable double-click to add "start in" path
app_listbox.bind("<Double-Button-1>", on_double_click)

# Enable drag-and-drop support for the application listbox
app_listbox.drop_target_register(DND_FILES)
app_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, app_listbox, "application"))

app_button_frame = ttk.Frame(app_frame, padding="10")
app_button_frame.pack(pady=5)

app_button = ttk.Button(app_button_frame, text="Add Application", command=add_application)
app_button.pack(side=tk.LEFT, padx=5)

folder_button = ttk.Button(app_button_frame, text="Add Folder", command=add_folder)
folder_button.pack(side=tk.LEFT, padx=5)

app_delete_button = ttk.Button(app_button_frame, text="Delete Selected", command=delete_selected_application)
app_delete_button.pack(side=tk.LEFT, padx=5)

# Frame for URLs
url_frame = ttk.Frame(root, padding="10")
url_frame.pack(pady=10, fill=tk.BOTH, expand=True)

url_label = ttk.Label(url_frame, text="URLs", font=("Segoe UI", 12))
url_label.pack()

url_entry = ttk.Entry(url_frame, width=70, font=default_font)
url_entry.pack(pady=5)

# Creating a frame for the URL Listbox and Scrollbar
url_listbox_frame = ttk.Frame(url_frame)
url_listbox_frame.pack(pady=5)

url_listbox = tk.Listbox(url_listbox_frame, height=10, width=150, font=default_font)
url_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

url_scrollbar = ttk.Scrollbar(url_listbox_frame, orient=tk.VERTICAL, command=url_listbox.yview)
url_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

url_listbox.config(yscrollcommand=url_scrollbar.set)

# Enable drag-and-drop support for the URL listbox
url_listbox.drop_target_register(DND_FILES)
url_listbox.dnd_bind('<<Drop>>', lambda event: on_drop_file(event, url_listbox, "url"))

url_button_frame = ttk.Frame(url_frame, padding="10")
url_button_frame.pack(pady=5)

url_button = ttk.Button(url_button_frame, text="Add URL", command=add_url)
url_button.pack(side=tk.LEFT, padx=5)

url_delete_button = ttk.Button(url_button_frame, text="Delete Selected", command=delete_selected_url)
url_delete_button.pack(side=tk.LEFT, padx=5)

# Frame for log messages
log_frame = ttk.Frame(root, padding="10")
log_frame.pack(pady=10, fill=tk.BOTH, expand=True)

log_label = ttk.Label(log_frame, text="Messages Log", font=("Segoe UI", 12))
log_label.pack()

# Creating a frame for the log Text widget and Scrollbar
log_text_frame = ttk.Frame(log_frame)
log_text_frame.pack(pady=5)

log_text = tk.Text(log_text_frame, height=10, width=150, font=default_font)
log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

log_scrollbar = ttk.Scrollbar(log_text_frame, orient=tk.VERTICAL, command=log_text.yview)
log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

log_text.config(yscrollcommand=log_scrollbar.set)  # Link scrollbar with Text widget
log_text.config(state=tk.DISABLED)  # Make it read-only initially

# Frame for control buttons
control_frame = ttk.Frame(root, padding="10")
control_frame.pack(pady=10)

save_button = ttk.Button(control_frame, text="Save", command=save_paths)
save_button.pack(side=tk.LEFT, padx=5)

run_button = ttk.Button(control_frame, text="Run", command=run_all)
run_button.pack(side=tk.LEFT, padx=5)

clear_button = ttk.Button(control_frame, text="Clear Log", command=clear_log)
clear_button.pack(side=tk.LEFT, padx=5)

# Load saved paths on startup
load_paths()

root.mainloop()