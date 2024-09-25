import customtkinter as ctk
import threading
import logging
import imaplib
import email as email_lib
from email.header import decode_header
import time
import os
from datetime import datetime, timedelta
import re
import openai
from tkhtmlview import HTMLLabel
from urllib.parse import urlparse
import webbrowser
import tkinter.messagebox as messagebox
import tkinter as tk
from tkinter import Listbox, Scrollbar
from tkinter.scrolledtext import ScrolledText
from PIL import Image
from unidecode import unidecode
import socket  # To check internet connection
import json
import sys
import locale


# Load translations based on selected language
def load_translation(language_code):
    try:
        with open(f"languages/{language_code}.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}  # Return empty dictionary if file not found


# Save configuration to config.txt
def save_config(config, filename="config.txt"):
    try:
        # Open the file with utf-8 encoding
        with open(filename, "w") as f:
            for key, value in config.items():
                f.write(f"{key}:{value}\n")
    except Exception as e:
        log_unexpected_error(e)


# Load email configuration and OpenAI key from config.txt
def load_config(filename="config.txt"):
    config = {}
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue  # Skip lines without key-value pair
                key, value = line.split(":", 1)
                config[key.strip()] = value.strip()
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise
    return config


config = load_config()

# Load the default language from config or use English
default_language = config.get("language_code", "en-US")
translations = load_translation(default_language)


# Function to get translated text
def tr(key):
    return translations.get(key, key)


# Initialize customtkinter
ctk.set_appearance_mode("dark")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "#4a9c34", "dark-blue"

openai.api_key = config["openai_key"]


# Check internet connection
def check_internet_connection():
    try:
        socket.create_connection(("www.google.com", 80))
        return True
    except OSError:
        return False


# Update internet connection status
def update_internet_status():
    is_connected = check_internet_connection()
    color = "#4a9c34" if is_connected else "#ed5e68"
    internet_status_label.configure(text="●", text_color=color)
    internet_status_detail_label.configure(
        text="INTERNET OK" if is_connected else "INTERNET DOWN",
        text_color=color,
        font=("Arial", 8),
    )
    root.after(5000, update_internet_status)  # Check every 5 seconds


# Load keywords from remove_keywords.txt
def load_keywords(filename="filters_files/remove_keywords.txt"):
    keywords = []
    try:
        with open(filename, "r") as f:
            keywords = [line.strip().lower() for line in f.readlines()]
    except Exception as e:
        log_unexpected_error(e)
        raise
    return keywords


# Load retain keywords from retain_keywords.txt
def load_retain_keywords(filename="filters_files/retain_keywords.txt"):
    retain_keywords = []
    try:
        with open(filename, "r") as f:
            retain_keywords = [line.strip().lower() for line in f.readlines()]
    except Exception as e:
        log_unexpected_error(e)
        raise
    return retain_keywords


keywords = load_keywords()
retain_keywords = load_retain_keywords()


# Load email domains from common_email_domains.txt
def load_email_domains(filename="filters_files/common_email_domains.txt"):
    domains = []
    try:
        with open(filename, "r") as f:
            domains = [line.strip().lower() for line in f.readlines()]
    except Exception as e:
        log_unexpected_error(e)
        raise
    return domains


email_domains = load_email_domains()


# Load unwanted senders from remove_senders.txt
def load_unwanted_senders(filename="filters_files/remove_senders.txt"):
    unwanted_senders = []
    try:
        with open(filename, "r") as f:
            unwanted_senders = [line.strip().lower() for line in f.readlines()]
    except Exception as e:
        log_unexpected_error(e)
        raise
    return unwanted_senders


unwanted_senders = load_unwanted_senders()

# Disable logging to the terminal
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("email_cleanup.log")],
)


# Handle unexpected errors and log them
def log_unexpected_error(e):
    with open("error_log.txt", "a") as error_file:
        error_file.write(f"{datetime.now()} - Unexpected error: {e}\n")
    logging.error(f"Unexpected error: {e}")


# Pre-filtering based on known spam keywords in the sender's email
def is_useless_email_keyword_filter(sender, subject, body):
    sender = sender.lower() if sender else ""

    # Check if the sender's domain is in the list of common email domains
    domain = sender.split("@")[-1]
    if domain in email_domains:
        return None  # Keep the email

    for unwanted_sender in unwanted_senders:
        if unwanted_sender in sender:
            return unwanted_sender.upper()

    for keyword in retain_keywords:
        if keyword in subject.lower() or keyword in body.lower():
            return None  # Retain the email if it matches a retain keyword

    for keyword in keywords:
        if keyword in subject.lower() or keyword in body.lower():
            return keyword.upper()

    return None


# Determine if an email is "useless" using GPT-3.5 or keyword filter
def is_useless_email(subject, sender, body, log_callback, update_openai_status, use_ai):
    # Check if the subject contains "Re:" or "Fw:"
    if "re:" in subject.lower() or "fw:" in subject.lower():
        log_callback(
            f"[KEPT] Email from {sender} with subject '{subject}' retained (Re/Fw detected).",
            "INFO",
        )
        return False  # Do not delete emails with Re: or Fw: in the subject

    keyword_reason = is_useless_email_keyword_filter(sender, subject, body)

    if keyword_reason:
        log_callback(
            f"[DELETED] Email from {sender} with subject '{subject}' moved to trash. [{keyword_reason}]",
            "INFO",
        )
        return True  # Filtered by keyword

    if use_ai:
        # Define a prompt to assess the importance of an email, including the body snippet
        prompt = f"Is the following email important? Subject: {subject} Sender: {sender} Short excerpt: {body[:200]}"

        try:
            update_openai_status("Connecting to OpenAI...", "#518cca")
            # Make the API call to OpenAI
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an assistant sorting your own emails. Be precise and make a thoughtful choice. Answer with YES/NO",
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=3,
                temperature=0.1,
            )
            update_openai_status("Connected to OpenAI", "#4a9c34")

            # Extract the response text
            answer = response.choices[0].message["content"].strip().lower()
            log_callback(f"OpenAI Response: [{answer.upper()}]", "INFO")

            # Determine if the email is considered important
            if answer == "no":
                log_callback(
                    f"[DELETED] Email from {sender} with subject '{subject}'.", "INFO"
                )
                return True
            else:
                log_callback(
                    f"[KEPT] Email from {sender} with subject '{subject}'.", "INFO"
                )
                return False
        except Exception as e:
            update_openai_status("OpenAI API Error", "#ed5e68")
            log_unexpected_error(e)
            log_callback(f"OpenAI API Error: {e}", "ERROR")
            return False  # Default to keeping the email if there's an error

    # If no keyword matched and AI is not used, keep the email
    log_callback(
        f"[KEPT] Email from {sender} with subject '{subject}' retained by keyword filter.",
        "INFO",
    )
    return False


# Extract and save unsubscribe links
def extract_and_save_unsubscribe_links(body):
    unsubscribe_links = {}
    lines = body.splitlines()

    for i, line in enumerate(lines):
        if "unsubscribe" in line.lower() or "unsubscribe" in line.lower():
            # Check nearby lines for URLs
            nearby_lines = lines[max(i - 2, 0) : i + 3]  # Adjust the range as needed
            for nearby_line in nearby_lines:
                urls = re.findall(r"(https?://\S+)", nearby_line)
                for url in urls:
                    # Validate URL to prevent Invalid IPv6 URL error
                    try:
                        domain = urlparse(url).netloc
                        if domain and domain not in unsubscribe_links:
                            unsubscribe_links[domain] = url
                    except ValueError:
                        continue

    if unsubscribe_links:
        with open("unsubscribe_links.txt", "a") as file:
            for link in unsubscribe_links.values():
                file.write(f"{link}\n")


# Archive deleted emails in HTML format
def archive_deleted_emails(sender, subject, body):
    filename = (
        f"deleted_emails/{datetime.now().strftime('%Y-%m-%d')}-{sender}-{subject}.html"
    )
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as file:
        file.write(
            f"<html><body><h2>Sender: {sender}</h2><h3>Subject: {subject}</h3><p>{body}</p></body></html>"
        )
    extract_and_save_unsubscribe_links(body)


# Save total counters and running time to a text file
def save_statistics(total_deleted, total_ignored, total_minutes):
    with open("stats.txt", "a") as stats_file:
        stats_file.write(
            f"{datetime.now()} - Deleted emails: {total_deleted}, Ignored emails: {total_ignored}, Execution time: {total_minutes} minutes\n"
        )


# Function to handle email cleanup process
def move_useless_emails_to_trash(
    stop_event,
    pause_event,
    log_callback,
    update_counters,
    update_status,
    update_email_count,
    last_processed_email_id,
    update_progress,
    use_ai,
    move_to_trash,
):
    config = load_config()
    start_time = time.time()

    try:
        mail = imaplib.IMAP4_SSL(config["imap_server"], config["imap_port"])
        mail.login(config["email_address"], config["password"])
        update_status(f"Connected to {config['email_address']}", "#4a9c34")

        # Get available mailboxes and select the inbox or a default mailbox
        status, mailboxes = mail.list()
        if status != "OK":
            raise Exception("Unable to retrieve the list of mailboxes.")

        inbox_found = False
        for mailbox in mailboxes:
            if b"INBOX" in mailbox.upper():
                status, _ = mail.select("INBOX")
                inbox_found = True
                break

        if not inbox_found:
            raise Exception("Inbox 'INBOX' not found.")

        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()
        total_emails = len(email_ids)

        # Update email count in UI
        update_email_count(total_emails)

        # Retrieve from the last processed email
        if last_processed_email_id:
            try:
                start_index = email_ids.index(last_processed_email_id.encode()) + 1
            except ValueError:
                start_index = 0
        else:
            start_index = 0

        session_deleted_count = 0
        session_ignored_count = 0

        for index, email_id in enumerate(email_ids[start_index:], start=start_index):
            if stop_event.is_set():
                log_callback("Process interrupted by user.", "WARNING")
                break

            while pause_event.is_set():
                time.sleep(0.5)

            try:
                status, msg_data = mail.fetch(email_id, "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email_lib.message_from_bytes(raw_email)

                # Process the email
                subject_decoded = decode_header(msg["Subject"])[0]
                subject = subject_decoded[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(
                        subject_decoded[1] if subject_decoded[1] else "utf-8"
                    )

                sender = msg.get("From")
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain" and not part.get(
                            "Content-Disposition"
                        ):
                            body += part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8"
                            )
                        elif part.get_content_type() == "text/html" and not part.get(
                            "Content-Disposition"
                        ):
                            body += part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8"
                            )
                else:
                    body = msg.get_payload(decode=True).decode(
                        msg.get_content_charset() or "utf-8"
                    )
                if is_useless_email(
                    subject, sender, body, log_callback, update_status, use_ai
                ):

                    if move_to_trash:
                        mail.store(email_id, "+X-GM-LABELS", "\\Trash")
                    else:
                        mail.store(email_id, "+FLAGS", "\\Deleted")
                    mail.expunge()
                    session_deleted_count += 1
                else:
                    session_ignored_count += 1

                # Update last_processed_email_id immediately after processing the email

                config["last_processed_email_id"] = email_id.decode()

                save_config(config)

                update_counters(session_deleted_count, session_ignored_count)
                update_progress(((index + 1) / total_emails) * 100)

                mail.expunge()
            except Exception as e:
                log_unexpected_error(e)
                log_callback(
                    f"Error processing email ID {email_id.decode()}: {e}", "ERROR"
                )

        mail.logout()
        end_time = time.time()
        total_minutes = (end_time - start_time) / 60
        save_statistics(session_deleted_count, session_ignored_count, total_minutes)
    except Exception as e:
        log_unexpected_error(e)
        update_status("Error connecting to email account", "#ed5e68")


# Function to open and edit text files within the program
def open_edit_window(filename, title, description=""):
    try:
        with open(filename, "r") as file:
            content = file.read()
    except FileNotFoundError:
        content = ""
        messagebox.showwarning(
            "File Missing", f"The file {filename} was not found.", icon="warning"
        )

    # Create a new window for editing the file
    edit_window = ctk.CTkToplevel()
    edit_window.title(title)
    edit_window.geometry("500x600")  # Adjust window size
    edit_window.minsize(500, 600)  # Minimum window size

    # Add description at the top
    if description:
        description_label = ctk.CTkLabel(
            edit_window, text=description, wraplength=480, justify="left"
        )
        description_label.pack(pady=10, padx=10)

    # ScrolledText widget to edit the file content
    text_widget = ScrolledText(edit_window, font=("Arial", 12))
    text_widget.pack(fill="both", expand=True, padx=10, pady=10)
    text_widget.insert(tk.END, content)

    # Save button to save changes made to the file
    def save_file():
        new_content = text_widget.get("1.0", tk.END).strip()
        with open(filename, "w") as file:
            file.write(new_content)
        messagebox.showinfo(
            "Save Successful", f"Changes have been saved to {filename}.", icon="info"
        )
        edit_window.destroy()

    save_button = ctk.CTkButton(
        edit_window, text="Save", command=save_file, height=30
    )  # Increase button height
    save_button.pack(pady=10)


# Function to open a new window to browse HTML archives
def open_html_archives():
    if (
        hasattr(open_html_archives, "archive_window")
        and open_html_archives.archive_window.winfo_exists()
    ):
        open_html_archives.archive_window.lift()
        return
    archive_window = ctk.CTkToplevel()
    open_html_archives.archive_window = archive_window
    archive_window.title("Deleted Emails Archives")
    archive_window.geometry("800x600")
    archive_window.minsize(800, 600)  # Minimum window size

    search_label = ctk.CTkLabel(archive_window, text="Search:")
    search_label.pack(pady=10)

    search_entry = ctk.CTkEntry(archive_window, width=400)
    search_entry.pack(pady=5)

    # Archive email list using Listbox from tkinter
    archive_listbox = Listbox(archive_window, width=100, height=25)
    archive_listbox.pack(pady=10, padx=10, fill="both", expand=True)
    scrollbar = Scrollbar(archive_window)
    scrollbar.pack(side="right", fill="y")

    archive_listbox.configure(yscrollcommand=scrollbar.set)
    scrollbar.configure(command=archive_listbox.yview)

    def update_archive_list(search_query=""):
        archive_listbox.delete(0, tk.END)  # Clear the listbox
        files = os.listdir("deleted_emails")
        for file in sorted(files):
            if search_query.lower() in file.lower():
                archive_listbox.insert(tk.END, file)

    def open_selected_file():
        selected_file = archive_listbox.get(archive_listbox.curselection()).strip()
        display_email(selected_file)

    def delete_selected_file():
        selected_file = archive_listbox.get(archive_listbox.curselection()).strip()
        os.remove(f"deleted_emails/{selected_file}")
        update_archive_list()
        messagebox.showinfo(
            "Deleted", f"The file {selected_file} has been deleted.", icon="info"
        )

    def delete_all_files():
        if messagebox.askyesno(
            "Confirm",
            "Are you sure you want to delete all archived emails?",
            icon="question",
        ):
            files = os.listdir("deleted_emails")
            for file in files:
                os.remove(f"deleted_emails/{file}")
            update_archive_list()
            messagebox.showinfo(
                "Deleted", "All archived emails have been deleted.", icon="info"
            )

    search_entry.bind(
        "<KeyRelease>", lambda event: update_archive_list(search_entry.get())
    )
    archive_listbox.bind("<<ListboxSelect>>", lambda event: open_selected_file())

    # Adding delete buttons
    delete_selected_button = ctk.CTkButton(
        archive_window,
        text="",
        image=ctk.CTkImage(Image.open("icons/delete_icon.png"), size=(20, 20)),
        command=delete_selected_file,
        state="disabled",
        fg_color="#ed5e68",
    )
    delete_selected_button.pack(side="left", padx=10, pady=10)

    delete_all_button = ctk.CTkButton(
        archive_window,
        text="Delete All Archived Emails",
        command=delete_all_files,
        fg_color="#ed5e68",
    )
    delete_all_button.pack(side="right", padx=10, pady=10)

    def update_buttons_state(event=None):
        if archive_listbox.curselection():
            delete_selected_button.configure(state="normal")
        else:
            delete_selected_button.configure(state="disabled")

    archive_listbox.bind("<<ListboxSelect>>", update_buttons_state)

    # Add a message regarding preview
    preview_warning_label = ctk.CTkLabel(
        archive_window,
        text="Note: Some emails may not display correctly due to formatting differences between servers.",
        text_color="#ed5e68",
        font=("Arial", 10),
    )
    preview_warning_label.pack(pady=5)

    update_archive_list()


# Function to display an email in HTML format
def display_email(filename):
    email_window = ctk.CTkToplevel()
    email_window.title(f"View: {filename}")
    email_window.geometry("800x600")
    email_window.minsize(800, 600)  # Minimum window size

    filepath = f"deleted_emails/{filename}"
    if not os.path.exists(filepath):
        messagebox.showerror(
            "Error", f"The file {filename} does not exist.", icon="error"
        )
        return

    with open(filepath, "r") as file:
        email_content = file.read()

    html_label = HTMLLabel(email_window, html=email_content)
    html_label.pack(fill="both", expand=True)

    # Add a button to delete the email
    delete_button = ctk.CTkButton(
        email_window,
        text="",
        image=ctk.CTkImage(Image.open("icons/delete_icon.png"), size=(20, 20)),
        command=lambda: delete_email(filepath, email_window),
        fg_color="#ed5e68",
    )
    delete_button.pack(pady=5)


def delete_email(filepath, email_window):
    os.remove(filepath)
    messagebox.showinfo(
        "Deleted",
        f"The email {os.path.basename(filepath)} has been deleted.",
        icon="info",
    )
    email_window.destroy()


# Function to handle unsubscribe links
def open_unsubscribe_links():
    if (
        hasattr(open_unsubscribe_links, "unsubscribe_window")
        and open_unsubscribe_links.unsubscribe_window.winfo_exists()
    ):
        open_unsubscribe_links.unsubscribe_window.lift()
        return
    unsubscribe_window = ctk.CTkToplevel()
    open_unsubscribe_links.unsubscribe_window = unsubscribe_window
    unsubscribe_window.title("Unsubscribe Links")
    unsubscribe_window.geometry("800x600")
    unsubscribe_window.minsize(800, 600)  # Minimum window size

    unsubscribe_frame = ctk.CTkFrame(unsubscribe_window)
    unsubscribe_frame.pack(pady=10, padx=10, fill="both", expand=True)

    # Unsubscribe email list using Listbox from tkinter
    unsubscribe_listbox = Listbox(unsubscribe_frame, width=100, height=25)
    unsubscribe_listbox.pack(side="left", fill="both", expand=True)
    scrollbar = Scrollbar(unsubscribe_frame)
    scrollbar.pack(side="right", fill="y")

    unsubscribe_listbox.configure(yscrollcommand=scrollbar.set)
    scrollbar.configure(command=unsubscribe_listbox.yview)

    open_link_button = ctk.CTkButton(
        unsubscribe_window, text="Open Link", state="disabled"
    )
    open_link_button.pack(pady=5)

    open_all_links_button = ctk.CTkButton(unsubscribe_window, text="Open All Links")
    open_all_links_button.pack(pady=5)

    def update_unsubscribe_list():
        unsubscribe_listbox.delete(0, tk.END)
        domains = set()
        try:
            with open("unsubscribe_links.txt", "r") as file:
                lines = file.readlines()
                for line in sorted(set(lines)):
                    domain = urlparse(line.strip()).netloc
                    if domain not in domains:
                        domains.add(domain)
                        unsubscribe_listbox.insert(tk.END, line)
        except FileNotFoundError:
            pass

    def remove_selected_link(selected_link):
        domain_to_remove = urlparse(selected_link).netloc
        with open("unsubscribe_links.txt", "r") as file:
            lines = file.readlines()

        with open("unsubscribe_links.txt", "w") as file:
            for line in lines:
                if urlparse(line.strip()).netloc != domain_to_remove:
                    file.write(line)

        with open("clicked_unsubscribe_links.txt", "a") as file:
            file.write(f"{selected_link}\n")

    def open_selected_link():
        selected_link = unsubscribe_listbox.get(
            unsubscribe_listbox.curselection()
        ).strip()
        webbrowser.open(selected_link)
        remove_selected_link(selected_link)
        update_unsubscribe_list()

    def open_all_links():
        if messagebox.askyesno(
            "Confirm", "Are you sure you want to open all links?", icon="question"
        ):
            links = unsubscribe_listbox.get(0, tk.END)
            for link in links:
                if link:
                    webbrowser.open(link)
                    remove_selected_link(link)
            update_unsubscribe_list()

    def delete_selected_link():
        selected_link = unsubscribe_listbox.get(
            unsubscribe_listbox.curselection()
        ).strip()
        remove_selected_link(selected_link)
        update_unsubscribe_list()
        messagebox.showinfo(
            "Deleted", f"The link {selected_link} has been deleted.", icon="info"
        )

    def delete_all_links():
        if messagebox.askyesno(
            "Confirm",
            "Are you sure you want to delete all unsubscribe links?",
            icon="question",
        ):
            open("unsubscribe_links.txt", "w").close()
            update_unsubscribe_list()
            messagebox.showinfo(
                "Deleted", "All unsubscribe links have been deleted.", icon="info"
            )

    unsubscribe_listbox.bind(
        "<<ListboxSelect>>", lambda event: open_link_button.configure(state="normal")
    )
    open_link_button.configure(command=open_selected_link)
    open_all_links_button.configure(command=open_all_links)

    # Adding delete buttons
    delete_selected_link_button = ctk.CTkButton(
        unsubscribe_window,
        text="",
        image=ctk.CTkImage(Image.open("icons/delete_icon.png"), size=(20, 20)),
        command=delete_selected_link,
        state="disabled",
        fg_color="#ed5e68",
    )
    delete_selected_link_button.pack(side="left", padx=10, pady=10)

    delete_all_links_button = ctk.CTkButton(
        unsubscribe_window,
        text="Delete All Links",
        command=delete_all_links,
        fg_color="#ed5e68",
    )
    delete_all_links_button.pack(side="right", padx=10, pady=10)

    def update_buttons_state(event=None):
        if unsubscribe_listbox.curselection():
            open_link_button.configure(state="normal")
            delete_selected_link_button.configure(state="normal")
        else:
            open_link_button.configure(state="disabled")
            delete_selected_link_button.configure(state="disabled")

    unsubscribe_listbox.bind("<<ListboxSelect>>", update_buttons_state)

    update_unsubscribe_list()


def get_available_mailboxes(mail):
    status, mailboxes = mail.list()
    if status == "OK":
        app.log_message("Available mailboxes:", "INFO")
        for mailbox in mailboxes:
            print("MailBox", mailbox.decode())
            app.log_message(mailbox.decode(), "INFO")
    else:
        raise Exception("Unable to retrieve the list of mailboxes.")


class EmailCleanupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Cleanup")
        self.root.geometry("1200x800")
        self.root.minsize(1200, 800)

        # Supported languages
        self.languages = {"English": "en-US", "Français": "fr-FR", "Español": "es-ES"}

        # Load icon images
        self.pencil_icon = ctk.CTkImage(
            Image.open("icons/pencil_icon.png"), size=(20, 20)
        )
        self.trash_icon = ctk.CTkImage(
            Image.open("icons/delete_icon.png"), size=(20, 20)
        )
        self.archive_icon = ctk.CTkImage(
            Image.open("icons/archive_icon.png"), size=(20, 20)
        )
        self.unsubscribe_icon = ctk.CTkImage(
            Image.open("icons/unsubscribe_icon.png"), size=(20, 20)
        )
        self.error_icon = ctk.CTkImage(
            Image.open("icons/error_icon.png"), size=(20, 20)
        )
        self.search_icon = ctk.CTkImage(
            Image.open("icons/search_icon.png"), size=(20, 20)
        )
        self.stats_icon = ctk.CTkImage(
            Image.open("icons/stats_icon.png"), size=(20, 20)
        )
        self.help_icon = ctk.CTkImage(Image.open("icons/help_icon.png"), size=(20, 20))

        # Load translations
        self.language_code = config.get("language_code", "en-US")
        self.translations = load_translation(self.language_code)

        # Create the left sidebar menu
        sidebar_frame = ctk.CTkFrame(root, width=200, corner_radius=0)
        sidebar_frame.pack(side="left", fill="y")

        # Add language selector
        self.language_var = ctk.StringVar(
            value=list(self.languages.keys())[
                list(self.languages.values()).index(self.language_code)
            ]
        )
        self.language_selector = ctk.CTkOptionMenu(
            sidebar_frame,
            values=list(self.languages.keys()),
            variable=self.language_var,
            command=self.change_language,
        )
        self.language_selector.pack(pady=10, padx=20)

        # Dark/Light mode switch
        self.mode_switch = ctk.CTkSwitch(
            sidebar_frame, text="Dark Mode", command=self.toggle_mode
        )
        self.mode_switch.pack(pady=20, padx=20)

        # Load and set the state of the "Move to Trash" checkbox from the config
        self.move_to_trash_var = ctk.BooleanVar(
            value=config.get("move_to_trash", "False") == "True"
        )
        self.move_to_trash_checkbox = ctk.CTkCheckBox(
            sidebar_frame,
            text="Move to Trash instead of Deleting",
            variable=self.move_to_trash_var,
        )
        self.move_to_trash_checkbox.pack(pady=10, padx=20)

        # Sidebar buttons
        self.clear_logs_button = ctk.CTkButton(
            sidebar_frame,
            text="View Error Logs",
            command=self.open_error_logs,
            image=self.error_icon,
            compound="left",
        )
        self.clear_logs_button.pack(pady=10, padx=20)

        self.open_archives_button = ctk.CTkButton(
            sidebar_frame,
            text="Open Archived Emails",
            command=open_html_archives,
            image=self.archive_icon,
            compound="left",
        )
        self.open_archives_button.pack(pady=10, padx=20)

        self.search_emails_button = ctk.CTkButton(
            sidebar_frame,
            text="Search Emails",
            command=self.open_search_window,
            image=self.search_icon,
            compound="left",
        )
        self.search_emails_button.pack(pady=10, padx=20)

        # Ajouter un bouton pour la suppression sur mesure
        self.custom_delete_button = ctk.CTkButton(
            sidebar_frame,
            text="Custom Delete",
            command=self.open_custom_delete_window,
            image=self.trash_icon,
            compound="left",
        )
        self.custom_delete_button.pack(pady=10, padx=20)

        self.open_unsubscribe_button = ctk.CTkButton(
            sidebar_frame,
            text="Manage Unsubscribe Links",
            command=open_unsubscribe_links,
            image=self.unsubscribe_icon,
            compound="left",
        )
        self.open_unsubscribe_button.pack(pady=10, padx=20)

        # Separator for design separation
        separator = ctk.CTkFrame(sidebar_frame, height=2, width=180, corner_radius=0)
        separator.pack(pady=20, padx=10)

        # Edit buttons with pencil icon
        self.edit_keywords_button = ctk.CTkButton(
            sidebar_frame,
            text="Edit Keywords",
            image=self.pencil_icon,
            compound="left",
            command=self.open_keywords_window,
        )
        self.edit_keywords_button.pack(pady=10, padx=20)

        self.edit_email_domains_button = ctk.CTkButton(
            sidebar_frame,
            text="Edit Email Domains",
            image=self.pencil_icon,
            compound="left",
            command=self.open_email_domains_file,
        )
        self.edit_email_domains_button.pack(pady=10, padx=20)

        self.edit_senders_button = ctk.CTkButton(
            sidebar_frame,
            text="Edit Senders",
            image=self.pencil_icon,
            compound="left",
            command=self.open_senders_file,
        )
        self.edit_senders_button.pack(pady=10, padx=20)

        self.edit_config_button = ctk.CTkButton(
            sidebar_frame,
            text="Edit Configuration",
            image=self.pencil_icon,
            compound="left",
            command=self.open_config,
        )
        self.edit_config_button.pack(pady=10, padx=20)

        # Display last email ID and version info
        last_email_id = config.get("last_processed_email_id", "N/A")
        total_emails = 0  # Replace this with the actual method to count emails
        self.version_label = ctk.CTkLabel(
            sidebar_frame,
            text=f"Emails in Inbox: {total_emails}\nLast Email ID (on start): {last_email_id}\nVersion: BETA B 4",
            font=("Arial", 18),
        )
        self.version_label.pack(pady=20, padx=10, side="bottom")

        # Internet connection status indicator
        global internet_status_label, internet_status_detail_label
        internet_status_label = ctk.CTkLabel(
            sidebar_frame, text="●", font=("Arial", 24), text_color="#ed5e68"
        )
        internet_status_label.pack(pady=10, padx=10, side="bottom")

        internet_status_detail_label = ctk.CTkLabel(
            sidebar_frame, text="", font=("Arial", 8)
        )
        internet_status_detail_label.pack(pady=5, padx=10, side="bottom")

        update_internet_status()

        # Main content area (right side)
        main_frame = ctk.CTkFrame(root, corner_radius=20)
        main_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)

        # Status display in the top of the main area
        self.status_label = ctk.CTkLabel(
            main_frame,
            text="Status: Waiting",
            font=("Arial", 16),
            anchor="w",
            pady=10,
            padx=10,
        )
        self.status_label.pack(side="top", fill="x")

        self.email_label = ctk.CTkLabel(
            main_frame,
            text="Not connected",
            text_color="#ed5e68",
            font=("Arial", 14),
            anchor="w",
            pady=10,
            padx=10,
        )
        self.email_label.pack(side="top", fill="x")

        # Add the help button in the top-right corner
        self.help_button = ctk.CTkButton(
            main_frame,
            text="",
            image=self.help_icon,
            command=self.open_tutorial_window,
            height=30,
            width=30,
            fg_color="#2b2b2b",
        )
        self.help_button.place(
            relx=0.98, rely=0.02, anchor="ne"
        )  # Position with extra padding

        # Logs display area using ScrolledText from tkinter
        self.log_text = ScrolledText(
            main_frame,
            width=120,
            height=20,
            font=("Arial", 12),
            state=tk.DISABLED,
            relief="flat",
            wrap="word",
            borderwidth=2,
            padx=10,
            pady=10,
        )
        self.log_text.pack(pady=10, padx=10, fill="both", expand=True)

        # Progress bar and percentage
        self.progress = ctk.CTkProgressBar(
            main_frame, orientation="horizontal", width=400
        )
        self.progress.set(0)  # Initialize to 0
        self.progress.pack(pady=10)

        self.progress_label = ctk.CTkLabel(main_frame, text="0%", font=("Arial", 12))
        self.progress_label.pack(pady=5)

        # AI Usage Checkbox
        self.use_ai_var = ctk.BooleanVar(value=True)
        self.use_ai_checkbox = ctk.CTkCheckBox(
            main_frame,
            text="Use AI to Sort Emails",
            variable=self.use_ai_var,
            command=self.check_ai_usage,
        )
        self.use_ai_checkbox.pack(pady=10)

        # Notice Label
        self.notice_label = ctk.CTkLabel(
            main_frame, text="", text_color="#ed5e68", font=("Arial", 12)
        )
        self.notice_label.pack(pady=10)

        # Control buttons
        control_frame = ctk.CTkFrame(main_frame)
        control_frame.pack(pady=20, padx=20, fill="x", expand=True)

        self.start_button = ctk.CTkButton(
            control_frame,
            text="Start",
            command=self.start_cleanup,
            fg_color="#4a9c34",
        )
        self.start_button.pack(
            side="left", padx=10, pady=10, anchor="center", expand=True
        )

        self.pause_button = ctk.CTkButton(
            control_frame, text="Pause", state="disabled", command=self.pause_cleanup
        )
        self.pause_button.pack(
            side="left", padx=10, pady=10, anchor="center", expand=True
        )

        self.stop_button = ctk.CTkButton(
            control_frame,
            text="Stop",
            state="disabled",
            command=self.stop_cleanup,
            fg_color="#ed5e68",
        )
        self.stop_button.pack(
            side="left", padx=10, pady=10, anchor="center", expand=True
        )

        # Removed Empty Trash button as per request

        # Counters display
        counters_frame = ctk.CTkFrame(main_frame)
        counters_frame.pack(pady=10, padx=10, fill="x")

        self.total_processed_label = ctk.CTkLabel(
            counters_frame,
            text=f"Total Emails Processed (Session): 0",
            font=("Arial", 12),
        )
        self.total_processed_label.pack(pady=5, side="left", padx=10)

        self.deleted_count_label = ctk.CTkLabel(
            counters_frame, text=f"Deleted Emails (Session): 0", font=("Arial", 12)
        )
        self.deleted_count_label.pack(pady=5, side="left", padx=10)

        self.ignored_count_label = ctk.CTkLabel(
            counters_frame, text=f"Ignored Emails (Session): 0", font=("Arial", 12)
        )
        self.ignored_count_label.pack(pady=5, side="left", padx=10)

        self.session_time_label = ctk.CTkLabel(
            counters_frame, text=f"Execution Time (minutes): 0", font=("Arial", 12)
        )
        self.session_time_label.pack(pady=5, side="left", padx=10)

        # Add a small magnifying glass button to open the stats window
        self.stats_button = ctk.CTkButton(
            counters_frame,
            text="",
            image=self.stats_icon,
            command=self.open_stats_window,
            height=30,
            width=30,
        )
        self.stats_button.pack(pady=5, side="right", padx=10)

        # Control variables
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.is_paused = False
        self.cleanup_thread = None
        self.session_deleted_count = 0
        self.session_ignored_count = 0
        self.start_time = None

        # Restore appearance mode from config
        appearance_mode = config.get("appearance_mode", "Dark").capitalize()
        if appearance_mode == "Light":
            self.toggle_mode()

    def change_language(self, selected_language):
        # Update the language code based on the selected language
        self.language_code = self.languages[selected_language]
        config["language_code"] = (
            self.language_code
        )  # Save the selected language to config
        save_config(config)  # Save config
        # Reload translations
        self.translations = load_translation(self.language_code)
        # Update all text in the UI
        self.update_ui_text()

        # Show a popup to inform about language change effect on next start
        messagebox.showinfo(
            "Language Changed",
            "The language will be updated on the next start.",
            icon="info",
        )

    def update_ui_text(self):
        # Update all the text elements in the UI to the selected language
        self.root.title(tr("Email Cleanup"))
        self.language_selector.set(tr(self.language_var.get()))
        self.mode_switch.configure(
            text=(
                tr("Dark Mode")
                if ctk.get_appearance_mode() == "Dark"
                else tr("Light Mode")
            )
        )
        # Update other UI elements as well...

    # Define the tr function to get translated text
    def tr(self, key):
        return self.translations.get(key, key)

    def toggle_mode(self):
        # Toggle between Dark and Light mode
        if ctk.get_appearance_mode() == "Dark":
            ctk.set_appearance_mode("Light")
            self.mode_switch.configure(text="Light Mode")
            config["appearance_mode"] = "Light"
        else:
            ctk.set_appearance_mode("Dark")
            self.mode_switch.configure(text="Dark Mode")
            config["appearance_mode"] = "Dark"
        save_config(config)

    def open_tutorial_window(self):
        # Implement the tutorial window creation and display logic here
        pass

    def log_message(self, message, level="INFO"):
        self.log_text.configure(state=tk.NORMAL)
        if "[DELETED]" in message:
            self.log_text.insert(tk.END, f"{level} - {message}\n", "#ca9e51")
            self.log_text.tag_config("#ca9e51", foreground="#ca9e51")
        elif "[KEPT]" in message:
            self.log_text.insert(tk.END, f"{level} - {message}\n", "#518cca")
            self.log_text.tag_config("#518cca", foreground="#518cca")
        elif "Process" in message:
            self.log_text.insert(tk.END, f"{level} - {message}\n", "#b6b5b5")
            self.log_text.tag_config("#b6b5b5", foreground="#b6b5b5")
        elif "ERROR" in message:
            self.log_text.insert(tk.END, f"{level} - {message}\n", "#ed5e68")
            self.log_text.tag_config("#ed5e68", foreground="#ed5e68")
        elif "OpenAI Response" in message:
            self.log_text.insert(tk.END, f"{level} - {message}\n", "#86861a")
            self.log_text.tag_config("#86861a", foreground="#86861a")
        else:
            self.log_text.insert(tk.END, f"{level} - {message}\n")
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.see(tk.END)
        logging.log(getattr(logging, level), message)

    def update_counters(self, deleted_count, ignored_count):
        self.deleted_count_label.configure(
            text=f"Deleted Emails (Session): {deleted_count}"
        )
        self.ignored_count_label.configure(
            text=f"Ignored Emails (Session): {ignored_count}"
        )
        self.total_processed_label.configure(
            text=f"Total Emails Processed (Session): {deleted_count + ignored_count}"
        )

    def update_progress(self, value):
        self.progress.set(value / 100)
        self.progress_label.configure(text=f"{int(value)}%")
        self.root.update_idletasks()

    def update_email_count(self, count):
        self.version_label.configure(
            text=f"Emails in Inbox: {count}\nLast Email ID (on start): {config.get('last_processed_email_id', 'N/A')}\nVersion: BETA B 4"
        )

    def check_ai_usage(self):
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.use_ai_checkbox.configure(state="disabled")
            self.notice_label.configure(text="Stop the process to modify AI usage.")
        else:
            self.use_ai_checkbox.configure(state="normal")
            self.notice_label.configure(text="")

        # Save the checkbox status to the config file
        config["use_ai"] = str(self.use_ai_var.get())
        save_config(config)

    def start_cleanup(self):
        self.progress.set(0)
        self.progress_label.configure(text="0%")
        self.status_label.configure(text="Status: In Progress", text_color="#4a9c34")
        self.start_button.configure(state="disabled")
        self.pause_button.configure(state="normal")
        self.stop_button.configure(state="normal")
        self.use_ai_checkbox.configure(state="disabled")
        self.move_to_trash_checkbox.configure(
            state="disabled"
        )  # Disable the checkbox when running
        self.notice_label.configure(text="Stop the process to modify settings.")
        self.stop_event.clear()
        self.start_time = time.time()
        config = load_config()
        last_processed_email_id = config.get("last_processed_email_id", None)
        use_ai = self.use_ai_var.get()
        move_to_trash = (
            self.move_to_trash_var.get()
        )  # Get the status of the "Move to Trash" checkbox
        self.cleanup_thread = threading.Thread(
            target=move_useless_emails_to_trash,
            args=(
                self.stop_event,
                self.pause_event,
                self.log_message,
                self.update_counters,
                self.update_status,
                self.update_email_count,
                last_processed_email_id,
                self.update_progress,
                use_ai,
                move_to_trash,
            ),
        )
        self.cleanup_thread.start()
        self.update_session_time()

    def pause_cleanup(self):
        if not self.is_paused:
            self.is_paused = True
            self.pause_button.configure(text="Resume")
            self.stop_button.configure(state="disabled")
            self.notice_label.configure(
                text="The program must be running to enable the Stop button."
            )
            self.status_label.configure(text="Status: Paused", text_color="#ca9e51")
            self.pause_event.set()
        else:
            self.is_paused = False
            self.pause_button.configure(text="Pause")
            self.stop_button.configure(state="normal")
            self.notice_label.configure(text="")
            self.status_label.configure(
                text="Status: In Progress", text_color="#4a9c34"
            )
            self.pause_event.clear()

    def stop_cleanup(self):
        self.stop_event.set()
        self.status_label.configure(text="Status: Stopped", text_color="#ed5e68")
        self.start_button.configure(state="normal")
        self.pause_button.configure(state="disabled")
        self.pause_button.configure(text="Pause")
        self.stop_button.configure(state="disabled")
        self.use_ai_checkbox.configure(state="normal")
        self.move_to_trash_checkbox.configure(
            state="normal"
        )  # Enable the checkbox when stopped
        self.notice_label.configure(text="")
        self.log_message("Cleanup process interrupted.", "WARNING")

    def open_config(self, event=None):
        config = load_config()

        def save_and_confirm():
            new_email = email_entry.get().strip()
            new_password = password_entry.get().strip()
            new_imap_server = imap_entry.get().strip()
            new_imap_port = port_entry.get().strip()
            last_email_id = last_email_entry.get().strip()

            def test_connection():
                try:
                    mail = imaplib.IMAP4_SSL(new_imap_server, new_imap_port)
                    mail.login(new_email, new_password)
                    mail.logout()
                    return True
                except Exception as e:
                    return False

            if test_connection():
                confirmation = messagebox.askyesno(
                    "Confirm",
                    f"Do you confirm the changes?\n\nEmail: {new_email}\nIMAP Server: {new_imap_server}\nIMAP Port: {new_imap_port}\nLast Processed ID: {last_email_id}",
                    icon="question",
                )
                if confirmation:
                    config["email_address"] = new_email
                    config["password"] = new_password
                    config["imap_server"] = new_imap_server
                    config["imap_port"] = new_imap_port
                    config["last_processed_email_id"] = last_email_id
                    config["move_to_trash"] = str(
                        self.move_to_trash_var.get()
                    )  # Save the checkbox state
                    save_config(config)
                    messagebox.showinfo(
                        "Changes Saved",
                        "The changes have been successfully saved.",
                        icon="info",
                    )
                    edit_window.destroy()
            else:
                messagebox.showerror(
                    "Connection Error",
                    "Unable to connect with the provided information. Please check and try again.",
                    icon="error",
                )

        edit_window = ctk.CTkToplevel()
        edit_window.title("Edit Config.txt")
        edit_window.geometry("500x450")
        edit_window.resizable(True, True)

        ctk.CTkLabel(edit_window, text="Email:").pack(pady=5)
        email_entry = ctk.CTkEntry(edit_window)
        email_entry.pack(pady=5)
        email_entry.insert(0, config["email_address"])

        ctk.CTkLabel(edit_window, text="Password:").pack(pady=5)
        password_entry = ctk.CTkEntry(edit_window, show="*")
        password_entry.pack(pady=5)
        password_entry.insert(0, config["password"])

        ctk.CTkLabel(edit_window, text="IMAP Server:").pack(pady=5)
        imap_entry = ctk.CTkEntry(edit_window)
        imap_entry.pack(pady=5)
        imap_entry.insert(0, config["imap_server"])

        ctk.CTkLabel(edit_window, text="IMAP Port:").pack(pady=5)
        port_entry = ctk.CTkEntry(edit_window)
        port_entry.pack(pady=5)
        port_entry.insert(0, config["imap_port"])

        ctk.CTkLabel(edit_window, text="Last Processed Email ID:").pack(pady=5)
        last_email_entry = ctk.CTkEntry(edit_window)
        last_email_entry.pack(pady=5)
        last_email_entry.insert(0, config["last_processed_email_id"])

        ctk.CTkButton(edit_window, text="Save", command=save_and_confirm).pack(pady=20)

    def open_keywords_window(self):
        # Create a new window to edit the two files remove_keywords.txt and retain_keywords.txt
        keywords_window = ctk.CTkToplevel()
        keywords_window.title("Edit Keywords")
        keywords_window.geometry("800x600")
        keywords_window.minsize(800, 600)

        try:
            with open("filters_files/remove_keywords.txt", "r") as f:
                keywords_content = f.read()
        except FileNotFoundError:
            keywords_content = ""
            messagebox.showwarning(
                "File Missing",
                "The file remove_keywords.txt was not found.",
                icon="warning",
            )

        try:
            with open("filters_files/retain_keywords.txt", "r") as f:
                retain_keywords_content = f.read()
        except FileNotFoundError:
            retain_keywords_content = ""
            messagebox.showwarning(
                "File Missing",
                "The file retain_keywords.txt was not found.",
                icon="warning",
            )

        ctk.CTkLabel(
            keywords_window,
            text="Keywords to delete emails:",
            wraplength=580,
            justify="left",
        ).pack(pady=10, padx=10)
        keywords_text = ScrolledText(keywords_window, font=("Arial", 12), height=20)
        keywords_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        keywords_text.insert(tk.END, keywords_content)

        ctk.CTkLabel(
            keywords_window,
            text="Keywords to retain emails:",
            wraplength=580,
            justify="left",
        ).pack(pady=10, padx=10)
        retain_keywords_text = ScrolledText(
            keywords_window, font=("Arial", 12), height=20
        )
        retain_keywords_text.pack(
            side="left", fill="both", expand=True, padx=10, pady=10
        )
        retain_keywords_text.insert(tk.END, retain_keywords_content)

        def save_keywords():
            new_keywords_content = keywords_text.get("1.0", tk.END).strip()
            with open("filters_files/remove_keywords.txt", "w") as f:
                f.write(new_keywords_content)
            messagebox.showinfo(
                "Save Successful",
                "Changes have been saved to remove_keywords.txt.",
                icon="info",
            )

        def save_retain_keywords():
            new_retain_keywords_content = retain_keywords_text.get(
                "1.0", tk.END
            ).strip()
            with open("filters_files/retain_keywords.txt", "w") as f:
                f.write(new_retain_keywords_content)
            messagebox.showinfo(
                "Save Successful",
                "Changes have been saved to retain_keywords.txt.",
                icon="info",
            )

        save_keywords_button = ctk.CTkButton(
            keywords_window, text="Save Keywords", command=save_keywords
        )
        save_keywords_button.pack(pady=10, padx=10)

        save_retain_keywords_button = ctk.CTkButton(
            keywords_window, text="Save Retain Keywords", command=save_retain_keywords
        )
        save_retain_keywords_button.pack(pady=10, padx=10)

    def open_email_domains_file(self):
        open_edit_window(
            "filters_files/common_email_domains.txt",
            "Edit Email Domains.txt",
            description="List of email domains. Emails from these domains will not be filtered.",
        )

    def open_senders_file(self):
        open_edit_window(
            "filters_files/remove_senders.txt",
            "Edit Senders.txt",
            description="List of unwanted senders. Emails from these senders will be automatically deleted.",
        )

    def open_error_logs(self):
        logs_window = ctk.CTkToplevel()
        logs_window.title("Error Logs")
        logs_window.geometry("600x400")

        logs_text = ScrolledText(
            logs_window,
            font=("Arial", 12),
            state=tk.DISABLED,
            relief="flat",
            wrap="word",
            borderwidth=2,
            padx=10,
            pady=10,
        )
        logs_text.pack(fill="both", expand=True)

        try:
            with open("error_log.txt", "r") as log_file:
                logs_content = log_file.read()
                logs_text.configure(state=tk.NORMAL)
                logs_text.insert(tk.END, logs_content)
                logs_text.configure(state=tk.DISABLED)
        except FileNotFoundError:
            logs_text.configure(state=tk.NORMAL)
            logs_text.insert(tk.END, "No error logs found.")
            logs_text.configure(state=tk.DISABLED)

        def clear_logs():
            if messagebox.askyesno(
                "Confirm",
                "Are you sure you want to clear the error logs?",
                icon="question",
            ):
                open("error_log.txt", "w").close()
                logs_text.configure(state=tk.NORMAL)
                logs_text.delete("1.0", tk.END)
                logs_text.insert(tk.END, "Error logs cleared.")
                logs_text.configure(state=tk.DISABLED)

        clear_button = ctk.CTkButton(
            logs_window, text="Clear Error Logs", command=clear_logs, fg_color="#ed5e68"
        )
        clear_button.pack(pady=10)

    def update_status(self, message, color):
        self.email_label.configure(text=message, text_color=color)

    def update_session_time(self):
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            elapsed_time = (time.time() - self.start_time) / 60
            self.session_time_label.configure(
                text=f"Execution Time (minutes): {int(elapsed_time)}"
            )
            self.root.after(1000 * 60, self.update_session_time)

    def open_search_window(self):
        search_window = ctk.CTkToplevel()
        search_window.title("Search Emails")
        search_window.geometry("800x700")
        search_window.resizable(True, True)

        search_label = ctk.CTkLabel(search_window, text="Search:")
        search_label.pack(pady=10)

        search_entry = ctk.CTkEntry(search_window, width=400)
        search_entry.pack(pady=5)

        search_button = ctk.CTkButton(
            search_window,
            text="",
            image=self.search_icon,
            compound="left",
            command=lambda: search_emails(search_entry.get()),
            height=30,
            width=30,
        )
        search_button.pack(pady=10)

        results_listbox = Listbox(search_window, width=100, height=25)
        results_listbox.pack(pady=10, padx=10, fill="both", expand=True)
        scrollbar = Scrollbar(search_window)
        scrollbar.pack(side="right", fill="y")

        results_listbox.configure(yscrollcommand=scrollbar.set)
        scrollbar.configure(command=results_listbox.yview)

        def search_emails(query):
            config = load_config()
            mail = imaplib.IMAP4_SSL(config["imap_server"], config["imap_port"])
            mail.login(config["email_address"], config["password"])

            results_listbox.delete(0, tk.END)

            mail.select("INBOX")
            status, messages = mail.search(
                None, f'(OR (SUBJECT "{query}") (FROM "{query}") (BODY "{query}"))'
            )
            if status == "OK":
                email_ids = messages[0].split()
                total_results = len(email_ids)
                limited_results = email_ids[:100]

                for email_id in limited_results:
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    raw_email = msg_data[0][1]
                    msg = email_lib.message_from_bytes(raw_email)

                    subject_decoded = decode_header(msg["Subject"])[0]
                    subject = subject_decoded[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(
                            subject_decoded[1] if subject_decoded[1] else "utf-8"
                        )

                    sender = msg.get("From")
                    results_listbox.insert(tk.END, f"{subject} - {sender}")

                results_count_label.configure(
                    text=f"Results Found: {total_results} - Showing the first {min(total_results, 100)} results"
                )
            mail.logout()

        def open_selected_email():
            selected_index = results_listbox.curselection()
            if selected_index:
                selected_email = results_listbox.get(selected_index)
                download_and_open_email(selected_email)

        def download_and_open_email(email_entry):
            config = load_config()
            mail = imaplib.IMAP4_SSL(config["imap_server"], config["imap_port"])
            mail.login(config["email_address"], config["password"])

            mail.select("INBOX")

            # Encode email_entry to UTF-8 to handle non-ASCII characters
            email_entry_utf8 = email_entry.encode("utf-8")

            # Use the BINARY option in IMAP search for handling UTF-8 strings
            status, messages = mail.search(
                None,
                f'OR (SUBJECT "{email_entry_utf8.decode("utf-8")}") (FROM "{email_entry_utf8.decode("utf-8")}")',
            )

            if status == "OK":
                email_ids = messages[0].split()

                for email_id in email_ids[:1]:
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    raw_email = msg_data[0][1]
                    msg = email_lib.message_from_bytes(raw_email)

                    subject_decoded = decode_header(msg["Subject"])[0]
                    subject = subject_decoded[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(
                            subject_decoded[1] if subject_decoded[1] else "utf-8"
                        )

                    sender = msg.get("From")

                    if not os.path.exists("tmp"):
                        os.makedirs("tmp")
                    filename = f"tmp/{subject}.html"
                    with open(filename, "w") as file:
                        file.write(
                            f"<html><body><h2>Sender: {sender}</h2><h3>Subject: {subject}</h3><p>{msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')}</p></body></html>"
                        )

                    webbrowser.open(filename)

            mail.logout()
            config = load_config()
            mail = imaplib.IMAP4_SSL(config["imap_server"], config["imap_port"])
            mail.login(config["email_address"], config["password"])

            mail.select("INBOX")
            status, messages = mail.search(
                None, f'(OR (SUBJECT "{email_entry}") (FROM "{email_entry}"))'
            )

            if status == "OK":
                email_ids = messages[0].split()

                for email_id in email_ids[:1]:
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    raw_email = msg_data[0][1]
                    msg = email_lib.message_from_bytes(raw_email)

                    subject_decoded = decode_header(msg["Subject"])[0]
                    subject = subject_decoded[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(
                            subject_decoded[1] if subject_decoded[1] else "utf-8"
                        )

                    sender = msg.get("From")

                    if not os.path.exists("tmp"):
                        os.makedirs("tmp")
                    filename = f"tmp/{subject}.html"
                    with open(filename, "w") as file:
                        file.write(
                            f"<html><body><h2>Sender: {sender}</h2><h3>Subject: {subject}</h3><p>{msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')}</p></body></html>"
                        )

                    webbrowser.open(filename)

            mail.logout()

        search_entry.bind("<Return>", lambda event: search_emails(search_entry.get()))
        results_listbox.bind("<Double-1>", lambda event: open_selected_email())

        results_count_label = ctk.CTkLabel(search_window, text="Results Found: 0")
        results_count_label.pack(pady=5)

    def open_stats_window(self):
        stats_window = ctk.CTkToplevel()
        stats_window.title("Session Statistics")
        stats_window.geometry("500x400")
        stats_window.minsize(500, 400)

        try:
            with open("stats.txt", "r") as stats_file:
                stats_content = stats_file.read()
        except FileNotFoundError:
            stats_content = "No statistics recorded."

        stats_text = ScrolledText(stats_window, font=("Arial", 12))
        stats_text.pack(fill="both", expand=True, padx=10, pady=10)
        stats_text.insert(tk.END, stats_content)
        stats_text.configure(state=tk.DISABLED)

        # Adding the new feature button for email usage insights
        def open_email_usage_insights():
            insights_window = ctk.CTkToplevel()
            insights_window.title("Email Usage Insights")
            insights_window.geometry("600x500")

            insights_text = ScrolledText(insights_window, font=("Arial", 12))
            insights_text.pack(fill="both", expand=True, padx=10, pady=10)
            insights_text.insert(tk.END, self.generate_email_insights())
            insights_text.configure(state=tk.DISABLED)

        insights_button = ctk.CTkButton(
            stats_window,
            text="Email Usage Insights",
            command=open_email_usage_insights,
            fg_color="#4a9c34",
        )
        insights_button.pack(pady=10)

    def open_custom_delete_window(self):
        custom_delete_window = ctk.CTkToplevel()
        custom_delete_window.title("Custom Delete Emails")
        custom_delete_window.geometry("600x400")

        ctk.CTkLabel(custom_delete_window, text="Select Filter:").pack(pady=10)

        # Define the filter_option variable before using it
        filter_option = ctk.StringVar(value="sender email")

        filter_dropdown = ctk.CTkOptionMenu(
            custom_delete_window,
            variable=filter_option,
            values=["sender email", "keyword", "date range"],
        )
        filter_dropdown.pack(pady=10)

        text_input_label = ctk.CTkLabel(custom_delete_window, text="Enter Value:")
        text_input_label.pack(pady=10)
        text_input = ctk.CTkEntry(custom_delete_window, width=400)
        text_input.pack(pady=10)

        # Date selection fields (initially hidden)
        date_from_label = ctk.CTkLabel(custom_delete_window, text="Date From:")
        date_to_label = ctk.CTkLabel(custom_delete_window, text="Date To:")
        date_from_entry = ctk.CTkEntry(custom_delete_window, width=200)
        date_to_entry = ctk.CTkEntry(custom_delete_window, width=200)

        # Function to show/hide date inputs
        def update_input_fields(*args):
            if filter_option.get() == "date range":
                text_input.pack_forget()
                text_input_label.pack_forget()
                date_from_label.pack(pady=5)
                date_from_entry.pack(pady=5)
                date_to_label.pack(pady=5)
                date_to_entry.pack(pady=5)
            else:
                date_from_label.pack_forget()
                date_from_entry.pack_forget()
                date_to_label.pack_forget()
                date_to_entry.pack_forget()
                text_input_label.pack(pady=10)
                text_input.pack(pady=10)

        filter_option.trace("w", update_input_fields)

        log_frame = ctk.CTkFrame(custom_delete_window)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        log_text = ScrolledText(log_frame, state="disabled", wrap="word")
        log_text.pack(fill="both", expand=True)

        # Function to handle custom deletion
        def perform_custom_delete():
            filter_type = filter_option.get()
            filter_value = (
                text_input.get()
                if filter_type != "date range"
                else (date_from_entry.get(), date_to_entry.get())
            )
            if not filter_value or (
                filter_type == "date range"
                and (not filter_value[0] or not filter_value[1])
            ):
                messagebox.showwarning(
                    "Input Error", "Please provide valid input for the selected filter."
                )
                return

            log_text.configure(state="normal")
            log_text.insert(
                tk.END,
                f"Performing deletion with filter: {filter_type} = {filter_value}\n",
            )
            log_text.configure(state="disabled")

            # Dummy deletion process for illustration
            log_text.configure(state="normal")
            log_text.insert(tk.END, "Deleted emails matching the criteria.\n")
            log_text.configure(state="disabled")

        delete_button = ctk.CTkButton(
            custom_delete_window,
            text="Delete Emails",
            command=perform_custom_delete,
            fg_color="#ed5e68",
        )
        delete_button.pack(pady=10)

        # Add a loading bar to show progress
        progress_bar = ctk.CTkProgressBar(
            custom_delete_window, orientation="horizontal", width=400
        )
        progress_bar.set(0)
        progress_bar.pack(pady=10)

    def generate_email_insights(self):
        insights = f"Email Usage Insights: \n\n"
        try:
            config = load_config()
            mail = imaplib.IMAP4_SSL(config["imap_server"], config["imap_port"])
            mail.login(config["email_address"], config["password"])

            mail.select("INBOX")
            status, messages = mail.search(None, "ALL")
            if status != "OK":
                return "Error retrieving emails."

            email_ids = messages[0].split()
            total_emails = len(email_ids)

            senders = {}
            keywords = {}
            response_times = []
            emails_per_day = {}

            for email_id in email_ids:
                status, msg_data = mail.fetch(email_id, "(RFC822)")
                raw_email = msg_data[0][1]
                msg = email_lib.message_from_bytes(raw_email)

                # Count senders
                sender = msg.get("From")
                if sender:
                    if sender in senders:
                        senders[sender] += 1
                    else:
                        senders[sender] = 1

                # Extract keywords from subject
                subject = msg.get("Subject")
                if subject:
                    decoded_subject = ""
                    for part in decode_header(subject):
                        try:
                            if isinstance(part[0], bytes):
                                decoded_subject += part[0].decode(
                                    part[1] if part[1] else "utf-8"
                                )
                            else:
                                decoded_subject += part[0]
                        except (UnicodeDecodeError, LookupError):
                            decoded_subject += (
                                part[0].decode("latin1")
                                if isinstance(part[0], bytes)
                                else part[0]
                            )

                    if decoded_subject:
                        for word in decoded_subject.split():
                            word = word.lower()
                            if word in keywords:
                                keywords[word] += 1
                            else:
                                keywords[word] = 1

                # Calculate response times if applicable
                if msg.get("In-Reply-To"):
                    date_tuple = email_lib.utils.parsedate_tz(msg.get("Date"))
                    if date_tuple:
                        email_date = datetime.fromtimestamp(
                            email_lib.utils.mktime_tz(date_tuple)
                        )
                        response_times.append(email_date)

                # Emails per day
                date_tuple = email_lib.utils.parsedate_tz(msg.get("Date"))
                if date_tuple:
                    email_date = datetime.fromtimestamp(
                        email_lib.utils.mktime_tz(date_tuple)
                    )
                    day = email_date.strftime("%Y-%m-%d")
                    if day in emails_per_day:
                        emails_per_day[day] += 1
                    else:
                        emails_per_day[day] = 1

            mail.logout()

            # Sort and format insights
            insights += f"Total Emails: {total_emails}\n\n"

            insights += f"Top Senders:\n"
            sorted_senders = sorted(senders.items(), key=lambda x: x[1], reverse=True)
            for sender, count in sorted_senders[:5]:
                insights += f"{sender}: {count} emails\n"

            insights += f"\nTop Keywords:\n"
            sorted_keywords = sorted(keywords.items(), key=lambda x: x[1], reverse=True)
            for keyword, count in sorted_keywords[:5]:
                insights += f"{keyword}: {count} occurrences\n"

            if response_times:
                average_response_time = sum(response_times, timedelta(0)) / len(
                    response_times
                )
                insights += f"\nAverage Response Time: {average_response_time}\n"

            insights += f"\nEmails Received Per Day:\n"
            sorted_emails_per_day = sorted(emails_per_day.items(), key=lambda x: x[0])
            for day, count in sorted_emails_per_day:
                insights += f"{day}: {count} emails\n"

        except Exception as e:
            log_unexpected_error(e)
            return f"Error generating insights: {e}"

        return insights


# Start the main application
root = ctk.CTk()
app = EmailCleanupApp(root)
root.mainloop()
