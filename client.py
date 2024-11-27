import socket
import ssl
import threading
from tkinter import Tk, Text, Entry, Button, Label, END, Listbox, Toplevel, messagebox
from cryptography.fernet import Fernet

KEY = b'...'  # Той самий ключ, що на сервері
cipher = Fernet(KEY)

class MessengerClient:
    def __init__(self, host, port):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client = ssl.wrap_socket(self.client)  # Підключення через TLS
        self.client.connect((host, port))
        self.username = None
        self.current_group = None

        # GUI компоненти
        self.root = Tk()
        self.root.title("Messenger")
        
        # Вікно повідомлень
        self.chat_box = Text(self.root, state='disabled', width=50, height=20)
        self.chat_box.pack()

        # Поле введення повідомлень
        self.input_box = Entry(self.root, width=50)
        self.input_box.pack()

        # Кнопка відправлення
        self.send_button = Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack()

        # Вибір груп
        self.group_label = Label(self.root, text="Choose a group:")
        self.group_label.pack()

        self.group_list = Listbox(self.root, height=5)
        self.group_list.pack()
        self.group_list.bind("<<ListboxSelect>>", self.change_group)

        # Кнопка реєстрації
        self.register_button = Button(self.root, text="Register", command=self.register_user)
        self.register_button.pack()

        # Кнопка авторизації
        self.auth_button = Button(self.root, text="Login", command=self.authenticate_user)
        self.auth_button.pack()

    def register_user(self):
        registration_window = Toplevel(self.root)
        registration_window.title("Register")
        Label(registration_window, text="Enter username:").pack()
        username_entry = Entry(registration_window, width=30)
        username_entry.pack()
        Label(registration_window, text="Enter password:").pack()
        password_entry = Entry(registration_window, width=30, show="*")
        password_entry.pack()
        Button(
            registration_window,
            text="Register",
            command=lambda: self.submit_registration(username_entry, password_entry, registration_window),
        ).pack()

    def submit_registration(self, username_entry, password_entry, window):
        username = username_entry.get()
        password = password_entry.get()
        self.client.send(cipher.encrypt(f"REGISTER|{username}|{password}".encode("utf-8")))
        response = cipher.decrypt(self.client.recv(1024)).decode("utf-8")
        if response == "OK":
            messagebox.showinfo("Success", "Registration successful!")
        else:
            messagebox.showerror("Error", "Registration failed!")
        window.destroy()

    def authenticate_user(self):
        auth_window = Toplevel(self.root)
        auth_window.title("Login")
        Label(auth_window, text="Enter username:").pack()
        username_entry = Entry(auth_window, width=30)
        username_entry.pack()
        Label(auth_window, text="Enter password:").pack()
        password_entry = Entry(auth_window, width=30, show="*")
        password_entry.pack()
        Button(
            auth_window,
            text="Login",
            command=lambda: self.submit_auth(username_entry, password_entry, auth_window),
        ).pack()

    def submit_auth(self, username_entry, password_entry, window):
        username = username_entry.get()
        password = password_entry.get()
        self.client.send(cipher.encrypt(f"AUTH|{username}|{password}".encode("utf-8")))
        response = cipher.decrypt(self.client.recv(1024)).decode("utf-8")
        if response == "Welcome!":
            self.username = username
            self.populate_groups()
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Login failed!")
        window.destroy()

    def populate_groups(self):
        self.group_list.delete(0, END)
        self.client.send(cipher.encrypt("LIST_GROUPS".encode("utf-8")))
        groups = cipher.decrypt(self.client.recv(1024)).decode("utf-8").split("|")
        for group in groups:
            self.group_list.insert(END, group)

    def change_group(self, event):
        selected_group = self.group_list.get(self.group_list.curselection())
        self.current_group = selected_group
        self.chat_box.config(state='normal')
        self.chat_box.insert(END, f"Switched to group: {selected_group}\n")
        self.chat_box.config(state='disabled')

    def send_message(self):
        if not self.username or not self.current_group:
            messagebox.showerror("Error", "You must log in and select a group!")
            return
        message = self.input_box.get()
        if message:
            self.client.send(cipher.encrypt(f"{self.current_group}|{message}".encode("utf-8")))
            self.input_box.delete(0, END)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client.recv(1024)
                message = cipher.decrypt(encrypted_message).decode("utf-8")
                self.chat_box.config(state="normal")
                self.chat_box.insert(END, f"{message}\n")
                self.chat_box.config(state="disabled")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def run(self):
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.root.mainloop()

if __name__ == "__main__":
    client = MessengerClient("127.0.0.1", 12345)
    client.run()
