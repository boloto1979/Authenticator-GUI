import tkinter as tk
import tkinter.messagebox as tkmessagebox
import hashlib
import logging

class Authenticator:
    def __init__(self):
        self.password = self.load_password()
        
    def load_password(self):
        try:
            with open("senha.txt", "r") as f:
                return f.readline().strip()
        except FileNotFoundError:
            return ""

    def save_password(self, password):
        with open("senha.txt", "w") as f:
            f.write(password)

    def check_password(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest() == self.password

    def change_password(self, password):
        self.password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.save_password(self.password)

class GUI:
    def __init__(self, root, authenticator):
        self.root = root
        self.authenticator = authenticator
        
        self.label = tk.Label(root, text="Digite a senha:")
        self.password_entry = tk.Entry(root, show="*")
        self.login_button = tk.Button(root, text="Login", command=self.login)
        self.new_password_label = tk.Label(root, text="Nova senha:")
        self.new_password_entry = tk.Entry(root, show="*")
        self.new_password_button = tk.Button(root, text="Criar nova senha", command=self.new_password)
        self.error_label = tk.Label(root, text="", fg="red")
        
        self.label.pack()
        self.password_entry.pack()
        self.login_button.pack()
        self.new_password_label.pack()
        self.new_password_entry.pack()
        self.new_password_button.pack()
        self.error_label.pack()

        logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    def login(self):
        if self.authenticator.check_password(self.password_entry.get()):
            logging.info('Senha correta')
            self.error_label.config(text="")
            tkmessagebox.showinfo("Sucesso", "Senha correta")
        else:
            logging.warning('Senha incorreta')
            self.error_label.config(text="Senha incorreta")

    def new_password(self):
        password = self.new_password_entry.get()
        if len(password) < 8 or not any(char.isdigit() for char in password):
            logging.error('A senha deve ter pelo menos 8 caracteres e pelo menos um número')
            self.error_label.config(text="A senha deve ter pelo menos 8 caracteres e pelo menos um número")
        else:
            self.authenticator.change_password(password)
            logging.info('Nova senha criada')
            self.error_label.config(text="Nova senha criada")
            tkmessagebox.showinfo("Sucesso", "Nova senha criada com sucesso")

if __name__ == "__main__":
    authenticator = Authenticator()
    root = tk.Tk()
    root.geometry("500x300")
    gui = GUI(root, authenticator)
    root.mainloop()
