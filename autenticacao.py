import tkinter as tk
import tkinter.messagebox as tkmessagebox
import hashlib
from loguru import logger


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

        logger.add('app.log', format="{time} - {level} - {message}", level="DEBUG")

    def login(self):
        password = self.password_entry.get()
        if not password:
            logger.warning('Senha não informada')
            self.error_label.config(text="Por favor, informe a senha")
            return
        if self.authenticator.check_password(password):
            logger.info('Senha correta')
            self.error_label.config(text="")
            tkmessagebox.showinfo("Sucesso", "Senha correta")
        else:
            logger.warning('Senha incorreta')
            self.error_label.config(text="Senha incorreta")

    def new_password(self):
        password = self.new_password_entry.get()
        if not password:
            logger.warning('Nova senha não informada')
            self.error_label.config(text="Por favor, informe a nova senha")
            return
        if password == self.authenticator.password:
            logger.warning('A nova senha deve ser diferente da senha atual')
            self.error_label.config(text="A nova senha deve ser diferente da senha atual")
            return
        if len(password) < 8 or not any(char.isdigit() for char in password):
            logger.error('A nova senha deve ter pelo menos 8 caracteres e pelo menos um número')
            self.error_label.config(text="A nova senha deve ter pelo menos 8 caracteres e pelo menos um número")
            return
        self.authenticator.change_password(password)
        logger.info('Nova senha criada')
        self.error_label.config(text="Nova senha criada")
        tkmessagebox.showinfo("Sucesso", "Nova senha criada com sucesso")


if __name__ == "__main__":
    authenticator = Authenticator()
    root = tk.Tk()
    root.geometry("500x300")
    gui = GUI(root, authenticator)
    root.mainloop()
