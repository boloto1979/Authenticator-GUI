import os
import tkinter as tk
import hashlib
from autenticacao import hash_password, check_password, reset_password, new_password

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password():
    file_path = os.path.abspath("senha.txt")
    with open(file_path, "r") as f:
        hashed_password = f.readline().strip()
    if hash_password(entry.get()) == hashed_password:
        label["text"] = "Senha correta!"
    else:
        label["text"] = "Senha incorreta. Tente novamente."
        entry.delete(0, tk.END)

def reset_password():
    file_path = os.path.abspath("senha.txt")
    with open(file_path, "w") as f:
        f.write(hash_password("nova_senha"))
    label["text"] = "Senha redefinida para 'nova_senha'."

def new_password():
    new_pass = new_password_entry.get()
    file_path = os.path.abspath("senha.txt")
    with open(file_path, "w") as f:
        f.write(hash_password(new_pass))
    new_password_entry.delete(0, tk.END)
    label["text"] = "Senha alterada para '{}'".format(new_pass)

root = tk.Tk()
root.geometry("300x200")

label = tk.Label(root, text="Digite a senha:")
label.pack()

entry = tk.Entry(root, show="*")
entry.pack()

button = tk.Button(root, text="Verificar", command=check_password)
button.pack()

reset_button = tk.Button(root, text="Redefinir senha", command=reset_password)
reset_button.pack()

new_password_label = tk.Label(root, text="Digite a nova senha:")
new_password_label.pack()

new_password_entry = tk.Entry(root, show="*")
new_password_entry.pack()

new_password_button = tk.Button(root, text="Nova senha", command=new_password)
new_password_button.pack()

root.mainloop()
