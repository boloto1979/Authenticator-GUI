
# Authenticator GUI
This is a graphical user interface (GUI) authentication program written in Python. It uses the tkinter module to create the interface and hashlib to encrypt the password. The program allows the user to login with a registered password or create a new password. Additionally, the program records logging information in an "app.log" file. The purpose of this program is to exemplify the use of the tkinter library to create simple graphical interfaces in Python.

The program has two classes:

## Authenticator

The `Authenticator` class is responsible for managing authentication and password change operations.

- `load_password`: loads the password stored in a text file called "password.txt"
- `save_password`: saves the new password in the file "senha.txt"
- `check_password`: checks that the password entered by the user is correct
- `change_password`: changes the password stored in the file "senha.txt" to the new password entered by the user

## GUI

The `GUI` class is responsible for creating and managing the program's graphical interface.

- `__init__`: initializes the graphical interface with the necessary widgets (Label, Entry and Button)
- `login`: checks if the password entered by the user is correct and displays error or success message
- `new_password`: checks if the new password entered by the user is valid and changes the password stored in the "senha.txt" file

The program also uses the logging module to record log information in an "app.log" file.

# How to run the program

To run the program, you need to have Python installed and the following packages:

- tkinter
- hashlib

After installing the necessary packages, just run the code in a terminal or Python IDE. When running the program, a login window will be displayed where the user must type the registered password or create a new password.
