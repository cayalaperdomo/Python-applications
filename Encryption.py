import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# Generar una clave y guardarla en un archivo
def generar_clave():
    clave = Fernet.generate_key()
    with open("clave.key", "wb") as clave_archivo:
        clave_archivo.write(clave)

# Cargar la clave desde el archivo
def cargar_clave():
    return open("clave.key", "rb").read()

# Cifrar un archivo
def cifrar_archivo(nombre_archivo):
    if not os.path.exists("clave.key"):
        generar_clave()
    clave = cargar_clave()
    f = Fernet(clave)
    
    with open(nombre_archivo, "rb") as archivo:
        datos_archivo = archivo.read()
    
    datos_cifrados = f.encrypt(datos_archivo)
    
    with open(nombre_archivo, "wb") as archivo:
        archivo.write(datos_cifrados)

# Descifrar un archivo
def descifrar_archivo(nombre_archivo):
    if not os.path.exists("clave.key"):
        messagebox.showerror("Error", "El archivo de clave no existe. Cifra un archivo primero para generar la clave.")
        return
    clave = cargar_clave()
    f = Fernet(clave)
    
    with open(nombre_archivo, "rb") as archivo:
        datos_cifrados = archivo.read()
    
    datos_descifrados = f.decrypt(datos_cifrados)
    
    with open(nombre_archivo, "wb") as archivo:
        archivo.write(datos_descifrados)

# Funciones para la GUI
def seleccionar_archivo():
    archivo = filedialog.askopenfilename()
    if archivo:
        archivo_entry.delete(0, tk.END)
        archivo_entry.insert(0, archivo)

def cifrar():
    archivo = archivo_entry.get()
    if not archivo:
        messagebox.showwarning("Advertencia", "Selecciona un archivo para cifrar.")
        return

    try:
        cifrar_archivo(archivo)
        messagebox.showinfo("Éxito", f"El archivo {archivo} ha sido cifrado.")
    except Exception as e:
        messagebox.showerror("Error", f"Ha ocurrido un error: {str(e)}")

def descifrar():
    archivo = archivo_entry.get()
    if not archivo:
        messagebox.showwarning("Advertencia", "Selecciona un archivo para descifrar.")
        return

    try:
        descifrar_archivo(archivo)
        messagebox.showinfo("Éxito", f"El archivo {archivo} ha sido descifrado.")
    except Exception as e:
        messagebox.showerror("Error", f"Ha ocurrido un error: {str(e)}")

def salir():
    root.destroy()

# Crear la ventana principal
root = tk.Tk()
root.title("Cifrado y Descifrado de Archivos")

# Crear widgets de la GUI
archivo_label = tk.Label(root, text="Archivo:")
archivo_label.grid(row=0, column=0, padx=10, pady=10)

archivo_entry = tk.Entry(root, width=50)
archivo_entry.grid(row=0, column=1, padx=10, pady=10)

seleccionar_btn = tk.Button(root, text="Seleccionar", command=seleccionar_archivo)
seleccionar_btn.grid(row=0, column=2, padx=10, pady=10)

cifrar_btn = tk.Button(root, text="Cifrar", command=cifrar)
cifrar_btn.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

descifrar_btn = tk.Button(root, text="Descifrar", command=descifrar)
descifrar_btn.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

# Botón para salir de la aplicación
salir_btn = tk.Button(root, text="Salir", command=salir)
salir_btn.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

# Iniciar el bucle principal de la GUI
root.mainloop()
