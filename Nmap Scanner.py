import tkinter as tk
from tkinter import messagebox
import nmap
import json
import time

# Function to scan for open ports
def scan_ports():
    ip_address = entry_ip.get()
    if not ip_address:
        messagebox.showerror("Error", "Por favor, ingresa una dirección IP para escanear.")
        return

    try:
        # Crear una ventana secundaria para mostrar el mensaje
        progress_window = tk.Toplevel(root)
        progress_window.title("Escaneo en Proceso")
        
        # Etiqueta en la ventana secundaria
        progress_label = tk.Label(progress_window, text="Escaneando los puertos, por favor espera...")
        progress_label.pack(pady=20)

        root.update_idletasks()  # Actualiza la interfaz mientras se procesa el escaneo

        nm = nmap.PortScanner()
        text_output.delete(1.0, tk.END)  # Limpiar resultados previos
        text_output.insert(tk.END, f"Escaneando {ip_address}...\n")
        
        time.sleep(1)  # Simula retraso para efectos visuales (opcional)
        nm.scan(hosts=ip_address, arguments='-sV')
        
        results = {"host": ip_address, "ports": []}
        
        for host in nm.all_hosts():
            text_output.insert(tk.END, f"Host: {host}\n")
            for protocol in nm[host].all_protocols():
                text_output.insert(tk.END, f"Protocolo: {protocol}\n")
                ports = nm[host][protocol].keys()
                for port in ports:
                    state = nm[host][protocol][port]["state"]
                    text_output.insert(tk.END, f" - Puerto: {port} | Estado: {state}\n")
                    results["ports"].append({"port": port, "state": state})

        # Guardar resultados en un archivo JSON
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=2)
        text_output.insert(tk.END, "\nResultados guardados en 'scan_results.json'.\n")

    except Exception as e:
        text_output.insert(tk.END, f"Error al escanear: {str(e)}\n")
    finally:
        progress_window.destroy()  # Cerrar la ventana secundaria al finalizar el escaneo

# Function to exit the application
def salir():
    root.destroy()

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("Escaneo de Puertos")

# Frame para la entrada de IP
frame = tk.Frame(root)
frame.pack(pady=10)

label_ip = tk.Label(frame, text="Dirección IP:")
label_ip.grid(row=0, column=0, padx=5, pady=5)

entry_ip = tk.Entry(frame, width=30)
entry_ip.grid(row=0, column=1, padx=5, pady=5)

# Botón de escaneo
boton_escanear = tk.Button(frame, text="Escanear Puertos", command=scan_ports)
boton_escanear.grid(row=1, column=0, padx=5, pady=10)

# Botón de salir
boton_salir = tk.Button(frame, text="Salir", command=salir)
boton_salir.grid(row=1, column=1, padx=5, pady=10)

# Área de resultados
text_output = tk.Text(root, height=15, width=70)
text_output.pack(pady=10)

root.mainloop()
