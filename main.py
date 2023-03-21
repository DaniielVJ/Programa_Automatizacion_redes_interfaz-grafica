from tkinter import *
from netmiko import ConnectHandler
import sqlite3
from PIL import ImageTk, Image
from pathlib import Path
import os

# VARIABLES CON INFO DE LOS DISPOSITIVOS PARA LA APP
lista_de_ips = []


# FORMATO DE INFO DEL DISPOSITIVO
informacion_dispositivo = {
    "device_type": "cisco_ios",
    "host": "",
    "username": "",
    "password": ""
}

# LOGIN CONSULTA BASE DE DATOS
def login_users(username, password):
    output_marco.delete(1.0, END)
    conexion = sqlite3.connect(RUTA_BASE_DE_DATOS)
    cursor = conexion.cursor()
    cursor.execute("SELECT * FROM usuarios")
    credenciales = cursor.fetchall()
    for credencial in credenciales:
        if username == credencial[1] and password == credencial[2]:
           output_marco.config(fg="green1")
           output_marco.insert(END, f'Bienvenido {username}, se ha logueado correctamente.')
           archivo_entry.config(state=NORMAL)
           texto_entry_archivo.set('direcciones_ip.txt')
           boton_enviar_ips.config(state=NORMAL)
           entry_config.config(state=NORMAL)
           texto_entry_config.set('configuraciones.txt')
           boton_enviar_config.config(state=NORMAL)
           verificar_entry.config(state=NORMAL)
           boton_enviar_verificacion.config(state=NORMAL)
           save_config.config(state=NORMAL)
           boton_reset.config(state=NORMAL)
           username_entry.delete(0, END)
           password_entry.delete(0, END)
           global informacion_dispositivo
           informacion_dispositivo["username"] = username
           informacion_dispositivo["password"] = password
        else:
            output_marco.config(fg="red")
            if username == credencial[1]:
                output_marco.insert(END, f"contraseña incorrecta")
            else:
                output_marco.insert(END, f"Lo siento el usuario {username} no se encuentra en la base de datos")
            archivo_entry.config(state=DISABLED)
            texto_entry_archivo.set('DIRECCIONES IP')
            boton_enviar_ips.config(state=DISABLED)
            entry_config.config(state=DISABLED)
            texto_entry_config.set('CONFIG')
            boton_enviar_config.config(state=DISABLED)
            verificar_entry.config(state=DISABLED)
            boton_enviar_verificacion.config(state=DISABLED)
            save_config.config(state=DISABLED)
            boton_reset.config(state=DISABLED)
            username_entry.delete(0, END)
            password_entry.delete(0, END)
    conexion.close()

# COMPROBACIÓN ARCHIVO_IP Y DISPOSITIVOS ENCONTRADOS.
def ip_verification(archivo):
    lista_no_encontrados = []
    output_marco.delete(1.0, END)
    try:
        archivo_ips = open(RUTA_ARCHIVO_IPS / archivo, 'r')
        print(archivo_ips)
    except:
        print('ARCHIVO NO ENCONTRADO') # MENSAJE POR OUTPUT
        output_marco.config(fg="red")
        output_marco.insert(END, f'ARCHIVO {archivo} NO ENCONTRADO')
    else:
        print('ARCHIVO ENCONTRADO') # MENSAJE POR OUTPUT
        output_marco.delete(1.0, END)
        for ip in archivo_ips:
            ip = ip.replace("\n", "") # FORMATEAMOS IP.
            global lista_de_ips
            informacion_dispositivo["host"] = ip
            print(informacion_dispositivo)
            try:
                conexion_al_dispositivo = ConnectHandler(**informacion_dispositivo)
            except:
                print(f'Dispositvo {ip}, No encontrado !!!\n')
                lista_no_encontrados.append(ip)
            else:
                print(f'Dispositivo {ip}, Encontrado\n')
                lista_de_ips.append(ip)

    if len(lista_de_ips) != 0:
        for ip_encontrada in lista_de_ips:
            output_marco.config(fg="green1")
            output_marco.insert(END, f'Dispositivo {ip_encontrada}, Encontrado.\n')
    if len(lista_no_encontrados) != 0:       
        output_marco.insert(END, f"Las siguientes direcciones ip no fueron encontradas en la red: {lista_no_encontrados}")
    archivo_ips.close()


# FUNCION PARA ENVIAR CONFIGURACIÓN A LOS DISPOSITIVOS
def enviar_configuracion(configuraciones):
    output_marco.delete(1.0, END)
    lista_comandos = []
    try:
        archivo_config = open(RUTA_ARCHIVO_CONFIG / configuraciones, 'r')
    except:
        print('ARCHIVO NO ENCONTRADO') # MENSAJE POR OUTPUT
        output_marco.config(fg="red")
        output_marco.insert(END, "EL ARCHIVO DE CONFIGURACIÓN NO FUE ENCONTRADO")
    else:
        print('ARCHIVO ENCONTRADO') # MENSAJE POR OUTPUT
        
        if len(lista_de_ips) != 0: # Solo si hay dispositivos enviamos configuraciones
            print('Hay dispositivos')
            for comando in archivo_config:
                lista_comandos.append(comando)
            for ip in lista_de_ips:
                informacion_dispositivo["host"] = ip
                try:
                    conexion_al_dispositivo = ConnectHandler(**informacion_dispositivo)
                    output = conexion_al_dispositivo.send_config_set(lista_comandos)
                except:
                    print("No se pudo enviar la configuración.")
                else:
                    print(f'Se ha configurado el dispositivo {ip}: ')
                    output_marco.config(fg="green1")
                    output_marco.insert(END, f'Se ha configurado el dispositivo {ip}: \n')
                    output_marco.insert(END, output + "\n\n")
                    log = open(RUTA_ARCHIVO_LOGS, mode='a')
                    log.write(f"Dispositivo {ip}:\n{output}")
                    log.write("\n\n")
                    
        else:
            print('No hay dispositivos')
            output_marco.config(fg="red")
            output_marco.insert(END, "No ha y dispositivos para configurar\nPase archivo con direcciones ip para conectarse antes de configurarlos")
    archivo_config.close()
    log.close()


# BLOQUE PARA ENVIAR COMANDOS DE VERIFICACION    
def show_command(comando_show):
    output_marco.delete(1.0, END)
    verificar_entry.delete(0, END)
    if len(lista_de_ips) != 0:
        for ip in lista_de_ips:
            informacion_dispositivo["host"] = ip
            try:
                conexion_al_dispositivo = ConnectHandler(**informacion_dispositivo)
                output = conexion_al_dispositivo.send_command(comando_show)
            except:
                print('No pudimos enviar el comando de verificación')
                output_marco.config(fg="red")
                output_marco.insert(END, 'No pudimos enviar el comando de verificación')
            else:
                print(output)
                output_marco.config(fg="green1")
                output_marco.insert(END, f"Dispositivo {ip}: \n")
                output_marco.insert(END, output + "\n\n")
                log = open(RUTA_ARCHIVO_LOGS, mode='a')
                log.write(f"Dispositivo {ip}:\n{output}")
                log.write("\n\n")
    else:
        print("No se encontraron dispositivos")
        output_marco.config(fg="red")
        output_marco.insert(END, "No hay dispositivos para verificar\nPase archivo con direcciones ip para conectarse antes de configurarlos")
    log.close()
# INSTRUCCIONES CLICK BOTON SAVE
def save_config_funcion():
    output_marco.delete(1.0, END)
    if len(lista_de_ips) != 0:
        for ip in lista_de_ips:
            informacion_dispositivo["host"] = ip
            try:
                conexion_al_dispositivo = ConnectHandler(**informacion_dispositivo)
                output = conexion_al_dispositivo.save_config()
            except:
                print('No pudimos enviar el comando de verificación')
            else:
                print(output)
                output_marco.config(fg="green1")
                output_marco.insert(END, f"Dispositivo {ip}: \n")
                output_marco.insert(END, output + "\n\n")
                log = open(RUTA_ARCHIVO_LOGS, mode='a')
                log.write(f"Dispositivo {ip}:\n{output}")
                log.write("\n\n")
    else:
        print("No se encontraron dispositivos")
        output_marco.config(fg="red")
        output_marco.insert(END, "No hay dispositivos para guardar configuracion\nPase archivo con direcciones ip para conectarse antes de configurarlos")                 
    log.close()

def reset_ips():
    output_marco.delete(1.0, END)
    global lista_de_ips
    if len(lista_de_ips) != 0: 
        lista_de_ips = []
        print(lista_de_ips)
        output_marco.config(fg='green1')
        output_marco.insert(END, "LISTA DE DIRECCIONES IP RESETEADAS CORRECTAMENTE")
    else:
        output_marco.config(fg='green1')
        output_marco.insert(END, "LA LISTA DE DIRECCIONES IP YA ESTA VACIA")

# RUTAS
DIRECTORIO_PROYECTO = os.getcwd() # working directory
print(DIRECTORIO_PROYECTO)
RUTA_IMAGEN_LOGO = Path(DIRECTORIO_PROYECTO , "img", "logo_inacap.png")
RUTA_IMAGEN_ROUTER = Path(DIRECTORIO_PROYECTO , "img", "router.ico")
RUTA_IMAGEN_SWITCH = Path(DIRECTORIO_PROYECTO , "img", "Multilayer_switch.png")
RUTA_BASE_DE_DATOS = Path(DIRECTORIO_PROYECTO, "db", "users.db")
RUTA_ARCHIVO_IPS = Path(DIRECTORIO_PROYECTO, "documents")
RUTA_ARCHIVO_CONFIG = Path(DIRECTORIO_PROYECTO, "documents")
RUTA_ARCHIVO_LOGS = Path(DIRECTORIO_PROYECTO,"documents", "logs.txt")




'''# CREACION BASE DE DATOS
conexion = sqlite3.connect(RUTA_BASE_DE_DATOS)
cursor = conexion.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users_app(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username varchar(255),
    password varchar(255)
)
""")
conexion.commit()
conexion.close()'''


print(os.getcwd())

# Configuración ventana
app = Tk()
app.geometry("1045x630+0+0")
app.title("Network Automation Application")
app.config(bg="cyan3", )
app.resizable(False, False)
app.call("wm", "iconphoto", app._w, PhotoImage(file=RUTA_IMAGEN_LOGO))


# IMAGENES APP
image_router = Image.open(RUTA_IMAGEN_ROUTER, mode='r')
image_router = image_router.resize((130, 100))
img_router = ImageTk.PhotoImage(image_router)
image_switch = Image.open(RUTA_IMAGEN_SWITCH, mode='r')
image_switch = image_switch.resize((130,100))
img_switch = ImageTk.PhotoImage(image_switch)



# PANEL DEL TITULO DE LA APP.
panel_titulo = Frame(app, relief=FLAT, bd=3, bg="black", padx=40)
panel_titulo.pack(side=TOP)

texto_titulo = Label(panel_titulo,
                     fg="white",
                     font=("Purisa", 35, "bold"),
                     bg="black",
                     text="Network Automation APP",
                     )
texto_titulo.grid(row=0,
                  column=1)
color_fondo = Label(panel_titulo, bg="black", image=img_router)
color_fondo.grid(row=0,
                 column=0)
color_fondo_2 = Label(panel_titulo, bg="black", image=img_switch)
color_fondo_2.grid(row=0,
                 column=2)

# PANELES DE FUNCIONALIDADES

panel_izquierdo = Frame(app, relief=FLAT, bg='cyan4')
panel_izquierdo.pack(side=LEFT)
panel_derecho = Frame(app, relief=FLAT, bg='cyan4')
panel_derecho.pack(side=LEFT)

# PANEL LOGIN APP

panel_login = LabelFrame(panel_izquierdo, relief=FLAT, text="Login", font=("serif", 20, "bold"), labelanchor="n", bg="cyan4")
panel_login.pack(anchor='nw', pady=5)
username_texto = Label(panel_login, text="Username: ", font=("serif", 13, "bold"), bg="cyan4")
username_texto.grid(row=0, column=0, pady=10)
username_entry = Entry(panel_login, width=30 , font=("serif", 10, "bold"))
username_entry.focus()
username_entry.grid(row=0,column=1)
password_texto = Label(panel_login, text="Password: ", font=("serif", 13, "bold"), bg="cyan4")
password_texto.grid(row=1, column=0)
password_entry = Entry(panel_login, width=30, show='*', font=("serif", 10, "bold"))
password_entry.grid(row=1,column=1)
boton_login = Button(panel_login, text="Log In", font=("serif", 13, "bold"), command=lambda: login_users(username_entry.get(), password_entry.get()))
boton_login.grid(row=2, column=0, sticky=W + E, columnspan = 2)


# PANEL CARGAR ARCHIVO DE DIRECCIONES IP Y COMANDOS

# Variable con el texto en el cuadro de archivos
texto_entry_archivo = StringVar()
texto_entry_archivo.set("DIRECCIONES IP")
texto_entry_config = StringVar()
texto_entry_config.set("CONFIG")
texto_entry_verificar = StringVar()
texto_entry_verificar.set("VERIFICAR")



panel_ejecucion = LabelFrame(panel_izquierdo, relief=FLAT, bg="cyan4", text="Functionalities", font=("serif", 20, "bold"), labelanchor="n")
panel_ejecucion.pack(anchor='nw')
# Enviar archivo de ips.
archivo_texto = Label(panel_ejecucion, text="Archivo: ", font=("serif", 13, "bold"), bg="cyan4" , pady=2)
archivo_texto.grid(row=0, column=0)
archivo_entry = Entry(panel_ejecucion, state=DISABLED, width=22, font=("serif", 13, "bold" ), textvariable=texto_entry_archivo)
archivo_entry.grid(row=0, column=1, pady=2)
boton_enviar_ips = Button(panel_ejecucion, text="Enviar IPS", font=("serif", 13, "bold"), width=2, state=DISABLED, command=lambda: ip_verification(archivo_entry.get()))
boton_enviar_ips.grid(row=1, column=0, sticky=W + E, columnspan=2, pady=5)
# Enviar archivo de config.
archivo_config = Label(panel_ejecucion, text="Config: ", font=("serif", 13, "bold"), bg="cyan4" , pady=2)
archivo_config.grid(row=2, column=0)
entry_config = Entry(panel_ejecucion, state=DISABLED, width=22, font=("serif", 13, "bold" ), textvariable=texto_entry_config)
entry_config.grid(row=2, column=1)
boton_enviar_config = Button(panel_ejecucion, text="Enviar Config", font=("serif", 13, "bold"), width=2, state=DISABLED, command=lambda: enviar_configuracion(entry_config.get()))
boton_enviar_config.grid(row=3, column=0, sticky=W + E, columnspan=2, pady=5)


# ENVIAR COMANDO DE VERIFICACIÓN
texto_verificar = Label(panel_ejecucion, text="Verificar: ", font=("serif", 13, "bold"), bg="cyan4" , pady=10)
texto_verificar.grid(row=4, column=0)
verificar_entry = Entry(panel_ejecucion, state=DISABLED, width=22, font=("serif", 13, "bold" ), textvariable=texto_entry_verificar)
verificar_entry.grid(row=4, column=1, pady=10)
boton_enviar_verificacion = Button(panel_ejecucion, text="Enviar Verificacion", font=("serif", 13, "bold"), width=2, state=DISABLED, command=lambda: show_command(verificar_entry.get()))
boton_enviar_verificacion.grid(row=5, column=0, sticky=W + E, columnspan=2, pady=5)


# BOTON SAVE CONFIG
save_config = Button(panel_ejecucion, text="Save Config", font=("serif", 13, "bold"), width=13, state=DISABLED, bg='black', fg='white', command=save_config_funcion)
save_config.grid(row=6, column=0, sticky=W, columnspan=2, pady=5)

# BOTON DE RESET
boton_reset = Button(panel_ejecucion, text="Reset", font=("serif", 13, "bold"), width=13, state=DISABLED, bg='white', fg='black', command=reset_ips)
boton_reset.grid(row=6, column=1, sticky=E)

# PANEL DE OUTPUT DE LOS COMANDOS A LOS DISPOSITIVOS
panel_salida = LabelFrame(panel_derecho, relief=FLAT, bg="cyan4", text="OUTPUT", font=("serif", 20, "bold"), labelanchor="n")
panel_salida.pack(side=RIGHT)

output_marco = Text(panel_salida, relief=FLAT, width=89, height=25, state=NORMAL, bg="black", fg="green1", font=("monospace", 10), )
output_marco.grid(row=0, column=0)
#output_marco.insert(END, "Hola Mundo")



app.mainloop()