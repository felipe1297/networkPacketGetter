import pyshark
import psutil
import os

#Function to clean the terminal
def cleanTerminal():
    os.system('cls' if os.name == 'nt' else 'clear')

#Delimiter for Menu
def delimiter():
    for i in range(80):
        print("*",end="")
    print()
    
#Main menu
def menuInterface():
    addrs = psutil.net_if_addrs()
    cleanTerminal()
    delimiter()
    print("Bienvenido este es un software que permite capturar las tramas")
    print("segun las interfaces presentes en su maquina: ")
    print("\nSu maquina dispone de ",end="")
    print(len(addrs),end=" ")
    print(" interfaces, las cuales son: ")
    lenInterfaces = int(len(addrs))
    li = list(addrs.keys())
    for i in range(0, lenInterfaces):
        print((i + 1),end=". ")
        print(li[i])
    print("\nEXIT -> Para salir")
    delimiter()

#View of the results after capturing packets from certain interface
def viewResults(listCap):
    op = ""
    if (len(listCap) > 0):
        while (op != "EXIT"):
            cleanTerminal()
            print("Se captaron ", end="")
            print(len(listCap), end=" ")
            print("paquetes.")
            print("Seleccione la opcion que desea visualizar: ")
            print("1. Ver todos los paquetes.")
            print("2. Ver determinado paquete.")
            print("Escribir \"EXIT\" si desea salir.")
            op = input("->")
            try:
                op = int(op)
                if (op == 1):
                    for k in range(0,len(listCap)):
                        print("\n\n============================================>>>> Package Nº ", end="")
                        print(k,end="\n\n")
                        print(listCap[k])
                    op2 = ""
                    print("\n\nEscribir \"EXIT\" para salir.")
                    while (op2 != "EXIT"):
                        op2 = input("->")
                elif (op == 2):
                    print("Nota: index comienzan desde 0")
                    index = input("Ingresar index del paquete: ")
                    try:
                        index = int(index)
                        print("\n\n|--------------------------------------------------------------------|\n")
                        print(listCap[index])
                        op2 = ""
                        print("\n\nEscribir \"EXIT\" para salir.")
                        while (op2 != "EXIT"):
                            op2 = input("->")
                    except:
                        print("",end="")
            except:
                print("",end="")
    else:
        cleanTerminal()
        print("No se captaron paquetes :,v")
        op2 = ""
        print("\n\nEscribir \"EXIT\" para salir.")
        while (op2 != "EXIT"):
            op2 = input("->")

#Main
if __name__ == "__main__":
    op = ""
    addrs = psutil.net_if_addrs()
    lis = list(addrs.keys())
    while(op != "EXIT"):
        menuInterface()
        op = input("\nSeleccionar la tarjeta a analizar (Si desea salir escriba \"EXIT\"):")
        try:
            op = int(op)
            if ((op > 0) & (op <= len(lis))):
                interfaceNetwork = lis[op - 1]
                cleanTerminal()
                print("La interfaz elegida es: ",end="")
                print(interfaceNetwork)
                timeOutCapture = input("Ingresar el tiempo en segundos, en el que desea capturar tramas: ")
                try:
                    timeOutCapture = int(timeOutCapture)
                    while (timeOutCapture <= 0):
                        timeOutCapture = input("Ingresar el tiempo en segundos, en el que desea capturar tramas: ")
                    capture = pyshark.LiveCapture(interface=interfaceNetwork)
                    capture.sniff(timeout=timeOutCapture)
                    viewResults(capture)
                except:
                    print("",end="")
        except:
            print("",end="")
