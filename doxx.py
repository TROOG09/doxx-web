# Proyecto creado por THC
# GitHub: https://github.com/tu-usuario
# Licencia: MIT

# ASCII Art - Thesixclown
# Creado por: thesixclown team / lapsus group / creator : 333g

"""
▄▄▄▄▄▄▄▄▄ ▄▄                                ▄▄                     
▀▀▀███▀▀▀ ██                ▀▀              ██                     
   ███    ████▄ ▄█▀█▄ ▄█▀▀▀ ██  ██ ██ ▄████ ██ ▄███▄ ██   ██ ████▄ 
   ███    ██ ██ ██▄█▀ ▀███▄ ██   ███  ██    ██ ██ ██ ██ █ ██ ██ ██ 
   ███    ██ ██ ▀█▄▄▄ ▄▄▄█▀ ██▄ ██ ██ ▀████ ██ ▀███▀  ██▀██  ██ ██ 
"""

import socket
import dns.resolver
import whois
import requests
import nmap
import json
import pyasn
import re

def obtener_datos_dns(dominio):
    print(f"Consultando DNS para {dominio}...")
    try:
        resultado = {}

        # Registros A (direcciones IP)
        respuestas = dns.resolver.resolve(dominio, 'A')
        resultado['A'] = [str(rdata) for rdata in respuestas]

        # Registros MX (servidores de correo)
        try:
            respuestas = dns.resolver.resolve(dominio, 'MX')
            resultado['MX'] = [str(rdata.exchange) for rdata in respuestas]
        except dns.resolver.NoAnswer:
            resultado['MX'] = None

        # Registros TXT (contiene registros SPF, DKIM, etc.)
        try:
            respuestas = dns.resolver.resolve(dominio, 'TXT')
            resultado['TXT'] = [str(rdata) for rdata in respuestas]
        except dns.resolver.NoAnswer:
            resultado['TXT'] = None

        return resultado
    except Exception as e:
        print(f"Error al obtener datos DNS: {e}")
        return None

def obtener_geolocalizacion(ip):
    print(f"Obteniendo geolocalización para la IP {ip}...")
    url = f"http://ip-api.com/json/{ip}?fields=country,city,zip,region"
    respuesta = requests.get(url)
    data = respuesta.json()

    if data['status'] == 'fail':
        return None
    return data

def obtener_tracking_root(ip):
    print(f"Consultando ASN y tracking root para {ip}...")
    try:
        # Usamos pyasn para obtener datos de ASN
        asn_db = pyasn.pyasn('asn.txt')  # Base de datos ASN
        asn, prefix, cc = asn_db.lookup(ip)
        return asn, prefix, cc
    except Exception as e:
        print(f"Error al obtener ASN: {e}")
        return None, None, None

def escanear_puertos(ip):
    print(f"Escaneando puertos en {ip}...")
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')  # Escaneo de puertos del 1 al 1024
    puertos_abiertos = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                puertos_abiertos.append(port)

    return puertos_abiertos

def obtener_info_whois(dominio):
    print(f"Consultando WHOIS para {dominio}...")
    try:
        w = whois.whois(dominio)
        return w
    except Exception as e:
        print(f"Error al obtener datos WHOIS: {e}")
        return None

def obtener_ip(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        return ip
    except socket.gaierror:
        return None

def extraer_correos_whois(whois_data):
    # Buscar correos en los datos WHOIS (sólo si están disponibles)
    correos = []
    if whois_data:
        for key, value in whois_data.items():
            if isinstance(value, str) and re.match(r"[^@]+@[^@]+\.[^@]+", value):
                correos.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and re.match(r"[^@]+@[^@]+\.[^@]+", item):
                        correos.append(item)
    return correos

def obtener_info_completa(dominio):
    ip = obtener_ip(dominio)
    if ip:
        print(f"La IP de {dominio} es {ip}")
    else:
        print("No se pudo obtener la IP.")
        return

    # Obtener datos DNS
    datos_dns = obtener_datos_dns(dominio)
    if datos_dns:
        print(f"Datos DNS de {dominio}: {json.dumps(datos_dns, indent=4)}")

    # Obtener información WHOIS
    info_whois = obtener_info_whois(dominio)
    if info_whois:
        print(f"Información WHOIS para {dominio}: {info_whois}")
        correos = extraer_correos_whois(info_whois)
        if correos:
            print(f"Correos electrónicos encontrados en WHOIS: {correos}")

    # Geolocalización de la IP
    geolocalizacion = obtener_geolocalizacion(ip)
    if geolocalizacion:
        print(f"Geolocalización de la IP: {geolocalizacion}")

    # Tracking Root (ASN, prefix, country)
    asn, prefix, cc = obtener_tracking_root(ip)
    if asn:
        print(f"ASN de la IP: {asn}, Prefijo: {prefix}, País: {cc}")

    # Escaneo de puertos
    puertos_abiertos = escanear_puertos(ip)
    if puertos_abiertos:
        print(f"Puertos abiertos en {ip}: {puertos_abiertos}")
    else:
        print(f"No se encontraron puertos abiertos en {ip}.")

def main():
    dominio = input("Introduce el dominio para obtener información: ")
    obtener_info_completa(dominio)

if __name__ == "__main__":
    main()
