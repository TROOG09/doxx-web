# Doxx-Web - Información sobre Dominios

Este repositorio contiene un script en Python que recopila información detallada sobre un dominio específico. El script puede obtener lo siguiente:

1. **Datos DNS**: Registros A, MX y TXT del dominio.
2. **Geolocalización**: Información de ubicación basada en la IP del dominio.
3. **Tracking Root y ASN**: Detalles sobre el número ASN, prefijo y país de la IP.
4. **Correos electrónicos**: Extrae correos electrónicos (si están disponibles) desde los datos WHOIS del dominio.
5. **Escaneo de Puertos**: Realiza un escaneo de puertos básicos en la IP del dominio.

## Proyecto creado por THC

- **GitHub**: [https://github.com/TROOG09/doxx-web](https://github.com/TROOG09/doxx-web)
- **Licencia**: MIT

## ASCII Art - Thesixclown

- **thesixclown team**
- **lapsus group**
- **creator : 333g**

## Requisitos

1. **Python 3.x**: Asegúrate de tener Python instalado en tu sistema. Si no lo tienes, puedes descargarlo desde [python.org](https://www.python.org/).
   
2. **Librerías necesarias**: El script necesita algunas librerías de Python. Puedes instalarlas con `pip`:

   ```bash
   pip install dnspython requests nmap whois pyasn

   termux : pkg update && pkg upgrade  pkg install python
pkg install nmap
pkg install python3-pip
pip install dnspython requests nmap whois pyasn 
git clone https://github.com/TROOG09/doxx-web.git 
cd doxx-web
python script.py

kali: sudo apt update && sudo apt upgrade 
sudo apt install python3 python3-pip nmap whois
pip3 install dnspython requests pyasn 
git clone https://github.com/TROOG09/doxx-web.git
cd doxx-web
python3 script.py

ejemplo: Introduce el dominio para obtener información: example.com 

## Advertencia

**thesixclown team** y **lapsus group** no se hacen responsables del uso que se le dé a esta herramienta. El script proporcionado está destinado exclusivamente para fines educativos y de pruebas de seguridad en redes y sistemas que te pertenezcan o para los cuales tengas autorización explícita. El uso de esta herramienta en sistemas o redes sin el consentimiento del propietario puede ser ilegal y violar leyes locales o internacionales.

**El uso inapropiado de esta herramienta puede resultar en consecuencias legales.**

Al utilizar esta herramienta, el usuario asume toda la responsabilidad y las consecuencias derivadas de su uso. Se recomienda encarecidamente utilizar esta herramienta de manera ética y legal.

**No se tolera el uso de este script para realizar actividades maliciosas, ilegales o no autorizadas.**
