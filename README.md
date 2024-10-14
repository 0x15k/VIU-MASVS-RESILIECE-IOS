# iOS Resilience Testing Framework

Este proyecto que utiliza MASTG y OWASP_MAS_Checklist para realizar pruebas de resiliencia en aplicaciones iOS de MASVS, incluyendo análisis estático y dinámico. Utiliza Flask para la interfaz web y Frida para la inyección de scripts en dispositivos iOS.

## Requisitos

- Flask==2.0.1
- werkzeug==2.0.1
- r2pipe==1.6.1
- frida==15.1.17
  
- Colocar en el PATH de sistema:
  - VIU-MASVS-RESILIECE-IOS\tools\
  - VIU-MASVS-RESILIECE-IOS\tools\radare2\bin

## Instalación
1. Clona el repositorio:
    ```bash
    git clone https://github.com/0x15k/VIU-MASVS-RESILIECE-IOS.git
    cd VIU-MASVS-RESILIECE-IOS
    python app.py
    ```
