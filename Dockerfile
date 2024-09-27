# Usa una imagen base de Python
FROM python:3.9-slim

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Copia los archivos de tu proyecto al contenedor
COPY . /app

# Instala las dependencias necesarias y frida-tools
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install frida-tools

# Instala radare2
RUN apt-get update && apt-get install -y \
    radare2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Expone el puerto en el que la aplicación correrá
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]