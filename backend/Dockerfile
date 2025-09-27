

# 1) etapa de build: compilar el ejecutable con Dart
FROM dart:stable AS build

#difinir el directorio de trabajo en docker
WORKDIR /app

# copiar todo el proyecto al contenedor inicio y destino
COPY . .

# descargar dependencias
RUN dart pub get

# compilar el servidor Dart a un binario nativo
RUN dart compile exe bin/server.dart -o bin/server

#cambiar los permisos del archivo para que sea ejecutable
#cambiar permisos de archivos - añadir permiso de ejecución - archivo al que le estás dando permisos de ejecución.
RUN chmod +x bin/server 

# 2) etapa de runtime: imagen mínima que contiene sólo runtime + binario
FROM dart:stable

#difinir el directorio de trabajo en docker
WORKDIR /app

# copiar el runtime de Dart desde la etapa build al contenedor final
#COPY --from=build /runtime/ /

# copiar el binario compilado al directorio /app/bin/ del contenedor final
COPY --from=build /app/bin/server /app/bin/

# Exponer el puerto que usará Cloud Run (no es obligatorio, pero es informativo)
EXPOSE 8080

# comando que se ejecutará al iniciar el contenedor
CMD ["/app/bin/server"]

