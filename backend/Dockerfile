

#usar la imagen estable de dart
from dart:stable as build

#definir el directorio de trabajo dentro de la app
workdir /app

#copiar todos los archivos del directorio local al docker
copy..

#descargar las dependencias que estan en el archivo pubspec.yaml
run dar put get

#compilar el servidor dar a un binario ejecutable
run dart compile exe bin/server.dart -o bin/server


#segunda parte creacion de una imagen vacia
from scratch

#copiar desde la etapa build la carpeta /runtime/ que trae el runtime de dart compilado
copy --from=build /runtime/

#copiar el compilado server al directorio de trabajo de docker
copy --from=build /app/bin/server /app/bin/

#exponer el puerto para que cluod run pueda conectarse
expose 8080

#comando que se ejcutara cuando arranque el contenedor
cmd["/app/bin/server"]


