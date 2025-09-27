import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart'; //agregar a dependencias
import 'package:mongo_dart/mongo_dart.dart' as mongo;
import 'package:dotenv/dotenv.dart' as dotenv;
import 'package:bcrypt/bcrypt.dart';

//cargar variables
//final env = dotenv.DotEnv()..load(); // carga el archivo .env

//configuracion
final String port = Platform.environment['PORT'] ?? '8080';
final String jwtclave = Platform.environment['JWT_SECRET']!;
final String mongourl = Platform.environment['MONGO_URL']!;

//final String port = env['PORT'] ?? '8080';
//final String jwtclave = env['JWT_SECRET'] ?? '123456';
//final String mongourl = env['MONGO_URL'] ?? 'urlmongo';

late mongo.Db db;
late mongo.DbCollection collecioneventos;

//helpers
Map<String, dynamic> serializeDoc(Map<String, dynamic> doc) {
  final out = <String, dynamic>{};
  //_id -> id string
  if (doc.containsKey('_id')) {
    final idval = doc['_id'];
    if (idval is mongo.ObjectId) {
      out['id'] = idval.toHexString();
    } else {
      out['id'] = idval.toString();
    }
  }

  doc.forEach((k, v) {
    if (k == '_id') return;
    //convertir datetime a iso
    if (v is DateTime) {
      out[k] = v.toUtc().toIso8601String();
    } else {
      out[k] = v;
    }
  });
  return out;
}

//generar el token jwt
String generarToken(String userid) {
  final jwt = JWT({'id': userid});
  return jwt.sign(SecretKey(jwtclave), expiresIn: Duration(hours: 1));
}

//middleware jwt que anade user en request.context y permite rutas publicas
Middleware jwtintermedio() {
  return (Handler innerhandler) {
    return (Request req) async {
      //permitir rutas publicas
      if (req.url.path == 'login' || req.url.path.startsWith('public')) {
        return innerhandler(req);
      }

      final auth = req.headers['authorization'];
      if (auth == null || !auth.startsWith('Bearer ')) {
        return Response(
          401,
          body: jsonEncode({'error': 'token requerido'}),
          headers: {'Content-Type': 'application/json'},
        );
      }

      final token = auth.substring(7);
      try {
        final jwt = JWT.verify(token, SecretKey(jwtclave));
        final enriched = req.change(context: {'user': jwt.payload});
        return innerhandler(enriched);
      } catch (e) {
        return Response(
          401,
          body: jsonEncode({'error': 'token invalido'}),
          headers: {'Content-Type': 'application/json'},
        );
      }
    };
  };
}

// cors
Middleware corsHeaders() {
  return (innerHandler) {
    return (req) async {
      // Manejo de preflight (OPTIONS)
      if (req.method == 'OPTIONS') {
        return Response.ok(
          '',
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers':
                'Origin, Content-Type, Authorization',
          },
        );
      }

      final resp = await innerHandler(req);
      return resp.change(
        headers: {
          ...resp.headers,
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Origin, Content-Type, Authorization',
        },
      );
    };
  };
}

//area de guardar usuario
Future<Response> registrausuario(Request req) async {
  try {
    final body = await req.readAsString();
    final data = jsonDecode(body);

    final usuario = data['usuario'];
    final password = data['password'];

    if (usuario == null || password == null) {
      return Response(
        400,
        body: jsonEncode({'error': 'usuario y contraseña requeridos'}),
        headers: {'Content-type': 'application/json'},
      );
    }

    final collecionuser = db.collection('usuarios');

    //verificar si el usuario existe
    final existeuser = await collecionuser.findOne({'usuario': usuario});
    if (existeuser != null) {
      return Response(
        409,
        body: jsonEncode({'error': 'el usuario ya existe'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    final passencript = BCrypt.hashpw(password, BCrypt.gensalt());

    //insertar user en colecion usuarios
    await collecionuser.insertOne({
      'usuario': usuario,
      'password': passencript,
    });

    //respuesta 200 si todo sale bien
    return Response.ok(
      jsonEncode({'mensaje': 'usuario registrado correctamente'}),
      headers: {'Content-type': 'application/json'},
    );
  } catch (e) {
    return Response(
      400,
      body: jsonEncode({'error': 'json invalido'}),
      headers: {'Content-Type': 'application/json'},
    );
  }
}

//handlers - validar usuario para login
Future<Response> loginhandler(Request req) async {
  try {
    final body = await req.readAsString();

    print('json: $body ');

    final data = jsonDecode(body);

    final usuario = data['usuario'];
    final password = data['password'];

    if (usuario == null || password == null) {
      return Response(
        400,
        body: jsonEncode({'error': 'usuario y password requeridos'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    final collecionuser = db.collection('usuarios');
    final user = await collecionuser.findOne({'usuario': usuario});

    if (user == null || !BCrypt.checkpw(password, user['password'])) {
      return Response(
        401,
        body: jsonEncode({'error': 'credenciales invalidas'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    final token = generarToken(user['usuario']);

    return Response.ok(
      jsonEncode({'token': token}),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e) {
    return Response(
      400,
      body: jsonEncode({'error': 'json invalido'}),
      headers: {'Content-Type': 'application/json'},
    );
  }
}

//crus api
Future<Response> getEventos(Request req) async {
  try {
    final list = await collecioneventos.find().toList();
    final out = list
        .map((d) => serializeDoc(Map<String, dynamic>.from(d)))
        .toList();
    return Response.ok(
      jsonEncode(out),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'error interno'}),
      headers: {'Content-Type': 'application/json'},
    );
  }
}

Future<Response> crearevento(Request req) async {
  try {
    final body = await req.readAsString();
    final data = jsonDecode(body);
    if (data['tipo'] == null) {
      return Response(
        400,
        body: jsonEncode({'error': 'titulo requerido'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    final evento = {
      'tipo': data['tipo'],
      'fecha': data['fecha'] ?? DateTime.now().toUtc().toIso8601String(),
      'descripcion': data['descripcion'] ?? '',
    };

    final res = await collecioneventos.insertOne(evento);
    //obtener id creado
    final createdid = (res.id is mongo.ObjectId)
        ? (res.id as mongo.ObjectId).toHexString()
        : res.id?.toString();
    return Response(
      201,
      body: jsonEncode({'msg': 'evento creado', 'id': createdid}),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'no se pudo crear el evento'}),
      headers: {'Content-Type': 'application/json'},
    );
  }
}

Future<Response> actualizarevento(Request req, String id) async {
  try {
    final body = await req.readAsString();
    final data = jsonDecode(body);
    final objectid = mongo.ObjectId.fromHexString(id);

    if (body.isEmpty) {
      return Response(
        400,
        body: jsonEncode({"error": "El body no puede estar vacío"}),
        headers: {"Content-Type": "application/json"},
      );
    }

    final result = await collecioneventos.updateOne(
      mongo.where.id(objectid),
      mongo.modify
          .set('tipo', data['tipo'])
          .set('fecha', data['fecha'])
          .set('descripcion', data['descripcion']),
    );

    return Response.ok(
      jsonEncode({'msg': 'evento actualizado'}),
      headers: {'Content-Type': 'application/json'},
    );
  } on FormatException {
    return Response(
      400,
      body: jsonEncode({'error': 'id invalido'}),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'no se pudo actualizar'}),
      headers: {'Content-Type': 'application/json'},
    );
  }
}

Future<Response> eliminarevento(Request req, String id) async {
  try {
    final objectid = mongo.ObjectId.fromHexString(id);
    final result = await collecioneventos.deleteOne(mongo.where.id(objectid));
    return Response.ok(
      jsonEncode({'msj': 'evento eliminado'}),
      headers: {'Content-Type': 'application/json'},
    );
  } on FormatException {
    return Response(
      400,
      body: jsonEncode({'error': 'id invalido'}),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'no se pudo eliminar'}),
      headers: {'Content-Type': 'application/json'},
    );
  }
}

//main
Future<void> main() async {
  //abrir bbdd
  print(mongourl);
  db = await mongo.Db.create(mongourl);
  await db.open();
  collecioneventos = db.collection('eventos');
  print('conetado a mongo - collecion eventos');

  //rutas
  final publicRouter = Router()
    ..post('/login', loginhandler)
    ..post('/registrar', registrausuario);

  final apirouter = Router()
    ..get('/eventos', getEventos)
    ..post('/eventos', crearevento)
    ..put('/eventos/<id>', actualizarevento)
    ..delete('/eventos/<id>', eliminarevento);

  //montar api protegida en /api
  final root = Router()
    ..mount(
      '/api/',
      Pipeline().addMiddleware(jwtintermedio()).addHandler(apirouter.call),
    );

  //agregar rutas publicas al root
  root.mount('/', publicRouter.call);

  final handle = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(corsHeaders())
      .addHandler(root.call);

  //cerrar conexion a mongo
  ProcessSignal.sigint.watch().listen((_) async {
    print('cerrando conexion a db');
    await db.close();
    exit(0);
  });

  final server = await serve(handle, InternetAddress.anyIPv4, int.parse(port));
  print('servidor corriendo en http://${server.address.host}:${server.port}');
}
