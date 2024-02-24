import Sys.println;
import Std.parseInt;
import js.lib.Error;
import js.node.*;
import js.node.ChildProcess.ChildProcessSpawnSyncResult;
import js.node.http.*;

#if (haxe >= version("4.0.0"))
import js.lib.Promise;
#else
import js.Promise;
#end

typedef Params = {
  repo : String,
  timeout : String,
  auth : {authorization: String, basic: String, user: String, password: String},
  service : String,
  isInfoRequest : Bool,
  remote : String,
  local : String,
  infos : String
}

class Main {
  static function safeUser(basic:String)
  {
    var basic = basic.split(":");
    if (basic.length != 2)
      throw "ERR: invalid Basic HTTP authentication";
    var user = basic[0];
    var pwd = basic[1];
    if ((user == pwd || pwd == "" || ~/oauth/.match(pwd)) && user.length > 5)
      user = user.substr(0, 5) + "...";
    return user;
  }

  static function parseAuth(s:String)
  {
    if (s == null)
      return null;
    var parts = s.split(" ");
    if (parts[0] != "Basic")
      throw "ERR: HTTP authentication schemes other than Basic not supported";
    var basic = haxe.crypto.Base64.decode(parts[1]).toString();
    var basicSplit = basic.split(":");
    return {
      authorization: s,
      basic: basic,
      user: basicSplit[0],
      password: basicSplit[1],
    }
  }

  static function getParams(req:IncomingMessage) : Params
  {
    var auth = parseAuth(req.headers["authorization"]);
    var r = ~/^\/([^+\/]+)(\+timeout=(\d+))?\/(.+)(.git)?\/(info\/refs\?service=)?(git-[^-]+-pack)$/;
    if (!r.match(req.url))
      throw 'Cannot deal with url';
    var repo = '${r.matched(1)}/${r.matched(4)}';
    var infos = repo + (auth != null ? ' (user ${safeUser(auth.basic)})' : '');
    return {
      auth: auth,
      infos: infos,
      timeout: r.matched(3) != null ? r.matched(3) : "60000",
      service: r.matched(7),
      isInfoRequest: r.matched(6) != null,
      repo: repo,
      remote: 'https://$repo',
      local: Path.join(cacheDir, repo)
    };
  }

  static function runGitWithCreds(cmd,args,auth) {
	  if(auth != null) {
      var credArgs = ['-c',"credential.helper=!echo username=$GIT_USER;echo password=$GIT_PASS;true"];
			var env = {GIT_USER:auth.user, GIT_PASS:auth.password};
			return ChildProcess.spawnSync(cmd,credArgs.concat(args),{env:env});
	  } else {
			var env = {};
		  return ChildProcess.spawnSync(cmd,args);
		}
  }

  static function clone(remote, local, auth, callback)
  {
    println('INFO: starting clone from $remote to $local');
	  var res = runGitWithCreds("git",["clone","--quiet","--mirror",remote,local],auth);
    saveHashedPassword(res, local, auth);
		callback(res);
  }

  static function fetch(remote, local, auth, callback)
  {
    println('INFO: starting fetch from $remote to $local');
	  runGitWithCreds("git",["-C",local,"remote","set-url","origin",remote],auth);
	  var res = runGitWithCreds("git",["-C",local,"fetch","--quiet","--prune","--prune-tags"],auth);
    saveHashedPassword(res, local, auth);
		callback(res);
  }

  static function saveHashedPassword(res:ChildProcessSpawnSyncResult, local, auth) {
    if(res.error == null && res.status == 0) {
      var salt = Random.string(32);
      var pwInfo = passwordInfo(local, auth);
      sys.io.File.saveContent(pwInfo.file, '$salt:${makeHash(pwInfo.password,salt)}');
    }
  }

  static function makeHash(password, salt) {
    return PBKDF2.encode(password, salt, 1000, 128);
  }

  static function authOffline(res:ServerResponse, params, callback:Bool->Void) {
    var pwInfo = passwordInfo(params.local, params.auth);
    var hashMatch = false;
    try {
	    var pwParts = sys.io.File.getContent(pwInfo.file).split(":");
      var salt = pwParts[0];
      var hash = pwParts[1];
      hashMatch = hash == makeHash(params.auth.password, salt);
    } catch (err:Dynamic) {
      hashMatch = false;
      println('ERR: no offline password found for user ${pwInfo.user}, $err');
    }
    
    if (hashMatch)
      callback(true);
    else {
      println('ERR: offline password hash mismatch for user ${pwInfo.user}');
      if(pwInfo.user == "@anon") {
        res.setHeader("www-authenticate",'Basic realm="GitHub"');
        res.writeHead(401, "Unauthorized");
      } else {
        res.writeHead(403, "Forbidden");
      }
      res.end();
    }
	}

  static function passwordInfo(local, auth) {
    var user = auth == null ? "@anon" : auth.user;
    var pass = auth == null ? "@none" : auth.password;
    return {user:user, password:pass, file:'$local/${user}.hashedpw'};
  }

  static function authenticate(res:ServerResponse, params, callback:Bool->Void)
  {
    println('INFO: authenticating on the upstream repo ${params.infos} timeout=${params.timeout}');
    var url = 'https://${params.repo}/info/refs?service=${params.service}';
    var eopts: js.node.Https.HttpsRequestOptions = {};
    eopts.timeout = parseInt(params.timeout);
    if(proxyAgent != null)
      eopts.agent = proxyAgent;
      
    var req = Https.request(url, eopts, function(upRes) {
      upRes.resume();
      switch(upRes.statusCode) {
        case 200:
          callback(false);
        default:
          println('ERROR: error from $url, statuscode:${upRes.statusCode}');
          res.writeHead(upRes.statusCode, upRes.headers);
          res.end();
        }
      });
    
    req.setTimeout(eopts.timeout, function (socket) { println('ERROR: timeout'); req.abort(); });
    req.setHeader("User-Agent", "git/");
    if (params.auth != null)
      req.setHeader("Authorization", params.auth.authorization);
      
    req.on('error', function (err:Dynamic) {
      if(err.errors is Array) {
         for(error in (err.errors : Array<Error>))
             println('ERROR: $error');
      }
      else {
           println('ERROR: ${(err:Error)}');
           println(haxe.CallStack.toString(haxe.CallStack.exceptionStack()));
      }
      println('INFO: detected remote server offline, using offline cache if possible');
      authOffline(res, params, callback);
    });
    
    req.end();
  }


  static function update(offline, params, callback)
  {
    var local = params.local;
    if (offline) {
      updatePromises[local] = Promise.resolve(null);
    }
    if (!updatePromises.exists(local)) {
      updatePromises[local] = new Promise(function(resolve, reject) {
        println('INFO: updating: fetching from ${params.infos}');
        fetch(params.remote, local, params.auth, function (fres) {
          if (fres.error != null || fres.status != 0) {
            println('WARN: updating: fetch failed with status code ${fres.status}, error ${fres.error}');
            println(fres.stdout);
            println(fres.stderr);
            println("WARN: continuing with clone");
            clone(params.remote, local, params.auth, function (cres) {
              if (cres.error != null || cres.status != 0) {
                println(cres.stdout);
                println(cres.stderr);
                reject('ERR: git clone exited with non-zero status: ${cres.status}');
              } else {
                println("INFO: updating via clone: success");
                resolve(null);
              }
            });
          } else {
            println("INFO: updating via fetch: success");
            resolve(null);
          }
        });
      });
    } else {
      println("INFO: reusing existing promise");
    }
    return updatePromises[local].then(
      function(nothing:Dynamic) {
        println("INFO: promise fulfilled");
        callback(null);
      },
      function(err:Dynamic) {
        println('WARNING: promise rejected error:${err}');
        callback(err);
      }).finally(function() {
        updatePromises.remove(local);
      });
  }

  static function handleRequest(req:IncomingMessage, res:ServerResponse)
  {
    try {
      println('REQUEST: ${req.method} ${req.url}');
      var params = getParams(req);

      switch ([req.method == "GET", params.isInfoRequest]) {
        case [false, false], [true, true]:  // ok
        case [m, i]: throw 'isInfoRequest=$i but isPOST=$m';
      }

      if (params.service != "git-upload-pack")
        throw 'Service ${params.service} not supported yet';

      authenticate(res, params, function (offline) {
        // will only be called if auth successful
        if (params.isInfoRequest) {
          update(offline, params, function (err) {
            if (err != null) {
              println('ERR: $err');
              println(haxe.CallStack.toString(haxe.CallStack.exceptionStack()));
              res.statusCode = 500;
              res.end();
              return;
            }
            res.statusCode = 200;
            res.setHeader("Content-Type", 'application/x-${params.service}-advertisement');
            res.setHeader("Cache-Control", "no-cache");
            res.write("001e# service=git-upload-pack\n0000");
            var up = ChildProcess.spawn(params.service, ["--stateless-rpc", "--advertise-refs", params.local]);
            up.stdout.pipe(res);
            up.stderr.on("data", function (data) println('${params.service} stderr: $data'));
            up.on("exit", function (code) {
              if (code != 0)
                res.end();
              println('INFO: ${params.service} done with exit $code');
            });
          });
        } else {
          res.statusCode = 200;
          res.setHeader("Content-Type", 'application/x-${params.service}-result');
          res.setHeader("Cache-Control", "no-cache");
          var up = ChildProcess.spawn(params.service, ["--stateless-rpc", params.local]);
          // If we receive gzip content, we must unzip
          if (req.headers['content-encoding'] == 'gzip')
            req.pipe(Zlib.createUnzip()).pipe(up.stdin);
          else
            req.pipe(up.stdin);
          up.stdout.pipe(res);
          up.stderr.on("data", function (data) println('${params.service} stderr: $data'));
          up.on("exit", function (code) {
            if (code != 0)
              res.end();
            println('${params.service} done with exit $code');
          });
        }
      });
    } catch (err:Dynamic) {
      println('ERROR: $err');
      println(haxe.CallStack.toString(haxe.CallStack.exceptionStack()));
      res.statusCode = 500;
      res.end();
    }
  }

  static var updatePromises = new Map<String, Promise<Dynamic>>();
  static var cacheDir = "/tmp/var/cache/git/";
  static var listenPort = 8080;
  static var proxyAgent = null;
  static var usage = "
A caching Git HTTP server.

Serve local mirror repositories over HTTP/HTTPS, updating them as they are requested.

Usage:
  git-cache-http-server.js [options]

Options:
  -c,--cache-dir <path>   Location of the git cache [default: /var/cache/git]
  -p,--port <port>        Bind to port [default: 8080]
  -h,--help               Print this message
  --version               Print the current version
";

  static function main()
  {
    var options = js.npm.Docopt.docopt(usage, { version : Version.readPkg() });
    cacheDir = options["--cache-dir"];
    listenPort = Std.parseInt(options["--port"]);
    if (listenPort == null || listenPort < 1 || listenPort > 65535)
      throw 'Invalid port number: ${options["--port"]}';

    println('INFO: cache directory: $cacheDir');
    println('INFO: listening to port: $listenPort');

    var env = Sys.environment();
    var proxyUrl = env["http_proxy"];
    if (proxyUrl == null)
      proxyUrl = env["HTTP_PROXY"];
    if (proxyUrl != null)
      proxyAgent = new HttpsProxyAgent(proxyUrl);

    var server = Http.createServer(handleRequest);
    server.setTimeout(120*60*1000); // 120 * 60 seconds * 1000 msecs
    server.listen(listenPort);
  }
}
