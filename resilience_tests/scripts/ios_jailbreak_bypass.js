// Script para bypassear detección de jailbreak con Frida
// Hook a la función 'fileExistsAtPath' para evitar detección de archivos de jailbreak

var paths = [
    "/Applications/Cydia.app",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/cydia",
    "/usr/bin/ssh"
];

var canOpenURLPaths = [
    "cydia://package/com.example.package"
];

function bypassFileExistsAtPath() {
    var resolver = new ApiResolver('objc');
    var targetClass = "NSFileManager";
    
    resolver.enumerateMatches('-[NSFileManager fileExistsAtPath:]', {
        onMatch: function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    var path = ObjC.Object(args[2]).toString();
                    if (paths.indexOf(path) !== -1) {
                        // Si el path coincide con alguno de los indicativos de jailbreak, devuelve 0 (no encontrado)
                        this.shouldBypass = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.shouldBypass) {
                        retval.replace(0);
                    }
                }
            });
        },
        onComplete: function () {}
    });
}

function bypassCanOpenURL() {
    var resolver = new ApiResolver('objc');
    var targetClass = "UIApplication";

    resolver.enumerateMatches('-[UIApplication canOpenURL:]', {
        onMatch: function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    var url = ObjC.Object(args[2]).toString();
                    if (canOpenURLPaths.indexOf(url) !== -1) {
                        // Si el URL coincide con cydia://, no permite abrirla
                        this.shouldBypass = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.shouldBypass) {
                        retval.replace(0);
                    }
                }
            });
        },
        onComplete: function () {}
    });
}

// Ejecutar el bypass
bypassFileExistsAtPath();
bypassCanOpenURL();