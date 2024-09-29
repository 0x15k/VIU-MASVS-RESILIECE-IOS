if (ObjC.available) {
    console.log("Iniciando bypass de detección de jailbreak...");

    var paths_to_bypass = [
        "/Applications/blackra1n.app",
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSetttings.app",
        "/Applications/WinterBoard.app",
        "/bin/bash",
        "/bin/sh",
        "/bin/su",
        "/etc/apt",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/tmp/cydia.log"
    ];

    function bypass(path) {
        if (paths_to_bypass.includes(path)) {
            console.log("Evitando chequeo para: " + path);
            return -1;
        }
        return 0;
    }

    var functions_to_intercept = ["stat", "open", "access", "lstat", "fopen", "opendir"];

    functions_to_intercept.forEach(function(func) {
        try {
            Interceptor.attach(Module.findExportByName(null, func), {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    console.log("Interceptando llamada a " + func + " con path: " + path);
                    this.bypass = bypass(path);
                },
                onLeave: function(retval) {
                    if (this.bypass) {
                        console.log("Bypass activado para " + func + " con path " + path);
                        retval.replace(-1);
                    }
                }
            });
        } catch (err) {
            console.log("Error interceptando " + func + ": " + err.message);
        }
    });

    console.log("Bypass completado.");
} else {
    console.log("Objective-C no está disponible.");
}