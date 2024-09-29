// Hooking de métodos en una aplicación iOS

// Hook UIApplication's canOpenURL: method
Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
    onEnter: function (args) {
        this.url = new ObjC.Object(args[2]).toString();
        send("canOpenURL: " + this.url);
    },
    onLeave: function (retval) {
        // Modificar el valor de retorno si es necesario
        // retval.replace(ptr("0x0"));
    }
});

// Hook NSFileManager's fileExistsAtPath: method
Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter: function (args) {
        this.path = new ObjC.Object(args[2]).toString();
        send("fileExistsAtPath: " + this.path);
    },
    onLeave: function (retval) {
        // Modificar el valor de retorno si es necesario
        // retval.replace(ptr("0x1"));
    }
});

// Hook fopen function
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function (args) {
        this.path = args[0].readCString();
        send("fopen: " + this.path);
    },
    onLeave: function (retval) {
        // Modificar el valor de retorno si es necesario
        // retval.replace(ptr("0x0"));
    }
});

// Hook libSystem.B.dylib's fork function
Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "fork"), {
    onLeave: function (retval) {
        // Modificar el valor de retorno si es necesario
        // retval.replace(ptr("0x0"));
    }
});

send("Hooking de métodos completado.");