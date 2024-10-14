if (ObjC.available) {
    try {
        console.log("Iniciando prueba de detección de herramientas de ingeniería inversa...\n");

        function testReverseEngineeringToolsDetection() {
            console.log("===== Testing Reverse Engineering Tools Detection =====\n");

            const tools = [
                { name: "frida-server", path: "/usr/sbin/frida-server" },
                { name: "CydiaSubstrate", path: "/Library/MobileSubstrate/MobileSubstrate.dylib" },
                { name: "Cycript", path: "/usr/bin/cycript" },
                { name: "SSL Kill Switch", path: "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch.dylib" }
            ];

            tools.forEach(tool => {
                const fileExists = ObjC.classes.NSFileManager.defaultManager().fileExistsAtPath_(tool.path);
                if (fileExists) {
                    console.log(`[*] Detectado: ${tool.name}\n`);
                } else {
                    console.log(`[*] No se ha detectado: ${tool.name}\n`);
                }
            });

            console.log("[*] Cumple con el control 'Testing Reverse Engineering Tools Detection'.\n");
            console.log("===== Fin de Testing Reverse Engineering Tools Detection =====\n");
            console.log("---split---");  // Agrega el delimitador aquí
        }

        setTimeout(testReverseEngineeringToolsDetection, 1000);  // Iniciar prueba

    } catch (err) {
        console.error("Error durante la ejecución: " + err.message);
    }
} else {
    console.log("Objective-C no está disponible.");
}