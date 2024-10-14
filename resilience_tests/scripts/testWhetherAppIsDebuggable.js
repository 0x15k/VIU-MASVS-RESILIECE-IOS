if (ObjC.available) {
    try {
        console.log("Iniciando prueba de depurabilidad...\n");

        function summarizeCompliance(ptraceCounter) {
            if (ptraceCounter > 0) {
                console.log("[*] Cumplimiento: Se detectaron llamadas a ptrace, indicando que la aplicación es depurable.\n");
            } else {
                console.log("[!] No se detectaron llamadas a ptrace en el tiempo monitoreado. Es posible que la aplicación no sea depurable o que se llamen más tarde.\n");
            }
            console.log("---split---");  // Agrega el delimitador aquí
        }

        function testWhetherAppIsDebuggable() {
            console.log("===== Testing Whether App Is Debuggable =====\n");

            const MAX_EXECUTIONS = 1;
            let ptraceCounter = 0;

            const ptrace = Module.findExportByName(null, "ptrace");

            if (!ptrace) {
                console.error("Error: No se encontró la función ptrace.");
                summarizeCompliance(ptraceCounter);
                return;
            }

            console.log("La función ptrace está disponible para ser interceptada.\n");

            // Hook ptrace
            const ptraceHook = Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    console.log("[*] ptrace llamado para detección de depurador.\n");
                },
                onLeave: function(retval) {
                    retval.replace(-1); // Bypass ptrace
                    ptraceCounter++;
                    if (ptraceCounter >= MAX_EXECUTIONS) {
                        ptraceHook.detach();
                    }
                }
            });

            console.log("[*] Hook instalado en ptrace. Monitoreando actividad...\n");

            setTimeout(function() {
                summarizeCompliance(ptraceCounter);
            }, 3000); // Monitoreo de 3 segundos
        }

        setTimeout(testWhetherAppIsDebuggable, 1000);  // Iniciar prueba

    } catch (err) {
        console.error("Error durante la ejecución: " + err.message);
    }
} else {
    console.warn("Objective-C no está disponible.");
}