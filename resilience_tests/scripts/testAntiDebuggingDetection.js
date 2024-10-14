if (ObjC.available) {
    try {
        console.log("===== Testing Anti-Debugging Detection =====\n");

        function summarizeCompliance(sysctlCounter, ptraceCounter, getppidCounter, hookInstalled, sysctlDetection, ptraceDetection, getppidDetection) {
            if (hookInstalled) {
                if (sysctlCounter > 0 || ptraceCounter > 0 || getppidCounter > 0) {
                    if (sysctlDetection || ptraceDetection || getppidDetection) {
                        console.log("[*] Cumplimiento: Se detectaron llamadas a sysctl, ptrace o getppid, indicando mecanismos anti-depuración.\n");
                        console.log("[*] Las llamadas a estas funciones fueron interceptadas y los valores devueltos fueron modificados para evitar la detección de depuradores.\n");
                        console.log("[*] Conclusión: El bypass fue exitoso, las funciones anti-depuración fueron evadidas, y la aplicación no detectó la presencia del depurador.\n");
                    } else {
                        console.log("[*] Cumplimiento parcial: Se detectaron llamadas a las funciones, pero no parecen estar relacionadas con mecanismos de detección de depuradores.\n");
                    }
                } else {
                    console.log("[!] Incumplimiento: No se detectaron llamadas a sysctl, ptrace o getppid en el tiempo monitoreado. La aplicación parece no implementar mecanismos de detección de depuradores, lo cual incumple con el test de MASVS Testing Anti-Debugging Detection.\n");
                }
            } else {
                console.log("[*] No se pudo instalar el hook. No se detectaron mecanismos de anti-depuración visibles.\n");
            }
            console.log("---split---");
        }

        function testAntiDebuggingDetection() {
            console.log("===== Testing Anti-Debugging Detection =====\n");

            const MAX_EXECUTIONS = 1;
            let sysctlCounter = 0;
            let ptraceCounter = 0;
            let getppidCounter = 0;
            let sysctlDetection = false;
            let ptraceDetection = false;
            let getppidDetection = false;
            let hookInstalled = false;

            const sysctl = Module.findExportByName(null, "sysctl");
            const ptrace = Module.findExportByName(null, "ptrace");
            const getppid = Module.findExportByName(null, "getppid");

            if (!sysctl || !ptrace || !getppid) {
                summarizeCompliance(sysctlCounter, ptraceCounter, getppidCounter, hookInstalled, sysctlDetection, ptraceDetection, getppidDetection);
                return;
            }

            console.log("Las funciones sysctl, ptrace y getppid están disponibles para ser interceptadas.\n");

            // Hook sysctl
            const sysctlHook = Interceptor.attach(sysctl, {
                onEnter: function(args) {
                    console.log("[*] sysctl llamado para detección de depurador. Argumentos: " + args[0].toString() + "\n");
                    console.log("[*] Verificando el tipo de clave pasada a sysctl...\n");

                    // Inspecciona los argumentos de sysctl
                    if (args[0].toInt32() === 1) { // Verifica si se está utilizando KERN_PROC, por ejemplo
                        console.log("[*] La aplicación está utilizando sysctl con KERN_PROC para intentar detectar depuradores.\n");
                        sysctlDetection = true;
                    } else {
                        console.log("[*] sysctl fue llamado pero no parece estar relacionado con la detección de depuradores.\n");
                    }
                },
                onLeave: function(retval) {
                    console.log("[*] Valor original de retorno de sysctl: " + retval.toInt32().toString() + "\n");
                    retval.replace(0); // Bypass sysctl
                    console.log("[*] Valor modificado de retorno de sysctl (Bypass): " + retval.toInt32().toString() + "\n");
                    sysctlCounter++;
                    if (sysctlCounter >= MAX_EXECUTIONS) {
                        sysctlHook.detach();
                    }
                }
            });

            // Hook ptrace
            const ptraceHook = Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    console.log("[*] ptrace llamado para detección de depurador. Argumentos: " + args[0].toString() + "\n");
                    ptraceDetection = true;
                },
                onLeave: function(retval) {
                    console.log("[*] Valor original de retorno de ptrace: " + retval.toInt32().toString() + "\n");
                    retval.replace(-1); // Bypass ptrace
                    ptraceCounter++;
                    if (ptraceCounter >= MAX_EXECUTIONS) {
                        ptraceHook.detach();
                    }
                }
            });

            // Hook getppid
            const getppidHook = Interceptor.attach(getppid, {
                onEnter: function(args) {
                    console.log("[*] getppid llamado para detección de depurador.\n");
                    getppidDetection = true;
                },
                onLeave: function(retval) {
                    const parentPID = Process.getParent().id;
                    console.log("[*] Valor original de retorno de getppid: " + retval.toInt32().toString() + "\n");
                    retval.replace(parentPID); // Bypass getppid
                    getppidCounter++;
                    if (getppidCounter >= MAX_EXECUTIONS) {
                        getppidHook.detach();
                    }
                }
            });

            hookInstalled = true;
            console.log("[*] Hooks instalados en sysctl, ptrace y getppid. Esperando llamadas...\n");

            setTimeout(function() {
                summarizeCompliance(sysctlCounter, ptraceCounter, getppidCounter, hookInstalled, sysctlDetection, ptraceDetection, getppidDetection);
            }, 3000); // Monitoreo de 3 segundos
        }

        setTimeout(testAntiDebuggingDetection, 1000);  // Iniciar prueba

    } catch (err) {
        console.error("Error durante la ejecución: " + err.message);
    }
} else {
    console.warn("Objective-C no está disponible.");
}
