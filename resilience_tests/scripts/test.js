if (ObjC.available) {
    try {
        console.log("Iniciando prueba de Anti-Debugging Detection y depurabilidad...");

        function summarizeCompliance(sysctlCounter, ptraceCounter, getppidCounter, hookInstalled, testType) {
            if (testType === "Anti-Debugging Detection") {
                if (hookInstalled) {
                    if (sysctlCounter > 0 || ptraceCounter > 0 || getppidCounter > 0) {
                        console.log("[*] Cumplimiento: La prueba de Anti-Debugging Detection se realizó correctamente.");
                        console.log("[*] El valor de retorno de las funciones se modificó para simular que no hay depurador presente.");
                    } else {
                        console.log("[!] No se detectaron llamadas a sysctl, ptrace o getppid dentro del tiempo de monitoreo. Es posible que la aplicación use otros métodos o que estas funciones se llamen más adelante.");
                    }
                } else {
                    console.log("[*] No se pudo instalar el hook. La aplicación se considera no debuggable y cumple con los requisitos de seguridad.");
                }
            } else if (testType === "Depurabilidad") {
                if (ptraceCounter > 0) {
                    console.log("[*] Se detectó el uso de ptrace para bloquear depuradores. La aplicación NO permite depuración con LLDB.");
                } else {
                    console.log("[*] No se detectaron bloqueos de ptrace. La aplicación es potencialmente depurable con LLDB.");
                }
            }
        }

        function testAntiDebuggingDetection() {
            console.log("===== Testing Anti-Debugging Detection =====");

            const MAX_EXECUTIONS = 1; 
            let sysctlCounter = 0;
            let ptraceCounter = 0;
            let getppidCounter = 0;
            let hookInstalled = false;

            const sysctl = Module.findExportByName(null, "sysctl");
            const ptrace = Module.findExportByName(null, "ptrace");
            const getppid = Module.findExportByName(null, "getppid");

            if (!sysctl || !ptrace || !getppid) {
                console.error("Error: No se encontraron todas las funciones necesarias (sysctl, ptrace, getppid).");
                summarizeCompliance(sysctlCounter, ptraceCounter, getppidCounter, hookInstalled, "Anti-Debugging Detection");
                return;
            }

            console.log("Las funciones sysctl, ptrace y getppid están disponibles para ser interceptadas.");

            // Hook sysctl
            const sysctlHook = Interceptor.attach(sysctl, {
                onEnter: function(args) {
                    console.log("[*] sysctl llamado para detección de depurador.");
                },
                onLeave: function(retval) {
                    retval.replace(0); // Bypass sysctl
                    sysctlCounter++;
                    if (sysctlCounter >= MAX_EXECUTIONS) {
                        sysctlHook.detach();
                    }
                }
            });

            // Hook ptrace
            const ptraceHook = Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    console.log("[*] ptrace llamado para detección de depurador.");
                },
                onLeave: function(retval) {
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
                    console.log("[*] getppid llamado para detección de depurador.");
                },
                onLeave: function(retval) {
                    const parentPID = Process.getParent().id;
                    retval.replace(parentPID); // Bypass getppid
                    getppidCounter++;
                    if (getppidCounter >= MAX_EXECUTIONS) {
                        getppidHook.detach();
                    }
                }
            });

            hookInstalled = true;
            console.log("[*] Hooks instalados en sysctl, ptrace y getppid. Esperando llamadas...");

            setTimeout(function() {
                summarizeCompliance(sysctlCounter, ptraceCounter, getppidCounter, hookInstalled, "Anti-Debugging Detection");
                testWhetherAppIsDebuggable();  // Llama al siguiente test
            }, 3000); // Monitorear por 3 segundos
        }

        function testWhetherAppIsDebuggable() {
            console.log("===== Testing Whether App Is Debuggable =====");

            let ptraceCounter = 0;
            const ptrace = Module.findExportByName(null, "ptrace");

            if (!ptrace) {
                console.error("Error: No se encontró la función `ptrace`. La aplicación podría ser depurable.");
                summarizeCompliance(ptraceCounter, null, null, null, "Depurabilidad");
                return;
            }

            console.log("Valor de `ptrace` encontrado:", ptrace);

            // Hook ptrace
            const ptraceHook = Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    console.log("[*] `ptrace` llamado para bloquear el depurador.");

                    const request = args[0].toInt32();
                    if (request === 0x1) { // PTRACE_TRACEME
                        ptraceCounter++;
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === -1) {
                        retval.replace(0); // Bypass ptrace
                    }
                }
            });

            console.log("[*] Hook instalado en `ptrace`. Monitoreando actividad...");

            setTimeout(function() {
                summarizeCompliance(ptraceCounter, null, null, null, "Depurabilidad");
                console.log("[*] Finalizado el test de depurabilidad.");
            }, 10000); // Monitorear por 10 segundos
        }

        setTimeout(testAntiDebuggingDetection, 1000);  // Iniciar prueba

    } catch (err) {
        console.error("Error durante la ejecución: " + err.message);
    }
} else {
    console.warn("Objective-C no está disponible.");
}
