function detectJailbreak() {
    console.log("[*] Iniciando detección de jailbreak...");
    console.log("");
    console.warn("-----------------------------------");
    console.warn("|         File-based Checks       |");
    console.warn("-----------------------------------");

    var jailbreakIndicators = [
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/usr/sbin/frida-server",
        "/var/cache/apt",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        "/etc/ssh/sshd_config"
    ];

    var NSFileManager = ObjC.classes.NSFileManager;
    var fileManager = NSFileManager.defaultManager();
    var foundIndicators = [];

    // Comprobar indicadores de jailbreak
    jailbreakIndicators.forEach(function(path) {
        if (fileManager.fileExistsAtPath_(path)) {
            console.log("[!] Indicador de jailbreak encontrado: " + path);
            foundIndicators.push(path);
        }
    });

    // Mostrar indicadores encontrados
    if (foundIndicators.length > 0) {
        console.log("\n[!] Se encontraron " + foundIndicators.length + " indicadores de jailbreak:");
        foundIndicators.forEach(function(indicator, index) {
            console.log("  " + (index + 1) + ". " + indicator);
        });
        console.log("\n[!] Es muy probable que este dispositivo esté jailbreakeado.");
    } else {
        console.log("\n[*] No se encontraron indicadores claros de jailbreak.");
        console.log("[*] Sin embargo, esto no garantiza que el dispositivo no esté jailbreakeado.");
    }

    // Comprobación adicional: intentar escribir en un directorio restringido
    var testFile = "/private/jailbreak_test_" + Date.now() + ".txt";
    try {
        var canWrite = fileManager.createFileAtPath_contents_attributes_(testFile, "test", null);
        if (canWrite) {
            console.log("\n[!] Se pudo escribir en un directorio restringido: " + testFile);
            console.log("[!] Esto es un fuerte indicador de jailbreak.");
            // Eliminar el archivo de prueba
            fileManager.removeItemAtPath_error_(testFile, null);
        }
    } catch (error) {
        console.log("\n[*] No se pudo escribir en el directorio restringido. Esto es normal en dispositivos no jailbreakeados.");
        console.log("[*] Error: " + error);
    }

    console.log("\n[*] Detección de jailbreak completada.");
}

// Ejecutar la función
try {
    detectJailbreak();
} catch (error) {
    console.log("[ERROR] Se produjo un error durante la detección de jailbreak:");
    console.log(error);
}
