import os

UPLOAD_FOLDER = 'resilience_tests/binary'
RESULTS_FOLDER = 'resilience_tests/results'
ALLOWED_EXTENSIONS = {'ipa', 'apk'}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

SCRIPTS = [
    'testAntiDebuggingDetection.js',
    'testWhetherAppIsDebuggable.js',
    'testReverseEngineeringToolsDetection.js',
    'ios_jailbreak_bypass.js'
]