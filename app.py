import sys
import os
from flask import Flask
from config import UPLOAD_FOLDER, RESULTS_FOLDER
from routes import routes

# Add 'resilience_tests' directory to PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'resilience_tests'))

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER

app.register_blueprint(routes)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')