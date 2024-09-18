document.addEventListener('DOMContentLoaded', () => {
    // Obtener referencias a los elementos del DOM
    const uploadBtn = document.getElementById('uploadBtn');
    const fileInput = document.getElementById('file');
    const uploadForm = document.getElementById('uploadForm');
    
    // Asignar evento click al botón de subir archivo
    uploadBtn.addEventListener('click', () => fileInput.click());

    // Asignar evento change al input de archivo
    fileInput.addEventListener('change', () => {
        // Si hay archivos seleccionados, enviar el formulario
        if (fileInput.files.length > 0) {
            uploadForm.submit();
        }
    });
});