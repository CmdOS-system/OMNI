# OMNI Preview para Windows

OMNI Preview es una aplicación gráfica portable de exploración y lanzamiento **explícito** de archivos inspeccionados. Descarga el artefacto `OMNI-Preview-Windows` desde GitHub Actions o ejecuta `python -m omni.windows_preview` desde el repositorio. La compilación PyInstaller genera un único `OMNI-Preview.exe`.

## Biblioteca y motores

Puedes agregar archivos, seleccionar una entrada de la biblioteca, consultar los motores disponibles y solicitar su apertura. El motor nativo admite ejecutables PE `.exe` compatibles con el Windows anfitrión. El adaptador experimental WSL2 intenta abrir ELF compatibles desde una unidad local de Windows usando una distribución WSL2 instalada. Ninguno de los dos garantiza compatibilidad con todas las aplicaciones.

El botón **Verificar archivo** compara el SHA-256, el formato y la arquitectura actuales con los valores registrados. Distingue entre archivo sin cambios, modificado, ausente y no inspeccionable. La verificación se realiza en segundo plano y **no** actualiza el registro de confianza ni ejecuta el archivo. Si cambia, vuelve a agregarlo conscientemente antes de intentar ejecutarlo.

OMNI requiere confirmación explícita antes de lanzar o forzar el cierre de procesos. Muestra procesos iniciados por la propia aplicación y diagnósticos acotados de stderr para WSL2. Finalizar `wsl.exe` no garantiza detener sus procesos Linux descendientes.

## Límites de seguridad y validación

**No hay sandbox.** Los programas se ejecutan con permisos del usuario. WSL2 puede acceder a archivos y redes del anfitrión. La verificación de rutas y huellas digitales no es una protección atómica contra reemplazos concurrentes de archivos. No abras ejecutables desconocidos o no confiables. La compilación automatizada y las pruebas unitarias no sustituyen la validación interactiva en un equipo Windows real, ni certifican compatibilidad.
