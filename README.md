# OMNI

Repositorio exclusivo del proyecto OMNI: gestor de compatibilidad multiplataforma en investigación.

## Componentes

- `engine/loader/`: inspector y despachador Rust actualmente orientado a Linux.
- `docs/PROOF-CONTRACT.md`: verificación de aplicaciones reales.
- `docs/ARCHITECTURE.md`: arquitectura y alcance.

## Pruebas

`cargo test --workspace --all-targets`

No se ha certificado ninguna aplicación externa. La aplicación instalable y la migración de Research Lab v0.12 siguen pendientes.

## Windows Preview (experimental)

El ejecutable de Windows se genera mediante el workflow `OMNI Windows Preview executable`.
Su biblioteca muestra, en segundo plano, el estado de integridad de los archivos
registrados: **Sin cambios**, **Modificado**, **No encontrado** o **No disponible**.
La comprobación se repite al añadir o quitar archivos y se puede solicitar
manualmente con **Verificar archivo**. Los resultados son observaciones puntuales:
**no certifican compatibilidad ni seguridad**, no ejecutan aplicaciones y no
actualizan la huella SHA-256 guardada. Los motores de ejecución vuelven a
comprobar el archivo antes de iniciarlo y solicitan confirmación explícita.

## Descargar y probar OMNI Preview en Windows

1. Abre [OMNI Windows Preview en GitHub Actions](https://github.com/CmdOS-system/OMNI/actions/workflows/omni-windows-preview.yml).
2. Selecciona una ejecución **correcta** de la rama `main`. Si no hay ninguna, usa **Run workflow** desde GitHub, siempre que tengas permisos.
3. En **Artifacts**, descarga `OMNI-Preview-Windows` y descomprime el ZIP.
4. Comprueba que están `OMNI-Preview.exe` y `OMNI-Preview.exe.sha256`. En PowerShell, dentro de la carpeta descomprimida, ejecuta:

```powershell
$expected = (Get-Content .\OMNI-Preview.exe.sha256).Split(' ')[0].Trim().ToLowerInvariant()
$actual = (Get-FileHash .\OMNI-Preview.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "OMNI: SHA-256 no coincide" }
Write-Host "OMNI: integridad verificada"
```

5. Ejecuta `OMNI-Preview.exe` en Windows. No es necesario instalar Python para abrir el ejecutable empaquetado.

**Descarga directa mediante GitHub Releases (opcional):** si tienes permisos para
ejecutar el workflow, selecciona **Run workflow** y activa
`publish_release`. Solo después de superar las pruebas Windows y verificar
la huella SHA-256, el workflow publicará una **pre-release** con el EXE y
su archivo de comprobación en [Releases](https://github.com/CmdOS-system/OMNI/releases).
No se crea ninguna release automáticamente en cada push. Si la ejecución
falla, no se publica una versión nueva. Una release es una vista previa
experimental, no una certificación de compatibilidad.

**Alcance real:** esta versión es una vista previa experimental de la biblioteca, la inspección de archivos y la ejecución nativa autorizada de programas Windows compatibles con el propio sistema. No ejecuta de forma general aplicaciones de otros sistemas operativos ni garantiza compatibilidad, aislamiento o seguridad. No descargues ejecutables de procedencia desconocida para probarla.

**Estado de compilación:** la existencia del workflow no implica que haya un artefacto disponible; comprueba que la ejecución figure como correcta antes de descargar.
