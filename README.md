# Sonda

Agente de IA para analizar capturas de red (`.pcap` / `.pcapng`): muestra un panel con los datos más importantes, detecta patrones de ataque, reconstruye flujos TCP y extrae los archivos transferidos con su SHA-256, propone y prueba reglas Snort, y responde preguntas sobre la captura desde un chat.

## Requisitos

- Node.js 18 o superior (no hay dependencias que instalar).
- Una clave de la API de Anthropic para el agente y el chat. Sin clave, el análisis, el panel y las reglas sugeridas siguen funcionando.

## Puesta en marcha

```bash
cd sonda
cp .env.example .env      # en Windows: copy .env.example .env
# edita .env y pon tu ANTHROPIC_API_KEY
npm start
```

Abre http://localhost:3000 y arrastra una captura, o pulsa "Probar con una captura de ejemplo".

Para generar un archivo de ejemplo y abrirlo también en Wireshark o Snort:

```bash
npm run ejemplo           # crea ejemplo.pcap
```

### Con Docker

```bash
docker build -t sonda .
docker run --rm -p 127.0.0.1:3000:3000 --env-file .env sonda
```

## Análisis desde la terminal

Sin navegador ni IA, útil para automatizar:

```bash
npm run analizar -- ejemplo.pcap
npm run analizar -- captura.pcap --reglas local.rules
npm run analizar -- captura.pcap --archivos extraidos   # guarda los archivos y un SHA256SUMS
npm run analizar -- captura.pcap --pdf informe.pdf --iocs iocs.csv --stix iocs.json --caso INC-1 --tlp amber
```

Para comprobar después que los archivos no cambiaron: `cd extraidos && sha256sum -c SHA256SUMS` (en macOS, `shasum -a 256 -c SHA256SUMS`).

## Configuración (.env)

| Variable | Por defecto | Uso |
|---|---|---|
| `ANTHROPIC_API_KEY` | (vacía) | Clave de la API. Necesaria para el agente. |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` | Modelo usado por el agente. |
| `MAX_TOKENS` | `4096` | Máximo de tokens por respuesta. |
| `PORT` | `3000` | Puerto del servidor. |
| `HOST` | `127.0.0.1` | Interfaz. Usa `0.0.0.0` solo si sabes quién accede: cualquiera que llegue al servidor gasta tu clave. |
| `ANTHROPIC_API_URL` | API oficial | Para pasar por un proxy corporativo o un gateway propio. |

Consulta los modelos disponibles y precios en https://docs.claude.com.

## Informes para entregar

"Exportar informe" pide los datos del caso (título, referencia, organización, analista y clasificación TLP), los recuerda en el navegador y genera:

- **PDF** listo para entregar:
  - Portada con la ficha del caso, el SHA-256 de la captura (para la cadena de custodia) y el nivel de riesgo.
  - Resumen ejecutivo en lenguaje claro y acciones recomendadas por prioridad.
  - Línea de tiempo por fases con MITRE ATT&CK.
  - Cada hallazgo con sus evidencias y sus tramas de referencia (`frame.number == N` en Wireshark).
  - Indicadores de compromiso y activos afectados.
  - Reglas Snort con las alertas que generan, archivos extraídos, perfil del tráfico, y metodología y limitaciones.
  - La marca TLP va en cada página, y el documento incluye marcadores y enlaces a ATT&CK. Opcionalmente añade la valoración del agente de IA.
- **Paquete de entrega (.zip)** con el PDF, el informe en Markdown, los IoC en CSV y en STIX 2.1, `local.rules`, los hashes de los archivos extraídos, un `LEEME.txt` y un `SHA256SUMS.txt` para comprobar la integridad del paquete. Los archivos extraídos no se incluyen porque pueden ser malware.
- **IoC en CSV** (hojas de cálculo y SIEM; los valores que empiezan como una fórmula se neutralizan) y en **STIX 2.1** (MISP, OpenCTI), con indicadores enlazados a las técnicas de ATT&CK y la marca TLP. En STIX, TLP:AMBER+STRICT se marca como TLP:AMBER, porque STIX 2.1 solo define las marcas TLP 1.0.

Desde la terminal: `npm run analizar -- captura.pcap --pdf informe.pdf --iocs iocs.csv --stix iocs.json --caso INC-1 --org "Mi empresa" --analista "SOC" --tlp amber`.

El PDF usa las fuentes estándar de PDF, que cubren el español; los caracteres de otros alfabetos o los emojis se sustituyen por "?" en las páginas (los metadatos del documento los conservan).

## MITRE ATT&CK y línea de tiempo del incidente

Cada hallazgo indica su fase del incidente y sus técnicas de MITRE ATT&CK (por ejemplo, T1046 para un escaneo de puertos o T1071.004 para un túnel DNS), con enlace a la ficha de cada técnica. Las reglas sugeridas incluyen la técnica principal como `reference:url,attack.mitre.org/...`.

La pestaña "Incidente" ordena los hallazgos en una línea de tiempo por fases (reconocimiento, acceso, comando y control, exfiltración e impacto). También muestra los equipos que aparecen en varias fases, que suelen ser el atacante, la víctima o el servidor de control, y avisa si las fases no siguen el orden habitual de un ataque. "Exportar capa ATT&CK Navigator" genera un JSON que se abre en el [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) con las técnicas coloreadas por severidad. El informe Markdown y `npm run analizar` incluyen la misma línea de tiempo.

El mapeo es heurístico: asigna la técnica más probable para cada patrón de tráfico, pero desde la red no siempre se puede distinguir, por ejemplo, un escaneo externo (T1595) de uno interno (T1046).

## Reconstruir flujos TCP y extraer archivos

- **Seguir flujo TCP.** En "Conversaciones" pulsa "Seguir" (o "Seguir flujo TCP" en el detalle de un paquete). Se muestra el diálogo completo como en Wireshark, en rojo lo que envía el cliente y en azul lo que responde el servidor, en ASCII, UTF-8 o hexadecimal. Los segmentos se ordenan por número de secuencia, se descartan las retransmisiones y se marcan los bytes que faltan en la captura. Si la misma pareja IP:puerto se reutilizó, cada conexión se ve por separado. Puedes descargar cada sentido en binario o el diálogo como texto.
- **Archivos.** La pestaña "Archivos" lista lo transferido en claro por:
  - **HTTP/1.x**: cuerpos de respuesta (con `Content-Length`, `chunked` o hasta el cierre, y descomprimidos si vienen en gzip o deflate) y subidas por `POST`/`PUT`, incluidas las partes `multipart/form-data`.
  - **FTP**: `RETR`, `STOR`, `APPE` y listados, enlazando la orden con su conexión de datos (`PASV`, `EPSV`, `PORT`, `EPRT`).
  - **SMB2/3 sin cifrar**: lecturas y escrituras de archivos (`CREATE`, `READ`, `WRITE`), con la ruta `\\servidor\recurso\archivo`.
- Cada archivo lleva su **SHA-256**, su tipo real según los primeros bytes (avisa si un "PDF" es en realidad un ejecutable), origen, destino y si está completo. "Exportar SHA256SUMS" genera un archivo compatible con `sha256sum -c`, y "Descargar todo (.zip)" incluye los archivos y ese mismo listado. Los ejecutables generan un hallazgo con una regla Snort.
- Los archivos pueden ser malware: ábrelos solo en una máquina aislada.

## Usar las reglas en Snort

1. En la pestaña "Reglas Snort", pulsa "Exportar local.rules".
2. Renombra el archivo descargado a `local.rules`.
3. Define `HOME_NET` en tu configuración e incluye el archivo:
   - Snort 3 (`snort.lua`): `ips = { include = 'local.rules', variables = default_variables }`
   - Snort 2 (`snort.conf`): `include $RULE_PATH/local.rules`
4. Prueba contra la misma captura: `snort -c snort.lua -R local.rules -r captura.pcap -A alert_fast` (Snort 3) o `snort -c snort.conf -r captura.pcap -A console` (Snort 2).

## Estructura

```
sonda/
├── server.js               Servidor HTTP: sirve public/ y reenvía /api/messages a la API
├── public/
│   ├── index.html          Estructura de la interfaz
│   ├── styles.css          Estilos (tema claro y oscuro)
│   ├── worker.js           Web Worker: lee y analiza la captura sin congelar la interfaz
│   ├── report.js           Informes: datos, PDF, Markdown, IoC en CSV y STIX 2.1
│   ├── engine.js           Lector pcap/pcapng, decodificadores, estadísticas,
│   │                       reensamblado TCP, extracción de archivos y SHA-256,
│   │                       detecciones, generador y probador de reglas Snort
│   ├── app.js              Interfaz: panel, tablas, flujos, archivos, hallazgos, reglas, chat
│   │                       y herramientas del agente
│   └── local-runtime.js    Bucle del agente (tool use) y descargas
├── scripts/
│   ├── generar-ejemplo.js  Crea ejemplo.pcap con ataques simulados
│   └── analizar.js         Análisis por terminal (y extracción de archivos)
├── Dockerfile
└── .env.example
```

## Cómo funciona el agente

La captura se procesa en el navegador, dentro de un Web Worker para que la interfaz siga respondiendo con archivos grandes (si el navegador no lo permite, se procesa en la página como antes); el servidor nunca la recibe. Cuando preguntas algo, el navegador envía la conversación al servidor, que añade la clave y la reenvía a la API con la lista de herramientas. Si el modelo pide una herramienta (`buscar_paquetes`, `detalle_host`, `consultas_dns`, `trafico_web`, `conversaciones`, `seguir_flujo_tcp`, `archivos_transferidos`, `linea_de_tiempo_incidente`, `listar_hallazgos`, `probar_regla_snort`, `crear_regla_snort`…), `local-runtime.js` la ejecuta en el navegador contra la captura cargada y devuelve el resultado, hasta que el modelo responde.

Para añadir una herramienta, agrega una entrada a `TOOLS` en `public/app.js` con nombre, descripción, esquema de entrada y función `execute`.

Para añadir una detección, edita `detect()` en `public/engine.js`: cada hallazgo es un objeto con severidad, título, descripción, evidencia y reglas sugeridas.

## Limitaciones

- Las detecciones son heurísticas; confírmalas antes de actuar.
- El probador de reglas cubre las opciones más comunes (`content` y modificadores, `flags`, `pcre`, `dsize`, `itype`, `icode`, `flow:established`, `detection_filter`). Evalúa paquete a paquete (no sobre el flujo reensamblado) ni usa los buffers HTTP de Snort 3; valida siempre en Snort real.
- La tabla de paquetes, la prueba de reglas, el seguimiento de flujos y la extracción de archivos usan los primeros 250.000 paquetes (las estadísticas cubren todo).
- La extracción no descifra nada: HTTPS, FTPS y SMB3 cifrado quedan fuera, igual que HTTP/2, SMB1 y los fragmentos IP. Los archivos con huecos se marcan como incompletos (las partes perdidas quedan a cero) y su hash no coincidirá con el original. En FTP en modo ASCII (`TYPE A`) los saltos de línea pueden cambiar el hash.
- Archivos de varios GB pueden agotar la memoria del navegador; divídelos con `editcap -c 500000`. Mientras se leen, la interfaz sigue respondiendo y se puede pulsar "Cancelar".
