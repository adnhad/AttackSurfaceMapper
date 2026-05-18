# Attack Surface Mapper

Attack Surface Mapper is a lightweight local platform for Android attack-surface inspection from either an APK or a decoded `AndroidManifest.xml` file. It extracts Android components, exported state, permissions, intent filters, and deep-link metadata, then turns that data into a readable security report with findings, recommendations, a heuristic risk score, and a Mermaid-based component graph.

The project was built for secure development review, classroom demonstrations, and first-pass Android triage. Its goal is not to replace heavyweight mobile security suites, but to give reviewers a fast and explainable view of what is externally reachable in an app before moving to deeper reverse-engineering tools.

## What the app does

- Accepts either:
  - an `.apk`
  - a decoded `AndroidManifest.xml`
- Extracts:
  - activities
  - activity aliases
  - services
  - broadcast receivers
  - content providers
  - exported status
  - permissions, `readPermission`, `writePermission`
  - intent filters
  - deep-link data such as scheme, host, path, and MIME type
- Detects high-signal risky patterns such as:
  - exported components without permission protection
  - browsable deep links
  - broad provider URI grants
  - suspicious `FileProvider`-like configurations
  - `android:allowBackup="true"`
  - `android:debuggable="true"`
- Produces:
  - surface-risk score from `0` to `100`
  - severity-tagged findings
  - remediation recommendations
  - component inventory
  - Mermaid graph source and rendered graph

## Architecture summary

The application is split into a compact Java backend and a browser frontend.

- `src/Main.java`
  - CLI entry point and local server launcher
- `src/SimpleWebServer.java`
  - local HTTP server for static pages and `/api/analyze`
- `src/ManifestLoader.java`
  - accepts XML or APK input and dispatches parsing
- `src/BinaryXmlParser.java`
  - decodes Android binary XML from APKs
- `src/ManifestModelParser.java`
  - builds the normalized `AttackSurfaceModel`
- `src/AttackSurfaceAnalyzer.java`
  - applies rule-based findings and computes the risk score
- `src/AttackSurfaceReport.java`
  - generates text and JSON report output
- `src/MermaidGraphBuilder.java`
  - generates Mermaid graph source
- `web/`
  - multi-page frontend for upload, overview, components, graph, findings, and recommendations

## Risk scoring model

The current score is heuristic and deterministic.

Application-level contributions:

- `allowBackup=true` -> `+12`
- `debuggable=true` -> `+25`

Exported component base score:

- provider -> `+18`
- service -> `+14`
- receiver -> `+10`
- activity / activity alias -> `+8`

Adjustments:

- permission protection present -> `-5`
- intent filter present -> `+4`
- deep link present -> `+8`
- `grantUriPermissions=true` -> `+10`

The final score is clamped to `0..100`.

## Run locally

### Requirements

- JDK 21+ recommended
- Windows, macOS, or Linux

### Start from source

```powershell
New-Item -ItemType Directory -Force out | Out-Null
javac -d out src\*.java
java -cp out Main
```

Then open:

```text
http://127.0.0.1:8080
```

### CLI mode

```powershell
java -cp out Main path\to\app.apk --json
```

or

```powershell
java -cp out Main path\to\AndroidManifest.xml
```

## Run with Docker

This project includes a `Dockerfile` and `docker-compose.yml` so the teacher can run it with minimal setup.

### Using Docker Compose

```bash
docker compose up --build
```

Then open:

```text
http://127.0.0.1:8080
```

To stop it:

```bash
docker compose down
```

### Notes for Docker usage

- The app runs entirely locally inside the container.
- The browser UI still uploads the APK to the local containerized backend only.
- The server is bound to `0.0.0.0` in Docker so port `8080` can be published to the host.

## Demo video

**Demo video:** [Watch the demo](https://drive.google.com/file/d/1OMvNaPXu2M6TxGq5geCXqz25BoWCFfbo/view?usp=sharing)


## Suggested usage workflow

1. Launch the app locally or with Docker.
2. Upload an APK or decoded manifest.
3. Check the overview page for score and summary counters.
4. Inspect exported components on the components page.
5. Use the graph page to visualize structural exposure.
6. Read the findings and recommendations pages to understand risk and remediation.

## Current limitations

- Manifest-level static analysis only
- No dynamic analysis
- No deep DEX semantic inspection
- Heuristic score, not exploitability proof
- Some exported components may be legitimate by design
- Presentation quality of Mermaid rendering depends on the browser environment

## Project structure

```text
surface_attack_mapper/
|---- src/
|---- web/
|---- reports/
|---- Dockerfile
|---- docker-compose.yml
`---- README.md
```

## License

MIT license

## Authors

Adnan Hadrou 
Amine FLoulou
