# NetGuard v2 — Simulador educativo de Firewall (Python)

**NetGuard v2** es un simulador educativo escrito en Python que permite entender conceptos de **Programación Orientada a Objetos (POO)** y patrones de diseño aplicados a un firewall en capas. El proyecto simula la llegada de paquetes de red, su validación y evaluación por una cadena de detectores (reputación, reglas y heurística). Es ideal para prácticas de redes, ciberseguridad y diseño orientado a objetos.

---

##  Resumen

- **Lenguaje:** Python 3.8+
- **Paradigma:** Programación Orientada a Objetos (clases, herencia, encapsulación, polimorfismo)
- **Patrones de diseño destacados:** Chain of Responsibility, Dependency Injection, Strategy (implícito), composición
- **Objetivo:** Simular el procesamiento de paquetes por un firewall compuesto por detectores que deciden si bloquear o permitir tráfico.

---

##  Características principales

- Paquetes con validación propia y manejo de excepciones personalizadas.
- Tres detectores concretos que implementan una interfaz abstracta (`DetectorBase`):
  - `DetectorReputacionIP` — consulta una blacklist de IPs.
  - `DetectorPorReglas` — aplica reglas estáticas (umbral de amenaza, patrones en payload).
  - `DetectorHeuristico` — mantiene estado temporal para detectar ráfagas (anti-DDoS / scans).
- `Red` actúa como firewall y orquesta la cadena de detectores.
- `Simulador` orquesta la creación de detectores, genera tráfico de prueba y ofrece una interfaz simple en consola.
- Estadísticas de paquetes procesados, permitidos, bloqueados y corruptos.

---


##  Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/Enriquesoto300/NetGuardV2.git
cd NetGuardV2
```

2. (Opcional) Crea un entorno virtual y activa:

```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# Unix / macOS
source .venv/bin/activate
```

3. Instala dependencias (este proyecto usa solo la librería estándar, pero si añades extras listálos en `requirements.txt`):

```bash
pip install -r requirements.txt
```

---

##  Cómo ejecutar

Hay dos formas principales de ejecutar el simulador:

### 1) Ejecutar el script principal (CLI)

```bash
python netguard/simulador.py
```

Al iniciar verás la consola administrativa con opciones para simular paquetes, ráfagas y ver reportes.

### 2) Usar el ejemplo para automatizar pruebas

```bash
python examples/ejecucion_demo.py
```

> `ejecucion_demo.py` puede crear una instancia de `Simulador()` y llamar a `simular_rafaga(cantidad=15)` para ver una ejecución automática.

---

##  Detalle del diseño (POO y patrones)

A continuación se explica cómo el diseño del código ejemplifica principios de POO y patrones de diseño.

### Clases y responsabilidades

- `Paquete`:
  - **Responsabilidad:** Representar un paquete de red y validar su propia integridad con `validar()`.
  - **Principios POO:** Encapsulación (la validación es responsabilidad del propio objeto).

- `ErrorSimulacion`, `PaqueteCorruptoError`:
  - **Responsabilidad:** Proveer errores específicos del dominio para facilitar manejo y debugging.

- `DetectorBase` (clase abstracta):
  - **Responsabilidad:** Definir la interfaz que deben implementar todos los detectores (`analizar_paquete`).
  - **Principios:** Abstracción e interfaz clara.

- `DetectorReputacionIP`, `DetectorPorReglas`, `DetectorHeuristico`:
  - **Responsabilidad:** Implementaciones concretas de detección.
  - **Polimorfismo:** `Red` llama `analizar_paquete()` sin preocuparse por la implementación concreta.
  - `DetectorHeuristico` muestra uso de **estado interno** para análisis temporal.

- `Red`:
  - **Responsabilidad:** Mantener la lista de detectores, procesar paquetes y recolectar estadísticas.
  - **Patrón:** Chain of Responsibility — la red pasa el paquete por cada detector hasta que uno lo bloquea.
  - **Composición:** Contiene detectores en lugar de heredar de ellos.

- `Simulador`:
  - **Responsabilidad:** Construir la red y detectores (Inyección de Dependencias), generar tráfico de prueba y ofrecer CLI.

### Principios SOLID (resumen breve)

- **S** (Single Responsibility): Cada clase tiene una responsabilidad bien definida.
- **O** (Open/Closed): Se pueden añadir nuevos detectores sin modificar `Red`.
- **L** (Liskov): Los detectores concretos son sustituibles por `DetectorBase`.
- **I** (Interface Segregation): `DetectorBase` define una interfaz pequeña y clara.
- **D** (Dependency Inversion): `Red` depende de la abstracción `DetectorBase`, no de implementaciones concretas.





---

##  Ejemplos y salida esperada

### Ejemplo de uso interactivo (CLI)

Al ejecutar `python netguard/simulador.py`:

```
======================================================
  Bienvenido a la Consola de NetGuard v2 (Firewall)
======================================================

Opciones de Administrador:
  1. Simular 1 paquete aleatorio
  2. Simular ráfaga de 15 paquetes (incluye prueba de DDoS)
  3. Ver reporte de red
  4. Salir
Seleccione una opción:
```

Tras simular ráfaga verás líneas tipo:

```
Analizando paquete: [Paquete] Origen: 104.20.15.12 | Destino: 192.168.1.7 | Tipo: HTTP | Amenaza: 0
 [BLOQUEADO] Razón: IP de origen (104.20.15.12) está en la blacklist. (Detectado por: DetectorReputacionIP)
...
--- Ráfaga completada ---

---  Reporte de NetGuard v2 ---
  Paquetes Totales Procesados: 15
  Paquetes Permitidos: 9
  Paquetes Bloqueados: 5
  Paquetes Corruptos/Descartados: 1
----------------------------------
```

> Los valores exactos dependen de la generación aleatoria del tráfico.

---

##  Buenas prácticas aplicadas

- Uso de excepciones personalizadas para diferenciar errores del dominio.
- Validación interna de objetos (encapsulación).
- Dependencia hacia abstracciones (`DetectorBase`) para permitir extensibilidad.
- Uso de estructuras eficientes (`set` para blacklist, `defaultdict(list)` para historial temporal).
- Comentarios y `__repr__` para facilitar trazabilidad y debug.

---

##  Pruebas sugeridas (pytest)

Crea tests unitarios para:

- Validación de `Paquete` (casos válidos y malformados).
- Comportamiento de `DetectorReputacionIP` con IP en blacklist y no en blacklist.
- Reglas de `DetectorPorReglas` (umbral, tipos maliciosos, detección de SQL_INJECTION).
- Lógica temporal de `DetectorHeuristico` (simular múltiples paquetes en ventana y verificar detección).
- Estadísticas de `Red` tras procesar paquetes mixtos.

Un ejemplo breve con `pytest`:

```python
from netguard.paquetes import Paquete
from netguard.detectores import DetectorReputacionIP

def test_detector_blacklist():
    detector = DetectorReputacionIP(ip_blacklist={"1.2.3.4"})
    paquete = Paquete(origen="1.2.3.4", destino="192.168.1.2", tipo="HTTP", datos="GET /", nivel_amenaza=0)
    assert detector.analizar_paquete(paquete)[0] is True
```


---


