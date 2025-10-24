import random
import time
from abc import ABC, abstractmethod # Importamos ABC para clases abstractas
from collections import defaultdict

# --- 1. Excepciones Personalizadas ---
# Es una buena práctica definir tus propias excepciones
# para manejar errores específicos de tu dominio (la simulación).

class ErrorSimulacion(Exception):
    """Excepción base para cualquier error en la simulación."""
    pass

class PaqueteCorruptoError(ErrorSimulacion):
    """Se lanza cuando un paquete no tiene la estructura requerida."""
    def __init__(self, paquete, razon: str):
        super().__init__(f"Paquete corrupto detectado desde {paquete.origen}. Razón: {razon}")
        self.paquete_origen = paquete

# --- 2. Clase Paquete (Mejorada con Validación) ---

class Paquete:
    """
    Representa un paquete de red.
    Ahora incluye un método de validación.
    """
    def __init__(self, origen: str, destino: str, tipo: str, datos: str, nivel_amenaza: int):
        self.origen = origen
        self.destino = destino
        self.tipo = tipo
        self.datos = datos
        self.nivel_amenaza = nivel_amenaza

    def __repr__(self) -> str:
        return (f"[Paquete] Origen: {self.origen:<15} | Destino: {self.destino:<15} | "
                f"Tipo: {self.tipo:<10} | Amenaza: {self.nivel_amenaza}")

    def validar(self):
        """
        Método de encapsulación. Revisa su propio estado interno.
        """
        if not self.origen or not self.destino:
            raise PaqueteCorruptoError(self, "IP de origen o destino faltante")
        if self.tipo == "MALFORMADO":
            raise PaqueteCorruptoError(self, "Payload del paquete inválido")
        # Si todo está bien, no hace nada

# --- 3. La Familia de Detectores (Herencia y Polimorfismo) ---

class DetectorBase(ABC):
    """
    CLASE ABSTRACTA (Interfaz).
    Define el "contrato" que todos los detectores DEBEN seguir.
    No se puede instanciar (crear un objeto) de esta clase.
    """
    @abstractmethod
    def analizar_paquete(self, paquete: Paquete) -> (bool, str):
        """
        Analiza un paquete.
        Retorna (es_amenaza: bool, razon: str)
        """
        pass

    def __repr__(self) -> str:
        # Nos da un nombre legible para los reportes
        return self.__class__.__name__


class DetectorPorReglas(DetectorBase):
    """
    DETECTOR CONCRETO 1: El que ya teníamos.
    Implementa la interfaz 'DetectorBase'.
    """
    def __init__(self, nivel_sensibilidad: int = 5):
        self.nivel_sensibilidad = nivel_sensibilidad

    def analizar_paquete(self, paquete: Paquete) -> (bool, str):
        if paquete.nivel_amenaza >= self.nivel_sensibilidad:
            return (True, f"Nivel amenaza ({paquete.nivel_amenaza}) > umbral ({self.nivel_sensibilidad})")
        
        tipos_maliciosos = ["SCAN_PUERTOS", "DDoS", "MALWARE"]
        if paquete.tipo in tipos_maliciosos:
            return (True, f"Tipo de paquete sospechoso: {paquete.tipo}")

        if "SQL_INJECTION" in paquete.datos.upper():
            return (True, "Patrón de SQL Injection detectado")

        return (False, "Tráfico benigno (Reglas)")


class DetectorReputacionIP(DetectorBase):
    """
    DETECTOR CONCRETO 2: Revisa contra una "blacklist".
    Implementa la interfaz 'DetectorBase'.
    """
    def __init__(self, ip_blacklist: set):
        # Usamos un 'set' para búsquedas súper rápidas (O(1))
        self.ip_blacklist = ip_blacklist
        print(f"Detector de Reputación inicializado con {len(self.ip_blacklist)} IPs bloqueadas.")

    def analizar_paquete(self, paquete: Paquete) -> (bool, str):
        if paquete.origen in self.ip_blacklist:
            return (True, f"IP de origen ({paquete.origen}) está en la blacklist.")
        
        return (False, "IP de origen confiable")


class DetectorHeuristico(DetectorBase):
    """
    DETECTOR CONCRETO 3: Un detector con "estado".
    Busca comportamientos sospechosos a lo largo del tiempo.
    """
    def __init__(self, umbral_conexiones: int = 10, ventana_tiempo_seg: int = 5):
        # Almacena el historial de conexiones por IP
        # Ej: {'1.2.3.4': [timestamp1, timestamp2, ...]}
        self.trafico_reciente = defaultdict(list)
        self.umbral = umbral_conexiones
        self.ventana = ventana_tiempo_seg
        print("Detector Heurístico (Anti-DDoS/Scan) inicializado.")

    def analizar_paquete(self, paquete: Paquete) -> (bool, str):
        tiempo_actual = time.time()
        
        ip_origen = paquete.origen
        
        # 1. Limpiar historial viejo para esta IP
        # Mantenemos solo los timestamps dentro de la ventana de tiempo
        historial_ip = self.trafico_reciente[ip_origen]
        historial_valido = [t for t in historial_ip if tiempo_actual - t < self.ventana]
        
        # 2. Agregar el paquete actual al historial
        historial_valido.append(tiempo_actual)
        self.trafico_reciente[ip_origen] = historial_valido # <-- MANTIENE ESTADO INTERNO
        
        # 3. Analizar
        if len(historial_valido) > self.umbral:
            # Borramos el historial para esta IP para no reportarla mil veces
            self.trafico_reciente[ip_origen] = [] 
            return (True, f"Posible DDoS/Scan. {len(historial_valido)} paquetes en {self.ventana}s.")
            
        return (False, "Comportamiento de tráfico normal")


# --- 4. La Red (Firewall) con Cadena de Responsabilidad ---

class Red:
    """
    Simula la red y actúa como un Firewall.
    Utiliza COMPOSICIÓN para mantener una lista de detectores.
    Aplica el patrón "Chain of Responsibility" (Cadena de Responsabilidad).
    """
    def __init__(self):
        # La red "tiene" una lista de detectores.
        self.detectores: list[DetectorBase] = []
        self.paquetes_procesados = 0
        self.paquetes_bloqueados = 0
        self.paquetes_permitidos = 0
        self.paquetes_corruptos = 0
        print("Red virtual 'NetGuard v2' (Firewall en capas) está en línea.")

    def agregar_detector(self, detector: DetectorBase):
        """
        Inyección de Dependencia: La red recibe los detectores
        en lugar de crearlos ella misma.
        """
        # Verificamos que el objeto CUMPLE con la interfaz
        if isinstance(detector, DetectorBase):
            self.detectores.append(detector)
            print(f"Detector '{detector}' agregado a la cadena de seguridad.")
        else:
            print(f"Error: El objeto {detector} no es un 'DetectorBase' válido.")

    def procesar_paquete(self, paquete: Paquete):
        """
        Procesa un paquete, validándolo y pasándolo por la cadena
        de detectores en orden.
        """
        self.paquetes_procesados += 1
        
        try:
            # 1. Validación de sanidad (Encapsulación del paquete)
            paquete.validar()
            print(f"\nAnalizando paquete: {paquete}")
            
            # 2. Cadena de Responsabilidad (Polimorfismo)
            for detector in self.detectores:
                # <-- ¡POLIMORFISMO EN ACCIÓN! -->
                # La Red no sabe (ni le importa) qué TIPO de detector es.
                # Solo sabe que puede llamar a ".analizar_paquete()".
                es_amenaza, razon = detector.analizar_paquete(paquete)
                
                if es_amenaza:
                    self.paquetes_bloqueados += 1
                    print(f"🔴 [BLOQUEADO] Razón: {razon} (Detectado por: {detector})")
                    return # Si un detector lo bloquea, los siguientes no se ejecutan
            
            # 3. Si pasa todos los filtros
            self.paquetes_permitidos += 1
            print(f"🟢 [PERMITIDO] Razón: Pasó todos los {len(self.detectores)} filtros.")

        except PaqueteCorruptoError as e:
            # Manejo de nuestra excepción personalizada
            self.paquetes_corruptos += 1
            print(f"\n🟡 [DESCARTADO] Paquete corrupto. Error: {e}")
            
        finally:
            time.sleep(0.05) # Pausa para legibilidad

    def obtener_estadisticas(self) -> dict:
        return {
            "Total Procesados": self.paquetes_procesados,
            "Total Bloqueados": self.paquetes_bloqueados,
            "Total Permitidos": self.paquetes_permitidos,
            "Total Corruptos": self.paquetes_corruptos
        }

# --- 5. El Orquestador (Simulador) ---

class Simulador:
    """
    Crea todos los objetos (composición) y los "conecta".
    Gestiona el bucle principal.
    """
    def __init__(self):
        # 1. Definir nuestra configuración de seguridad
        blacklist_ips = {"104.20.15.12", "198.51.100.45"}
        
        # 2. Crear los "ladrillos" (los objetos)
        detector_ips = DetectorReputacionIP(ip_blacklist=blacklist_ips)
        detector_reglas = DetectorPorReglas(nivel_sensibilidad=5)
        detector_comportamiento = DetectorHeuristico(umbral_conexiones=5, ventana_tiempo_seg=10)
        
        # 3. Crear el objeto principal (la Red)
        self.red = Red()

        # 4. "Conectar" los ladrillos (Inyección de Dependencias)
        # El ORDEN importa. Es más eficiente chequear la blacklist
        # (muy rápido) antes que las reglas o la heurística (más lentos).
        self.red.agregar_detector(detector_ips)
        self.red.agregar_detector(detector_reglas)
        self.red.agregar_detector(detector_comportamiento)

        # Configuración para generar tráfico
        self._ips_simuladas = [f"192.168.1.{random.randint(2, 100)}" for _ in range(10)]
        self._ips_externas = [f"104.20.{random.randint(10, 50)}.{random.randint(1, 254)}" for _ in range(5)]
        # Añadimos una IP de la blacklist para probar
        self._ips_externas.append("104.20.15.12") 

    def _generar_paquete_aleatorio(self) -> Paquete:
        trafico_posible = [
            {"tipo": "HTTP", "datos": "GET /index.html", "amenaza": 0},
            {"tipo": "DNS", "datos": "Query: google.com", "amenaza": 0},
            {"tipo": "SCAN_PUERTOS", "datos": "NMAP -sS", "amenaza": 6},
            {"tipo": "HTTP", "datos": "GET /login.php?user=' OR '1'='1", "amenaza": 8},
            {"tipo": "MALFORMADO", "datos": "x@!#\0", "amenaza": 0}, # Paquete para probar excepción
        ]
        
        eleccion = random.choice(trafico_posible)
        origen = random.choice(self._ips_externas)
        destino = random.choice(self._ips_simuladas)

        return Paquete(
            origen=origen,
            destino=destino,
            tipo=eleccion["tipo"],
            datos=eleccion["datos"],
            nivel_amenaza=eleccion["amenaza"]
        )

    def simular_rafaga(self, cantidad: int):
        print(f"\n--- Iniciando ráfaga de {cantidad} paquetes ---")
        for i in range(cantidad):
            # Para probar el detector heurístico, simulamos un ataque
            if i > (cantidad - 5) and cantidad >= 10:
                print("... (Simulando ráfaga de ataque)...")
                paquete_nuevo = Paquete("8.8.4.4", "192.168.1.10", "DDoS", "SYN Flood", 7)
            else:
                paquete_nuevo = self._generar_paquete_aleatorio()
            
            self.red.procesar_paquete(paquete_nuevo)
            time.sleep(0.1)
        print("--- Ráfaga completada ---")

    def mostrar_reporte(self):
        stats = self.red.obtener_estadisticas()
        print("\n--- 📊 Reporte de NetGuard v2 ---")
        print(f"  Paquetes Totales Procesados: {stats['Total Procesados']}")
        print(f"  Paquetes Permitidos: {stats['Total Permitidos']}")
        print(f"  Paquetes Bloqueados: {stats['Total Bloqueados']}")
        print(f"  Paquetes Corruptos/Descartados: {stats['Total Corruptos']}")
        print("----------------------------------")

    def iniciar_interfaz_admin(self):
        print("======================================================")
        print("  Bienvenido a la Consola de NetGuard v2 (Firewall)  ")
        print("======================================================")
        
        while True:
            print("\nOpciones de Administrador:")
            print("  1. Simular 1 paquete aleatorio")
            print("  2. Simular ráfaga de 15 paquetes (incluye prueba de DDoS)")
            print("  3. Ver reporte de red")
            print("  4. Salir")
            opcion = input("Seleccione una opción: ")

            if opcion == '1':
                self.simular_rafaga(cantidad=1)
            elif opcion == '2':
                self.simular_rafaga(cantidad=15)
            elif opcion == '3':
                self.mostrar_reporte()
            elif opcion == '4':
                print("Cerrando NetGuard. La red ya no está monitoreada.")
                break
            else:
                print("Opción no válida. Intente de nuevo.")


# --- Punto de Entrada Principal ---
if __name__ == "__main__":
    simulador = Simulador()
    simulador.iniciar_interfaz_admin()