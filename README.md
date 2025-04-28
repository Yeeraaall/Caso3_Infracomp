# Caso3_Infracomp

# Ejecución del Programa de Consultas Cifradas

Este proyecto simula un sistema de consultas cifradas entre un cliente y un servidor, con diferentes modos de operación.

## Pasos para Ejecutar el Programa

1. **Ejecutar `DelegadoServidor.java`**  
   (Inicia el servidor delegado para manejar consultas).

2. **Ejecutar `ServidorPrincipal.java`**  
   (Inicia el servidor principal que procesará las solicitudes).

3. **Ejecutar `Cliente.java`**  
   (Inicia el cliente interactivo para realizar consultas).

---

## Escenarios Disponibles

Al ejecutar `Cliente.java`, se mostrará un menú para seleccionar entre:

### Escenario 1  
- **1 servidor de consulta + 1 cliente iterativo**  
- Realiza **1 consulta única** de forma secuencial.

### Escenario 2  
- **1 servidor de consulta + 1 cliente iterativo**  
- Realiza **32 consultas secuenciales** (simula carga secuencial).

### Escenario 3  
- **Servidor + Clientes Concurrentes**  
- Permite elegir entre **4, 16, 32 o 64 delegados concurrentes** (simula múltiples clientes en paralelo).

---

## Visualización de Resultados

Para ver las respuestas cifradas y métricas:  

- **Consola de `ServidorPrincipal`**:  
  - Muestra el intercambio de información (cifrada y en claro).  
  - Tiempos de operación (firma, cifrado de tablas y verificación).  

- **Consola de `Cliente`**:  
  - Respuestas descifradas del servidor.  
  - Peticiones cifradas y respuestas en claro.  



> **Nota**: Ejecutar los archivos **en el orden indicado** para el correcto funcionamiento del sistema.