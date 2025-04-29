import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*; // Para MessageDigest.isEqual

public class Cliente {

    private static final String DATA_DIR = "datos";
    private static final String SERVER_PUBLIC_KEY_FILE = "server_public.key"; // Llave pública RSA del servidor
    private static final String HOST = "localhost";
    private static final int PORT = 4000;

    public static void main(String[] args) {
        PublicKey serverPubRSA = null;
        try {
            // 1) Cargar llave pública RSA del servidor desde datos/server_public.key
            Path pubKeyPath = Paths.get(DATA_DIR, SERVER_PUBLIC_KEY_FILE);
            // Leer como String Base64 y decodificar, o leer bytes directamente si no es
            // Base64
            String spk_base64 = new String(Files.readAllBytes(pubKeyPath), "UTF-8").trim();
            serverPubRSA = ManejadorDeCifrado.generarLlavePublica(spk_base64); // Usar método de ManejadorDeCifrado
            System.out.println("Llave pública RSA del servidor cargada.");

        } catch (NoSuchFileException e) {
            System.err.println("Error: No se encontró el archivo de llave pública del servidor: " + e.getFile());
            return;
        } catch (IOException e) {
            System.err.println("Error leyendo la llave pública del servidor: " + e.getMessage());
            return;
        } catch (GeneralSecurityException e) {
            System.err.println("Error de seguridad procesando la llave pública del servidor: " + e.getMessage());
            return;
        } catch (Exception e) {
            System.err.println("Error inesperado cargando llave pública: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Menú para elegir el escenario
        Scanner scanner = new Scanner(System.in);
        System.out.println("---------------------------------- Bienvenidx -----------------------------");
        System.out.println("Selecciona el escenario:");
        System.out.println("1. Un servidor de consulta y un cliente iterativo (1 consulta)");
        System.out.println("2. Un servidor de consulta y un cliente iterativo (32 consultas secuenciales)");
        System.out.println("3. Servidor y clientes concurrentes (N clientes)");
        System.out.print("Opción (1, 2 o 3): ");

        int opcion = 0;
        try {
            opcion = Integer.parseInt(scanner.nextLine().trim());
        } catch (NumberFormatException e) {
            System.out.println("Entrada inválida. Debe ser un número.");
            scanner.close();
            return;
        }

        try {
            if (opcion == 1) {
                System.out.print("Ingrese el servicio a consultar (S1, S2, S3): ");
                String serviceId = scanner.nextLine().trim();
                if (serviceId.isEmpty()) {
                    System.out.println("ID de servicio no puede estar vacío.");
                } else {
                    realizarConsultaUnica(serviceId, serverPubRSA);
                }
            } else if (opcion == 2) {
                ejecutarEscenario1(serverPubRSA, 32); // 32 sequential
            } else if (opcion == 3) {
                System.out.print("Ingrese el número de clientes concurrentes (e.g., 4, 16, 32, 64): ");
                int numClientes = 0;
                try {
                    numClientes = Integer.parseInt(scanner.nextLine().trim());
                    if (numClientes <= 0)
                        throw new NumberFormatException();
                } catch (NumberFormatException e) {
                    System.out.println("Número de clientes inválido.");
                }
                if (numClientes > 0) {
                    ejecutarEscenario2(serverPubRSA, numClientes); // Concurrent
                }
            } else {
                System.out.println("Opción no válida.");
            }
        } catch (Exception e) {
            // Captura errores generales que puedan ocurrir en los escenarios
            System.err.println("Ocurrió un error durante la ejecución del escenario: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
            System.out.println("Cliente terminado.");
        }
    }

    // Método para UNA consulta única
    private static void realizarConsultaUnica(String serviceId, PublicKey serverPubRSA) {
        System.out.println("\n--- Ejecutando Consulta Única para: " + serviceId + " ---");
        long tiempoInicio = System.nanoTime();
        // Usar try-with-resources para la conexión
        try (Socket sock = new Socket()) {
            // Conectar con timeout
            sock.connect(new InetSocketAddress(HOST, PORT), 5000); // Timeout de 5 seg para conectar
            sock.setSoTimeout(10000); // Timeout de 10 seg para lecturas

            try (DataInputStream in = new DataInputStream(sock.getInputStream());
                    DataOutputStream out = new DataOutputStream(sock.getOutputStream())) {

                // Llamar al método que maneja la comunicación segura
                enviarSolicitud(in, out, serviceId, serverPubRSA);

            } // Streams se cierran aquí
        } catch (ConnectException ce) {
            System.err.println("Error de conexión: El servidor en " + HOST + ":" + PORT
                    + " no está disponible o rechazó la conexión.");
        } catch (SocketTimeoutException ste) {
            System.err.println("Error: Timeout durante la comunicación con el servidor.");
        } catch (EOFException eofe) {
            System.err.println("Error: El servidor cerró la conexión inesperadamente.");
        } catch (IOException ioe) {
            System.err.println("Error de I/O con el servidor: " + ioe.getMessage());
        } catch (GeneralSecurityException gse) {
            System.err.println("Error de seguridad durante la comunicación: " + gse.getMessage());
        } catch (Exception e) {
            System.err.println("Error inesperado en consulta única para " + serviceId + ": " + e.getMessage());
            e.printStackTrace(); // Para debug
        } finally {
            long tiempoFin = System.nanoTime();
            System.out.printf("--- Consulta Única completada en %.2f ms ---%n",
                    (tiempoFin - tiempoInicio) / 1_000_000.0);
        }
    }

    // Método para ejecutar el Escenario 1: Cliente iterativo con N consultas
    // secuenciales
    private static void ejecutarEscenario1(PublicKey serverPubRSA, int numConsultas) {
        System.out.println("\n--- Ejecutando Escenario 1: " + numConsultas + " consultas secuenciales ---");
        long tiempoTotalInicio = System.nanoTime();
        int consultasExitosas = 0;

        for (int i = 0; i < numConsultas; i++) {
            // Selección de servicio (ciclico S1, S2, S3)
            String serviceId = "S" + (i % 3 + 1);
            System.out.println("\n--- Consulta " + (i + 1) + "/" + numConsultas + " para " + serviceId + " ---");
            long tiempoConsultaInicio = System.nanoTime();

            // Crear una nueva conexión para cada request
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(HOST, PORT), 5000); // Timeout conexión
                socket.setSoTimeout(10000); // Timeout lectura

                try (DataInputStream newIn = new DataInputStream(socket.getInputStream());
                        DataOutputStream newOut = new DataOutputStream(socket.getOutputStream())) {

                    enviarSolicitud(newIn, newOut, serviceId, serverPubRSA);
                    consultasExitosas++;

                } // Streams cerrados aquí
            } catch (ConnectException ce) {
                System.err
                        .println("Error de conexión en consulta " + (i + 1) + ": Servidor no disponible. Deteniendo.");
                break; // Detener si el servidor no responde
            } catch (SocketTimeoutException ste) {
                System.err.println("Error: Timeout en consulta " + (i + 1) + ".");
            } catch (EOFException eofe) {
                System.err.println("Error: El servidor cerró la conexión inesperadamente en consulta " + (i + 1) + ".");
            } catch (IOException ioe) {
                System.err.println(
                        "Error de I/O en consulta " + (i + 1) + " para " + serviceId + ": " + ioe.getMessage());
            } catch (GeneralSecurityException gse) {
                System.err.println("Error de seguridad en consulta " + (i + 1) + ": " + gse.getMessage());
            } catch (Exception e) {
                System.err.println(
                        "Error inesperado en consulta " + (i + 1) + " para " + serviceId + ": " + e.getMessage());
                e.printStackTrace(); // Para debug
            } finally {
                long tiempoConsultaFin = System.nanoTime();
                System.out.printf("--- Consulta %d completada en %.2f ms ---%n", (i + 1),
                        (tiempoConsultaFin - tiempoConsultaInicio) / 1_000_000.0);
            }
        } // Fin del bucle for

        long tiempoTotalFin = System.nanoTime();
        System.out.printf("\n--- Escenario 1 completado. Consultas exitosas: %d/%d. Tiempo total: %.2f ms ---%n",
                consultasExitosas, numConsultas, (tiempoTotalFin - tiempoTotalInicio) / 1_000_000.0);
    }

    // Método para ejecutar el Escenario 2: Servidor y N clientes concurrentes
    private static void ejecutarEscenario2(PublicKey serverPubRSA, int numClientes) {
        System.out.println("\n--- Ejecutando Escenario 2: " + numClientes + " clientes concurrentes ---");
        List<Thread> threads = new ArrayList<>();
        // Contador atómico para rastrear éxitos/fallos si es necesario
        // java.util.concurrent.atomic.AtomicInteger exitos = new
        // java.util.concurrent.atomic.AtomicInteger(0);
        // java.util.concurrent.atomic.AtomicInteger fallos = new
        // java.util.concurrent.atomic.AtomicInteger(0);
        long tiempoTotalInicio = System.nanoTime();

        for (int i = 0; i < numClientes; i++) {
            final int clientId = i; // Necesario para usar dentro del lambda
            Thread thread = new Thread(() -> {
                long tiempoHiloInicio = System.nanoTime();
                String serviceId = "S" + (int) (Math.random() * 3 + 1); // Servicio aleatorio
                // System.out.println("[Cliente " + clientId + "] Iniciando consulta para: " +
                // serviceId);

                // Crear un nuevo socket para cada hilo dentro del try-with-resources
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(HOST, PORT), 5000); // Timeout conexión
                    socket.setSoTimeout(10000); // Timeout lectura

                    try (DataInputStream newIn = new DataInputStream(socket.getInputStream());
                            DataOutputStream newOut = new DataOutputStream(socket.getOutputStream())) {

                        // System.out.println("[Cliente " + clientId + "] Conectado. Enviando solicitud
                        // para: " + serviceId);
                        enviarSolicitud(newIn, newOut, serviceId, serverPubRSA);
                        // exitos.incrementAndGet(); // Incrementar éxitos si se completa sin excepción
                        // System.out.println("[Cliente " + clientId + "] Consulta para " + serviceId +
                        // " completada.");

                    } // Streams cerrados aquí

                } catch (ConnectException ce) {
                    System.err.println("[Cliente " + clientId + "] Error de conexión: Servidor no disponible.");
                    // fallos.incrementAndGet();
                } catch (SocketTimeoutException ste) {
                    System.err.println("[Cliente " + clientId + "] Error: Timeout.");
                    // fallos.incrementAndGet();
                } catch (EOFException eofe) {
                    System.err.println(
                            "[Cliente " + clientId + "] Error: El servidor cerró la conexión inesperadamente.");
                    // fallos.incrementAndGet();
                } catch (IOException ioe) {
                    System.err.println("[Cliente " + clientId + "] Error de I/O: " + ioe.getMessage());
                    // fallos.incrementAndGet();
                } catch (GeneralSecurityException gse) {
                    System.err.println("[Cliente " + clientId + "] Error de seguridad: " + gse.getMessage());
                    // fallos.incrementAndGet();
                } catch (Exception e) {
                    System.err.println("[Cliente " + clientId + "] Error inesperado: " + e.getMessage());
                    e.printStackTrace(); // Para debug
                    // fallos.incrementAndGet();
                } finally {
                    long tiempoHiloFin = System.nanoTime();
                    // System.out.printf("[Cliente %d] Hilo terminado en %.2f ms%n", clientId,
                    // (tiempoHiloFin - tiempoHiloInicio) / 1_000_000.0);
                }
            }); // Fin del lambda del thread
            threads.add(thread);
            thread.start(); // Iniciar el hilo
        } // Fin del bucle for para crear hilos

        // Esperar a que todos los hilos terminen usando join()
        System.out.println("Esperando a que los " + numClientes + " hilos terminen...");
        for (Thread t : threads) {
            try {
                t.join(); // Esperar a que este hilo termine
            } catch (InterruptedException e) {
                System.err.println("Hilo principal interrumpido mientras esperaba. Continuando...");
                Thread.currentThread().interrupt(); // Restaurar estado de interrupción
            }
        }

        long tiempoTotalFin = System.nanoTime();
        System.out.printf("\n--- Escenario 2 completado. %d clientes concurrentes. Tiempo total: %.2f ms ---%n",
                numClientes, (tiempoTotalFin - tiempoTotalInicio) / 1_000_000.0);
        // System.out.printf(" Resultados: %d éxitos, %d fallos%n", exitos.get(),
        // fallos.get());

    }

    /**
     * Maneja una interacción completa y segura con el servidor:
     * 1. Recibe la clave pública DH firmada del servidor y la verifica.
     * 2. Genera su propia clave DH y la envía.
     * 3. Deriva las claves simétricas (AES, HMAC).
     * 4. Recibe la tabla de servicios cifrada/autenticada del servidor y la
     * verifica.
     * 5. Envía la solicitud de servicio cifrada/autenticada.
     * 6. Recibe la respuesta cifrada/autenticada y la verifica/descifra.
     *
     * @param in           DataInputStream conectado al servidor.
     * @param out          DataOutputStream conectado al servidor.
     * @param serviceId    El ID del servicio a solicitar.
     * @param serverPubRSA La clave pública RSA del servidor para verificar firmas.
     * @throws IOException              Si ocurren errores de red.
     * @throws GeneralSecurityException Si ocurren errores criptográficos.
     */
    private static void enviarSolicitud(DataInputStream in, DataOutputStream out, String serviceId,
            PublicKey serverPubRSA)
            throws IOException, GeneralSecurityException {

        // --- Handshake Diffie-Hellman Firmado ---

        // 3) Recibir public key DH + firma desde el servidor
        int lenPubS_DH = in.readInt();
        if (lenPubS_DH > 10000 || lenPubS_DH <= 0)
            throw new IOException("Tamaño llave DH servidor inválido: " + lenPubS_DH);
        byte[] pubS_DH_bytes = new byte[lenPubS_DH];
        in.readFully(pubS_DH_bytes);

        int lenSigS = in.readInt();
        if (lenSigS > 2048 || lenSigS <= 0)
            throw new IOException("Tamaño firma servidor inválido: " + lenSigS);
        byte[] sigS = new byte[lenSigS];
        in.readFully(sigS);

        // Verificar firma DH del servidor usando su llave pública RSA
        if (!ManejadorDeCifrado.validarFirma(serverPubRSA, pubS_DH_bytes, sigS)) {
            throw new SecurityException("Firma DH del servidor inválida. Abortando.");
        }
        // System.out.println("Firma DH del servidor verificada.");

        // 4) Generar nuestro par DH usando los mismos parámetros recibidos y enviar
        // public key
        KeyFactory kf_DH = KeyFactory.getInstance("DH");
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(pubS_DH_bytes);
        DHPublicKey serverPubDH = (DHPublicKey) kf_DH.generatePublic(xspec); // Llave pública DH del Servidor
        DHParameterSpec dhSpec = serverPubDH.getParams(); // Obtener parámetros DH del servidor

        KeyPairGenerator kpg_cliente = KeyPairGenerator.getInstance("DH");
        kpg_cliente.initialize(dhSpec); // Inicializar con los parámetros del servidor
        KeyPair clientKP_DH = kpg_cliente.generateKeyPair(); // Nuestro par de claves DH

        byte[] pubC_DH_bytes = clientKP_DH.getPublic().getEncoded(); // Nuestra clave pública DH
        out.writeInt(pubC_DH_bytes.length);
        out.write(pubC_DH_bytes);
        out.flush();
        // System.out.println("Llave pública DH del cliente enviada.");

        // 5) Derivar secreto compartido (Z) y llaves simétricas (K_enc, K_hmac)
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(clientKP_DH.getPrivate()); // Nuestra clave privada DH
        ka.doPhase(serverPubDH, true); // Con la clave pública DH del servidor
        byte[] z = ka.generateSecret();

        SecretKey[] keys = ManejadorDeCifrado.generarLlavesSimetricas(z); // Derivar AES y HMAC keys
        SecretKey kEnc = keys[0];
        SecretKey kHmac = keys[1];
        // System.out.println("Secreto compartido y llaves simétricas derivadas.");
        // z debe ser limpiado de memoria si es posible después de derivar las claves

        // --- Recepción y Verificación de la Tabla de Servicios ---

        // System.out.println("Esperando tabla de servicios cifrada del servidor...");
        int ivTableLen = in.readInt();
        if (ivTableLen != 16)
            throw new IOException("Tamaño IV tabla inválido: " + ivTableLen);
        byte[] ivTable = new byte[ivTableLen];
        in.readFully(ivTable);

        int cipherTableLen = in.readInt();
        if (cipherTableLen <= 0 || cipherTableLen > 65536)
            throw new IOException("Tamaño tabla cifrada inválido: " + cipherTableLen); // Ajustar límite
        byte[] cipherTable = new byte[cipherTableLen];
        in.readFully(cipherTable);

        int hmacTableLen = in.readInt();
        if (hmacTableLen != 32)
            throw new IOException("Tamaño HMAC tabla inválido: " + hmacTableLen);
        byte[] hmacTableRcvd = new byte[hmacTableLen];
        in.readFully(hmacTableRcvd);
        // System.out.println("Tabla cifrada recibida.");

        // Verificar HMAC de la tabla recibida: HMAC( IV_tabla || CIPHERTEXT_tabla )
        Mac mac = Mac.getInstance("HmacSHA256"); // Crear instancia MAC
        mac.init(kHmac);
        mac.update(ivTable);
        mac.update(cipherTable);
        byte[] hmacTableCalc = mac.doFinal();

        if (!MessageDigest.isEqual(hmacTableRcvd, hmacTableCalc)) { // Comparación segura
            throw new SecurityException("HMAC de la tabla de servicios inválido. Datos corruptos o manipulados.");
        }
        // System.out.println("HMAC de la tabla de servicios verificado.");
        // Opcional: Descifrar la tabla si el cliente la necesita
        // Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(ivTable));
        // String tablaServicios = new String(cipher.doFinal(cipherTable), "UTF-8");
        // System.out.println("Tabla de Servicios Descifrada:\n" + tablaServicios);

        // --- Envío de la Solicitud de Servicio ---

        // System.out.println("------------------------------------------------------ "
        // );
        // System.out.println("Servicio a solicitar (antes de cifrar): " + serviceId);
        SecureRandom rnd = SecureRandom.getInstanceStrong();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Crear instancia Cipher
        byte[] ivReq = new byte[cipher.getBlockSize()]; // IV para la petición
        rnd.nextBytes(ivReq);
        IvParameterSpec ivSpecReq = new IvParameterSpec(ivReq);

        // Cifrar el ID del servicio
        cipher.init(Cipher.ENCRYPT_MODE, kEnc, ivSpecReq);
        byte[] cReq = cipher.doFinal(serviceId.getBytes("UTF-8")); // Petición cifrada

        // Calcular HMAC para la petición: HMAC( IV_req || CIPHER_req )
        mac.reset(); // Reusar la instancia Mac inicializada con kHmac
        mac.update(ivReq);
        mac.update(cReq);
        byte[] hReq = mac.doFinal(); // HMAC de la petición

        // System.out.println("Petición cifrada (Base64): " +
        // Base64.getEncoder().encodeToString(cReq));
        // System.out.println("Enviando petición cifrada (IV + Cipher + HMAC)...");

        // Enviar petición cifrada y autenticada:
        // len(iv)‖iv‖len(cipher)‖cipher‖len(hmac)‖hmac
        out.writeInt(ivReq.length);
        out.write(ivReq);
        out.writeInt(cReq.length);
        out.write(cReq);
        out.writeInt(hReq.length); // Enviar longitud del HMAC
        out.write(hReq); // Enviar HMAC
        out.flush();
        // System.out.println("Petición enviada.");

        // --- Recepción y Verificación de la Respuesta ---

        // System.out.println("Esperando respuesta cifrada del servidor...");
        int ivRespLen = in.readInt();
        if (ivRespLen != 16)
            throw new IOException("Tamaño IV respuesta inválido: " + ivRespLen);
        byte[] ivResp = new byte[ivRespLen];
        in.readFully(ivResp);

        int cRespLen = in.readInt();
        if (cRespLen <= 0 || cRespLen > 65536 * 2)
            throw new IOException("Tamaño respuesta cifrada inválido: " + cRespLen); // Ajustar límite
        byte[] cResp = new byte[cRespLen];
        in.readFully(cResp);

        int hRespLen = in.readInt();
        if (hRespLen != 32)
            throw new IOException("Tamaño HMAC respuesta inválido: " + hRespLen);
        byte[] hRespRcvd = new byte[hRespLen];
        in.readFully(hRespRcvd);
        // System.out.println("Respuesta cifrada recibida.");

        // Verificar HMAC de la respuesta: HMAC( IV_resp || CIPHER_resp )
        mac.reset(); // Reusar MAC
        mac.update(ivResp);
        mac.update(cResp);
        byte[] hRespCalc = mac.doFinal();
        if (!MessageDigest.isEqual(hRespRcvd, hRespCalc)) { // Comparación segura
            throw new SecurityException("HMAC de la respuesta del servidor inválido.");
        }
        // System.out.println("HMAC de la respuesta verificado.");

        // Descifrar la respuesta
        cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(ivResp)); // Reusar Cipher
        byte[] plainRespBytes = cipher.doFinal(cResp);
        String respuesta = new String(plainRespBytes, "UTF-8");

        System.out.println("------------------------------------------------------ ");
        System.out.println("Respuesta final descifrada: " + respuesta);
        System.out.println("------------------------------------------------------ ");

        // Limpieza de claves simétricas si es posible/necesario
        // kEnc, kHmac, z (si aún existe referencia)

        // El cierre de streams/socket lo maneja el try-with-resources del método
        // llamador

    } // Fin de enviarSolicitud

    // Clase auxiliar (debe coincidir con la del servidor)
    static class ManejadorDeCifrado {
        public static PublicKey generarLlavePublica(String base64Key) throws GeneralSecurityException, IOException {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA"); // O el algoritmo que sea
            return kf.generatePublic(spec);
        }

        public static boolean validarFirma(PublicKey verifyKey, byte[] data, byte[] signature)
                throws GeneralSecurityException {
            Signature sig = Signature.getInstance("SHA256withRSA"); // Usar mismo algoritmo que el servidor
            sig.initVerify(verifyKey);
            sig.update(data);
            return sig.verify(signature);
        }

        public static SecretKey[] generarLlavesSimetricas(byte[] sharedSecretZ) throws GeneralSecurityException {
            // Usar misma KDF que el servidor
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] derivedKeyMaterial = sha256.digest(sharedSecretZ);

            byte[] keyEncBytes = Arrays.copyOfRange(derivedKeyMaterial, 0, 16); // AES-128
            byte[] keyHmacBytes = Arrays.copyOfRange(derivedKeyMaterial, 16, 32); // Para HMAC-SHA256

            SecretKey kEnc = new SecretKeySpec(keyEncBytes, "AES");
            SecretKey kHmac = new SecretKeySpec(keyHmacBytes, "HmacSHA256");

            // Limpiar arrays intermedios
            Arrays.fill(derivedKeyMaterial, (byte) 0);
            Arrays.fill(keyEncBytes, (byte) 0);
            Arrays.fill(keyHmacBytes, (byte) 0);

            return new SecretKey[] { kEnc, kHmac };
        }
    }

} // Fin de la clase Cliente