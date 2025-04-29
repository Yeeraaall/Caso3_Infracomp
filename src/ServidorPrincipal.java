import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServidorPrincipal {

    private static final int PORT = 4000;
    private static final String DATA_DIR = "datos";
    private static final String SERVICES_FILE = "Servicios.txt";
    private static final String PRIVATE_KEY_FILE = "server_private.key";
    // Hacer servicios 'final' si no cambia después de la carga inicial
    private static final Map<String, String[]> servicios = new HashMap<>();
    private static final int MAX_CONNECTIONS = 64; // Número máximo de conexiones que el servidor procesará


    public static void main(String[] args) throws Exception {
        // Obtener la ruta completa utilizando File.separator
        Path serviciosPath = Paths.get(DATA_DIR, SERVICES_FILE);
        System.out.println("Ruta de Servicios.txt: " + serviciosPath.toAbsolutePath().toString());

        // Cargar tabla de servicios
        List<String> lines = Files.readAllLines(serviciosPath);
        for (String línea : lines) {
            if (línea.trim().isEmpty() || línea.startsWith("#"))
                continue; // Ignorar vacías o comentarios
            String[] partes = línea.split(",", 4);
            if (partes.length == 4) {
                servicios.put(partes[0], new String[] { partes[1], partes[2], partes[3] });
            } else {
                System.err.println("Línea mal formateada en Servicios.txt: " + línea);
            }
        }


        // Cargar llave privada RSA
        Path privateKeyPath = Paths.get(DATA_DIR, PRIVATE_KEY_FILE);
        PrivateKey serverPriv = null; // Inicializar a null

        try {
            // 1. Leer el archivo PEM como String
            String privateKeyPEMContent = Files.readString(privateKeyPath, StandardCharsets.UTF_8);

            String privateKeyPEM = privateKeyPEMContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("\\r\\n|\\r|\\n", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .trim(); // Eliminar espacios al inicio/final

            if (privateKeyPEM.isEmpty()) {
                throw new IOException("El contenido de la clave PEM está vacío después de limpiar cabeceras/pies.");
            }

            // 3. Decodificar Base64 para obtener los bytes DER
            byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

            // 4. Crear la especificación PKCS#8 y generar la llave
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyDER);
            KeyFactory kf = KeyFactory.getInstance("RSA"); // Asegúrate que la clave sea RSA
            serverPriv = kf.generatePrivate(spec);
            System.out.println("Llave privada RSA cargada correctamente desde PEM.");

        } catch (NoSuchFileException e) {
            System.err.println("Error Crítico: No se encontró el archivo de llave privada: " + e.getFile());
            System.exit(1); // Salir si no se encuentra la llave
        } catch (IOException | IllegalArgumentException | GeneralSecurityException e) {
            // IllegalArgumentException para errores de Base64
            // GeneralSecurityException para errores de KeyFactory/Spec
            System.err.println("Error Crítico al cargar o procesar la llave privada desde " + privateKeyPath);
            e.printStackTrace(); // Imprimir stack trace para depuración
            System.exit(1);
        }

        if (serverPriv == null) {
            System.err.println("Fallo crítico inesperado: La llave privada no se pudo cargar.");
            System.exit(1);
        }


        ServerSocket serverSocket = null;
        int connectionCount = 0;
        System.out.println("Servidor principal iniciando en puerto " + PORT);

        try {
            serverSocket = new ServerSocket(PORT);
            System.out.println("Servidor principal escuchando en puerto " + PORT);

            while (connectionCount < MAX_CONNECTIONS) {
                try {
                    Socket sock = serverSocket.accept(); // Aceptar conexiones DENTRO del bucle
                    System.out.println("------------------------------------------------------ ");
                    System.out.println("Nueva conexión de " + sock.getRemoteSocketAddress() + " (Conexión "
                            + (connectionCount + 1) + "/" + MAX_CONNECTIONS + ")");


                    ClienteHandler handler = new ClienteHandler(sock, serverPriv);
                    handler.start();

                    connectionCount++;

                } catch (IOException e) {

                    if (serverSocket.isClosed()) {
                        System.out.println("ServerSocket cerrado, deteniendo aceptación de nuevas conexiones.");
                        break;
                    }
                    System.err.println("Error aceptando conexión: " + e.getMessage());

                }
            }
        } catch (IOException e) {
            System.err.println("No se pudo iniciar el servidor en el puerto " + PORT + ": " + e.getMessage());
            e.printStackTrace(); // Imprimir stack trace para depuración
        } finally {
            System.out.println(
                    "Se alcanzó el límite de conexiones (" + connectionCount + ") o el servidor se está deteniendo.");
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                    System.out.println("ServerSocket cerrado.");
                } catch (IOException e) {
                    System.err.println("Error cerrando ServerSocket: " + e.getMessage());
                }
            }

            System.out.println("Servidor detenido después de procesar " + connectionCount + " conexiones.");
        }
    }

    // Manejador para cada cliente concurrente
    static class ClienteHandler extends Thread {
        private Socket sock;
        private PrivateKey serverPriv;

        // Variables para almacenar los tiempos
        private long tiempoFirmaDH = 0;
        private long tiempoCifrarTabla = 0;
        private long tiempoVerificarConsultaHMAC = 0; // Renombrado internamente para claridad

        // Helper para convertir bytes a Hexadecimal
        private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        public static String bytesToHex(byte[] bytes) {
            char[] hexChars = new char[bytes.length * 2];
            for (int j = 0; j < bytes.length; j++) {
                int v = bytes[j] & 0xFF;
                hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            }
            return new String(hexChars);
        }


        ClienteHandler(Socket s, PrivateKey pk) {
            this.sock = s;
            this.serverPriv = pk;
        }

        @Override
        public void run() {
            // Reiniciar tiempos para cada cliente
            tiempoFirmaDH = 0;
            tiempoCifrarTabla = 0;
            tiempoVerificarConsultaHMAC = 0;

            try (DataInputStream in = new DataInputStream(sock.getInputStream());
                 DataOutputStream out = new DataOutputStream(sock.getOutputStream())) {

                // 1) Handshake Diffie-Hellman + firma del public key
                AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
                paramGen.init(1024); // O usar un tamaño más moderno como 2048
                AlgorithmParameters params = paramGen.generateParameters();
                DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(dhSpec);
                KeyPair serverKP = kpg.generateKeyPair();

                // Firma del public key DH del servidor con la llave privada RSA del servidor
                byte[] pubS_DH = serverKP.getPublic().getEncoded();
                long tFirmaStart = System.nanoTime();
                byte[] sigS = ManejadorDeCifrado.generarFirma(serverPriv, pubS_DH);
                long tFirmaEnd = System.nanoTime();
                tiempoFirmaDH = tFirmaEnd - tFirmaStart; // Almacenar duración

                // Enviar: largo + publicKeyDH_Servidor + largo + firma_Servidor
                out.writeInt(pubS_DH.length);
                out.write(pubS_DH);
                out.writeInt(sigS.length);
                out.write(sigS);
                out.flush();

                // Quitado print intermedio de tiempo de firma

                // 2) Recibir public key DH del cliente
                int lenPubC = in.readInt();
                if (lenPubC > 10000 || lenPubC < 0) { // Validación básica de tamaño solucion bugg
                    throw new IOException("Tamaño inválido para la clave pública del cliente: " + lenPubC);
                }
                byte[] pubC_DH = new byte[lenPubC];
                in.readFully(pubC_DH);

                // Reconstruir la llave pública DH del cliente
                KeyFactory kf = KeyFactory.getInstance("DH");
                PublicKey clientPubDH = kf.generatePublic(new X509EncodedKeySpec(pubC_DH));

                // Derivar secreto compartido (Z)
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(serverKP.getPrivate());
                ka.doPhase(clientPubDH, true);
                byte[] z = ka.generateSecret();

                // Derivar K_enc y K_hmac de Z usando una KDF (Key Derivation Function)
                SecretKey[] keys = ManejadorDeCifrado.generarLlavesSimetricas(z); // Asume que esto usa HKDF o similar
                SecretKey kEnc = keys[0];
                SecretKey kHmac = keys[1];

                // 3) Serializar tabla de servicios
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, String[]> e : servicios.entrySet()) {
                    String id = e.getKey();
                    String[] v = e.getValue();
                    sb.append(id).append(",").append(v[0]).append(",").append(v[1]).append(",").append(v[2])
                            .append("\n");
                }

                if (sb.length() > 0) {
                    sb.setLength(sb.length() - 1); // Eliminar el último '\n'
                }
                byte[] plainTable = sb.toString().getBytes(StandardCharsets.UTF_8); // Usar StandardCharsets

                // 4) Cifrar tabla (AES)
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] ivBytes = new byte[cipher.getBlockSize()];
                SecureRandom rnd = SecureRandom.getInstanceStrong();
                rnd.nextBytes(ivBytes);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);

                cipher.init(Cipher.ENCRYPT_MODE, kEnc, iv);
                long tCifradoStart = System.nanoTime();
                byte[] cipherTable = cipher.doFinal(plainTable);
                long tCifradoEnd = System.nanoTime();
                tiempoCifrarTabla = tCifradoEnd - tCifradoStart; // Almacenar duración

                // Quitado print intermedio de tiempo de cifrado

                // 5) Calcular HMAC( IV_tabla || CIPHERTEXT_tabla )
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(kHmac);
                mac.update(ivBytes);
                mac.update(cipherTable);
                byte[] tableHmac = mac.doFinal();

                // --- IMPRIMIR INFORMACIÓN CIFRADA ENVIADA AL CLIENTE ---
                System.out.println("  [INFO] Datos cifrados de la tabla enviados al cliente:");
                System.out.println("    IV (Hex): " + bytesToHex(ivBytes));
                System.out.println("    Ciphertext (Base64): " + Base64.getEncoder().encodeToString(cipherTable));
                System.out.println("    HMAC (Hex): " + bytesToHex(tableHmac));
                // --- FIN IMPRESIÓN ---

                // Enviar tabla cifrada y autenticada al cliente:
                out.writeInt(ivBytes.length);
                out.write(ivBytes);
                out.writeInt(cipherTable.length);
                out.write(cipherTable);
                out.writeInt(tableHmac.length);
                out.write(tableHmac);
                out.flush();

                // 6) Esperar petición cifrada del cliente
                int ivReqLen = in.readInt();
                if (ivReqLen != 16) { // Asumiendo bloque AES de 128 bits
                    throw new IOException("Tamaño de IV de petición inválido: " + ivReqLen);
                }
                byte[] ivReq = new byte[ivReqLen];
                in.readFully(ivReq);

                int cReqLen = in.readInt();
                if (cReqLen > 2048 || cReqLen <= 0) { // Validación más estricta
                    throw new IOException("Tamaño de petición cifrada inválido: " + cReqLen);
                }
                byte[] cReq = new byte[cReqLen];
                in.readFully(cReq);

                int hReqLen = in.readInt();
                if (hReqLen != 32) { // SHA256 produce 32 bytes
                    throw new IOException("Tamaño de HMAC de petición inválido: " + hReqLen);
                }
                byte[] hReqRcvd = new byte[hReqLen];
                in.readFully(hReqRcvd);


                // 7) Verificar HMAC de la petición: HMAC( IV_req || CIPHER_req )
                mac.reset(); // Reutilizar el objeto Mac inicializado con kHmac
                mac.update(ivReq);
                mac.update(cReq);
                long tHmacStart = System.nanoTime();
                byte[] hReqCalc = mac.doFinal();
                long tHmacEnd = System.nanoTime();
                tiempoVerificarConsultaHMAC = tHmacEnd - tHmacStart; // Almacenar duración

                // Quitado print intermedio de tiempo de verificación HMAC

                if (!MessageDigest.isEqual(hReqRcvd, hReqCalc)) {
                    System.err.println(
                            "HMAC de petición inválido de " + sock.getRemoteSocketAddress() + ". Cerrando conexión.");
                    // IMPORTANTE: Salir aquí, pero el bloque finally se ejecutará para imprimir tiempos
                    return;
                }

                // 8) Descifrar petición y extraer serviceId
                cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(ivReq)); // Reusar instancia Cipher
                byte[] plainRequestBytes = cipher.doFinal(cReq);
                String serviceId = new String(plainRequestBytes, StandardCharsets.UTF_8).trim(); // Usar StandardCharsets

                System.out.println("Solicitud descifrada de " + sock.getRemoteSocketAddress() + " para servicio: '"
                        + serviceId + "'");

                // 9) Delegar consulta al servidor correspondiente (conexión plana)
                String[] info = servicios.get(serviceId); // Usar get(), no getOrDefault para detectar servicio inválido
                String respuesta = null;

                if (info == null) {
                    System.err.println("Servicio solicitado '" + serviceId + "' no encontrado para "
                            + sock.getRemoteSocketAddress());
                    respuesta = "ERROR: Servicio '" + serviceId + "' no encontrado.";
                } else {
                    String ipDelegado = info[1];
                    int portDelegado = -1;
                    try {
                        portDelegado = Integer.parseInt(info[2]);
                        if (portDelegado <= 0 || portDelegado > 65535)
                            throw new NumberFormatException("Puerto fuera de rango: " + info[2]);
                    } catch (NumberFormatException nfe) {
                        System.err.println("Puerto inválido para servicio '" + serviceId + "': " + info[2]);
                        respuesta = "ERROR: Configuración interna del servidor inválida para el servicio.";
                        portDelegado = -1; // Marcar como inválido
                    }

                    if (portDelegado != -1) {
                        System.out.println("  Delegando consulta para '" + serviceId + "' a " + ipDelegado + ":" + portDelegado);
                        try (Socket del = new Socket()) {
                            // Establecer timeouts de conexión y lectura
                            del.connect(new InetSocketAddress(ipDelegado, portDelegado), 5000); // Timeout de conexión 5 seg
                            del.setSoTimeout(10000); // Timeout de lectura 10 seg

                            try (DataOutputStream dout = new DataOutputStream(del.getOutputStream());
                                 DataInputStream din = new DataInputStream(del.getInputStream())) {

                                dout.writeUTF(serviceId); // Enviar solo el ID del servicio
                                dout.flush();
                                respuesta = din.readUTF(); // Leer respuesta del servidor delegado
                                System.out.println("  Respuesta recibida del servidor delegado: " + respuesta);
                            }

                        } catch (UnknownHostException uhe) {
                            System.err.println("Error delegando a " + ipDelegado + ": Host desconocido.");
                            respuesta = "ERROR: El servidor de consulta para '" + serviceId
                                    + "' no está disponible (host inválido).";
                        } catch (SocketTimeoutException ste) {
                            System.err.println("Error delegando a " + ipDelegado + ":" + portDelegado + ": Timeout.");
                            respuesta = "ERROR: El servidor de consulta para '" + serviceId
                                    + "' no respondió a tiempo.";
                        } catch (ConnectException ce) {
                            System.err.println("Error conectando a " + ipDelegado + ":" + portDelegado + ": " + ce.getMessage());
                             respuesta = "ERROR: No se pudo conectar con el servidor de consulta para '" + serviceId
                                    + "'. Verifique que esté activo.";
                        } catch (IOException ioe) {
                            System.err.println("Error de I/O delegando a " + ipDelegado + ":" + portDelegado + ": "
                                    + ioe.getMessage());
                            respuesta = "ERROR: Problema de comunicación con el servidor de consulta para '" + serviceId
                                    + "'.";
                            ioe.printStackTrace(); // Para más detalles en log
                        }
                    }

                }

                // 10) Enviar respuesta cifrada al cliente original
                byte[] ivRespBytes = new byte[cipher.getBlockSize()];
                rnd.nextBytes(ivRespBytes);
                IvParameterSpec ivResp = new IvParameterSpec(ivRespBytes);

                cipher.init(Cipher.ENCRYPT_MODE, kEnc, ivResp); // Reusar Cipher en modo cifrado
                byte[] cResp = cipher.doFinal(respuesta.getBytes(StandardCharsets.UTF_8)); // Usar StandardCharsets

                // Calcular HMAC para la respuesta: HMAC( IV_resp || CIPHER_resp )
                mac.reset(); // Reutilizar Mac
                mac.update(ivRespBytes);
                mac.update(cResp);
                byte[] hResp = mac.doFinal();

                out.writeInt(ivRespBytes.length);
                out.write(ivRespBytes);
                out.writeInt(cResp.length);
                out.write(cResp);
                out.writeInt(hResp.length);
                out.write(hResp);
                out.flush();

                System.out.println("Respuesta cifrada enviada a " + sock.getRemoteSocketAddress());

            } catch (EOFException e) {
                System.err.println("Cliente " + sock.getRemoteSocketAddress() + " cerró la conexión inesperadamente.");
                // No imprimir stack trace completo para EOF normal
            } catch (IOException e) {
                System.err.println(
                        "Error de I/O con el cliente " + sock.getRemoteSocketAddress() + ": " + e.getMessage());
                e.printStackTrace(); // Imprimir para depuración de IOErrors

            } catch (GeneralSecurityException e) {
                System.err.println(
                        "Error de seguridad con el cliente " + sock.getRemoteSocketAddress() + ": " + e.getMessage());
                e.printStackTrace(); // Imprimir para depuración de errores criptográficos

            } catch (Exception e) {
                System.err.println(
                        "Error inesperado procesando cliente " + sock.getRemoteSocketAddress() + ": " + e.getMessage());
                e.printStackTrace(); // Imprimir para cualquier otro error inesperado
            } finally {
                // --- IMPRIMIR TIEMPOS TOTALES ---
                System.out.println("----------- Tiempos totales de ejecución ----------");
                System.out.printf("[CIFRA TIEMPO] firma DH: %,d ns%n", tiempoFirmaDH);
                System.out.printf("[CIFRA TIEMPO] Cifrar la tabla: %,d ns%n", tiempoCifrarTabla);
                // Usamos la etiqueta solicitada por el usuario, aunque internamente sea verificación HMAC
                System.out.printf("[CIFRA TIEMPO] Verificar consulta DH: %,d ns%n", tiempoVerificarConsultaHMAC);
                System.out.println("------------------------------------------------------ "); // Separador final

                // El try-with-resources cerrará los streams y el socket asociado automáticamente.
                // No es necesario un sock.close() explícito aquí si los streams se abrieron bien.
                 if (sock != null && !sock.isClosed()) {
                     try {
                         sock.close();
                         //System.out.println("Socket cerrado explícitamente para " + sock.getRemoteSocketAddress());
                     } catch (IOException e) {
                         // Ignorar errores al cerrar si ya hay otros problemas
                     }
                 }
            }
        } // Fin del método run()
    } // Fin de la clase ClienteHandler


    // --- Clase ManejadorDeCifrado sin cambios ---
    static class ManejadorDeCifrado {
        public static PrivateKey generarLlavePrivadaFromBytes(byte[] keyBytes)
                throws GeneralSecurityException, IOException {

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }

        public static PublicKey generarLlavePublica(String base64Key) throws GeneralSecurityException, IOException {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }

        public static byte[] generarFirma(PrivateKey signKey, byte[] dataToSign) throws GeneralSecurityException {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(signKey);
            sig.update(dataToSign);
            return sig.sign();
        }

        public static boolean validarFirma(PublicKey verifyKey, byte[] data, byte[] signature)
                throws GeneralSecurityException {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(verifyKey);
            sig.update(data);
            return sig.verify(signature);
        }

        public static SecretKey[] generarLlavesSimetricas(byte[] sharedSecretZ) throws GeneralSecurityException {

            // Usar HKDF sería más robusto, pero SHA-256 directo como KDF simple:
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] derivedKeyMaterial = sha256.digest(sharedSecretZ);

            // Dividir el material derivado para K_enc (AES-128) y K_hmac (HMAC-SHA256)
            // AES-128 necesita 16 bytes, HMAC-SHA256 idealmente 32 bytes (o más)
            if (derivedKeyMaterial.length < 32) {
                throw new GeneralSecurityException("Secreto compartido DH demasiado corto para derivar llaves (necesita 32 bytes)");
            }

            byte[] keyEncBytes = Arrays.copyOfRange(derivedKeyMaterial, 0, 16); // Primeros 16 bytes para AES-128
            byte[] keyHmacBytes = Arrays.copyOfRange(derivedKeyMaterial, 16, 32); // Siguientes 16 (o 32) bytes para HMAC-SHA256

            SecretKey kEnc = new SecretKeySpec(keyEncBytes, "AES");
            SecretKey kHmac = new SecretKeySpec(keyHmacBytes, "HmacSHA256");

            // Limpieza de arrays intermedios (buena práctica)
            Arrays.fill(derivedKeyMaterial, (byte) 0);
            Arrays.fill(keyEncBytes, (byte) 0);
            Arrays.fill(keyHmacBytes, (byte) 0);

            return new SecretKey[] { kEnc, kHmac };
        }
    }
}