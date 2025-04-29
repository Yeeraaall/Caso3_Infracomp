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

        ClienteHandler(Socket s, PrivateKey pk) {
            this.sock = s;
            this.serverPriv = pk;
        }

        @Override
        public void run() {
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

                // Enviar: largo + publicKeyDH_Servidor + largo + firma_Servidor
                out.writeInt(pubS_DH.length);
                out.write(pubS_DH);
                out.writeInt(sigS.length);
                out.write(sigS);
                out.flush();

                System.out.printf("  [Medida] Firma DH para %s: %,d ns%n", sock.getRemoteSocketAddress(),
                        (tFirmaEnd - tFirmaStart));

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
                    sb.setLength(sb.length() - 1);
                }
                byte[] plainTable = sb.toString().getBytes("UTF-8");

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


                System.out.printf("  [Medida] Cifrar tabla para %s: %,d ns%n", sock.getRemoteSocketAddress(),
                        (tCifradoEnd - tCifradoStart));

                // 5) Calcular HMAC( IV_tabla || CIPHERTEXT_tabla )
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(kHmac);
                mac.update(ivBytes); 
                mac.update(cipherTable); 
                byte[] tableHmac = mac.doFinal();

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
                if (ivReqLen != 16) { 
                    throw new IOException("Tamaño de IV de petición inválido: " + ivReqLen);
                }
                byte[] ivReq = new byte[ivReqLen];
                in.readFully(ivReq);

                int cReqLen = in.readInt();
                if (cReqLen > 2048 || cReqLen <= 0) {
                    throw new IOException("Tamaño de petición cifrada inválido: " + cReqLen);
                }
                byte[] cReq = new byte[cReqLen];
                in.readFully(cReq);

                int hReqLen = in.readInt();
                if (hReqLen != 32) {
                    throw new IOException("Tamaño de HMAC de petición inválido: " + hReqLen);
                }
                byte[] hReqRcvd = new byte[hReqLen];
                in.readFully(hReqRcvd);


                // 7) Verificar HMAC de la petición: HMAC( IV_req || CIPHER_req )
                mac.reset(); 
                mac.update(ivReq);
                mac.update(cReq);
                long tHmacStart = System.nanoTime();
                byte[] hReqCalc = mac.doFinal();
                long tHmacEnd = System.nanoTime();

                System.out.printf("  [Medida] Verificar HMAC petición para %s: %,d ns%n", sock.getRemoteSocketAddress(),
                        (tHmacEnd - tHmacStart));

                if (!MessageDigest.isEqual(hReqRcvd, hReqCalc)) {
                    System.err.println(
                            "HMAC de petición inválido de " + sock.getRemoteSocketAddress() + ". Cerrando conexión.");
                    return; 
                }

                // 8) Descifrar petición y extraer serviceId
                cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(ivReq)); // Reusar instancia Cipher
                byte[] plainRequestBytes = cipher.doFinal(cReq);
                String serviceId = new String(plainRequestBytes, "UTF-8").trim();

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
                            throw new NumberFormatException();
                    } catch (NumberFormatException nfe) {
                        System.err.println("Puerto inválido para servicio '" + serviceId + "': " + info[2]);
                        respuesta = "ERROR: Configuración interna del servidor inválida para el servicio.";
                        portDelegado = -1; // Marcar como inválido
                    }

                    if (portDelegado != -1) {
                        try (Socket del = new Socket()) {
                         
                            del.connect(new InetSocketAddress(ipDelegado, portDelegado), 5000); 
                                                                                                // seg
                            del.setSoTimeout(10000);

                            try (DataOutputStream dout = new DataOutputStream(del.getOutputStream());
                                    DataInputStream din = new DataInputStream(del.getInputStream())) {
                                
                            dout.writeUTF(serviceId); 
                            dout.flush();
                            respuesta = din.readUTF(); 

                            }


                        } catch (UnknownHostException uhe) {
                            System.err.println("Error delegando a " + ipDelegado + ": Host desconocido.");
                            respuesta = "ERROR: El servidor de consulta para '" + serviceId
                                    + "' no está disponible (host inválido).";
                        } catch (SocketTimeoutException ste) {
                            System.err.println("Error delegando a " + ipDelegado + ":" + portDelegado + ": Timeout.");
                            respuesta = "ERROR: El servidor de consulta para '" + serviceId
                                    + "' no respondió a tiempo.";
                        } catch (IOException ioe) {
                            System.err.println("Error de I/O delegando a " + ipDelegado + ":" + portDelegado + ": "
                                    + ioe.getMessage());
                            respuesta = "ERROR: No se pudo comunicar con el servidor de consulta para '" + serviceId
                                    + "'.";
                            
                        }
                    }
                   
                }

                // 10) Enviar respuesta cifrada al cliente original
                byte[] ivRespBytes = new byte[cipher.getBlockSize()];
                rnd.nextBytes(ivRespBytes);
                IvParameterSpec ivResp = new IvParameterSpec(ivRespBytes);

                cipher.init(Cipher.ENCRYPT_MODE, kEnc, ivResp); 
                byte[] cResp = cipher.doFinal(respuesta.getBytes("UTF-8"));

                // Calcular HMAC para la respuesta: HMAC
                mac.reset(); 
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


            } 
             catch (IOException e) {
                System.err.println(
                        "Error de I/O con el cliente " + sock.getRemoteSocketAddress() + ": " + e.getMessage());
                
            } catch (GeneralSecurityException e) {
                
                System.err.println(
                        "Error de seguridad con el cliente " + sock.getRemoteSocketAddress() + ": " + e.getMessage());
               
            } catch (Exception e) {
                
                System.err.println(
                        "Error inesperado procesando cliente " + sock.getRemoteSocketAddress() + ": " + e.getMessage());
                e.printStackTrace(); 
            } finally {
                
            }
        } 
    } 


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

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] derivedKeyMaterial = sha256.digest(sharedSecretZ); 

            byte[] keyEncBytes = Arrays.copyOfRange(derivedKeyMaterial, 0, 16); 
            byte[] keyHmacBytes = Arrays.copyOfRange(derivedKeyMaterial, 16, 32); 
                                                                                  
            SecretKey kEnc = new SecretKeySpec(keyEncBytes, "AES");
            SecretKey kHmac = new SecretKeySpec(keyHmacBytes, "HmacSHA256");

            Arrays.fill(derivedKeyMaterial, (byte) 0);
            Arrays.fill(keyEncBytes, (byte) 0);
            Arrays.fill(keyHmacBytes, (byte) 0);

            return new SecretKey[] { kEnc, kHmac };
        }
    }

}