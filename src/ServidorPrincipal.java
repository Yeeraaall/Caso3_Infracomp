// ServidorPrincipal.java
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

public class ServidorPrincipal {

    // Parámetros de socket
    private static final int PORT = 4000;

    // Nombre de archivos
    private static final String DATA_DIR   = "datos";
    private static final String SERVICES_FILE = "Servicios.txt";
    private static final String PRIVATE_KEY_FILE = "server_private.key";

    

    // Mapa de servicios: id → [descripción, IP, puerto]
    private static Map<String, String[]> servicios = new HashMap<>();

    public static void main(String[] args) throws Exception {

  // Obtener la ruta completa utilizando File.separator
  Path serviciosPath = Paths.get(DATA_DIR, SERVICES_FILE);
  System.out.println("Ruta de Servicios.txt: " + serviciosPath.toAbsolutePath().toString()); // Imprimir la ruta completa

  // Cargar tabla de servicios
  for (String línea : Files.readAllLines(serviciosPath)) {
      if (línea.trim().isEmpty()) continue;
      String[] partes = línea.split(",", 4);
      // partes = { id, descripción, ip, puerto }
      servicios.put(partes[0], new String[]{partes[1], partes[2], partes[3]});
  }

  // Cargar llave privada RSA
  Path privateKeyPath = Paths.get(DATA_DIR, PRIVATE_KEY_FILE);
  String pkcs8 = new String(Files.readAllBytes(privateKeyPath), "UTF-8").trim();
  PrivateKey serverPriv = ManejadorDeCifrado.generarLlavePrivada(pkcs8);

  ServerSocket serverSocket = new ServerSocket(PORT);
  System.out.println("Servidor principal escuchando en puerto " + PORT);

  while (true) {
      Socket sock = serverSocket.accept();
      System.out.println("→ Nueva conexión de " + sock.getRemoteSocketAddress());
      new ClienteHandler(sock, serverPriv).start();
  }

}

    static class ClienteHandler extends Thread {
        private Socket sock;
        private PrivateKey serverPriv;

        ClienteHandler(Socket s, PrivateKey pk) {
            this.sock = s;
            this.serverPriv = pk;
        }

        public void run() {
            try {
                DataInputStream  in  = new DataInputStream(sock.getInputStream());
                DataOutputStream out = new DataOutputStream(sock.getOutputStream());

                //
                // 1) — Handshake Diffie–Hellman + firma del public key
                //
                AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
                paramGen.init(1024);
                AlgorithmParameters    params   = paramGen.generateParameters();
                DHParameterSpec       dhSpec   = params.getParameterSpec(DHParameterSpec.class);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(dhSpec);
                KeyPair serverKP = kpg.generateKeyPair();

                // Firma del public key
                byte[] pubS = serverKP.getPublic().getEncoded();
                long tFirmaStart = System.nanoTime();
                byte[] sigS  = ManejadorDeCifrado.generarFirma(serverPriv, pubS);
                long tFirmaEnd   = System.nanoTime();

                // Enviar largo+publicKey + largo+firma
                out.writeInt(pubS.length);
                out.write(pubS);
                out.writeInt(sigS.length);
                out.write(sigS);
                out.flush();

                System.out.printf("  [Medida] firma DH: %,d ns%n", (tFirmaEnd - tFirmaStart));

                //
                // 2) — Recibir public key del cliente
                //
                int lenPubC = in.readInt();
                byte[] pubC = new byte[lenPubC];
                in.readFully(pubC);

                KeyFactory kf = KeyFactory.getInstance("DH");
                PublicKey clientPub = kf.generatePublic(new X509EncodedKeySpec(pubC));

                // Derivar secreto compartido
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(serverKP.getPrivate());
                ka.doPhase(clientPub, true);
                byte[] z = ka.generateSecret();

                // Derivar K_enc y K_hmac
                SecretKey[] keys = ManejadorDeCifrado.generarLlavesSimetricas(z);
                SecretKey kEnc  = keys[0];
                SecretKey kHmac = keys[1];

                //
                // 3) — Serializar tabla de servicios ("id,desc,ip,puerto\n")
                //
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String,String[]> e : servicios.entrySet()) {
                    String id = e.getKey();
                    String[] v = e.getValue();
                    sb.append(id).append(",").append(v[0]).append(",").append(v[1]).append(",").append(v[2]).append("\n");
                }
                byte[] plainTable = sb.toString().getBytes("UTF-8");

                //
                // 4) — Cifrar tabla
                //
                //  IV aleatorio
                byte[] ivBytes = new byte[16];
                SecureRandom rnd = new SecureRandom();
                rnd.nextBytes(ivBytes);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, kEnc, iv);
                long tCifradoStart = System.nanoTime();
                byte[] cipherTable = cipher.doFinal(plainTable);
                long tCifradoEnd   = System.nanoTime();

                System.out.printf("  [Medida] cifrar tabla: %,d ns%n", (tCifradoEnd - tCifradoStart));

                //
                // 5) — Calcular HMAC( IV ‖ CIPHER )
                //
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(kHmac);
                mac.update(ivBytes);
                mac.update(cipherTable);
                byte[] tableHmac = mac.doFinal();

                // Enviar: len(iv)‖iv‖len(cipher)‖cipher‖len(hmac)‖hmac
                out.writeInt(ivBytes.length);
                out.write(ivBytes);
                out.writeInt(cipherTable.length);
                out.write(cipherTable);
                out.writeInt(tableHmac.length);
                out.write(tableHmac);
                out.flush();

                //
                // 6) — Esperar petición cifrada del cliente
                //
                int ivReqLen = in.readInt();
                byte[] ivReq  = new byte[ivReqLen];
                in.readFully(ivReq);

                int cReqLen = in.readInt();
                byte[] cReq  = new byte[cReqLen];
                in.readFully(cReq);

                int hReqLen = in.readInt();
                byte[] hReq  = new byte[hReqLen];
                in.readFully(hReq);

                // 7) — Verificar HMAC de la petición
                mac.reset();
                mac.update(ivReq);
                mac.update(cReq);
                long tHmacStart = System.nanoTime();
                byte[] ourHreq = mac.doFinal();
                long tHmacEnd   = System.nanoTime();

                System.out.printf("  [Medida] verificar HMAC: %,d ns%n", (tHmacEnd - tHmacStart));

                if (!MessageDigest.isEqual(hReq, ourHreq)) {
                    System.err.println("  → HMAC inválido, cerrando conexión.");
                    sock.close();
                    return;
                }

                // 8) — Descifrar petición y extraer serviceId
                
                cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(ivReq));
                String serviceId = new String(cipher.doFinal(cReq), "UTF-8").trim();

                System.out.println("→ Solicitud recibida para servicio: " + serviceId); //depuración

                // 9) — Delegar consulta (conexión plana)
                String[] info = servicios.getOrDefault(serviceId, new String[]{"","-1","-1"});
                String ip   = info[1];
                int    port = Integer.parseInt(info[2]);
                String respuesta;
                try (Socket del = new Socket(ip, port);
                     DataOutputStream dout = new DataOutputStream(del.getOutputStream());
                     DataInputStream  din  = new DataInputStream(del.getInputStream()))
                {
                    dout.writeUTF(serviceId);
                    respuesta = din.readUTF();
                }

                // 10) — Enviar respuesta cifrada al cliente
                //     (misma rutina que antes)
                byte[] iv2Bytes = new byte[16];
                rnd.nextBytes(iv2Bytes);
                IvParameterSpec iv2 = new IvParameterSpec(iv2Bytes);

                cipher.init(Cipher.ENCRYPT_MODE, kEnc, iv2);
                byte[] cResp = cipher.doFinal(respuesta.getBytes("UTF-8"));

                mac.reset();
                mac.update(iv2Bytes);
                mac.update(cResp);
                byte[] hResp = mac.doFinal();

                out.writeInt(iv2Bytes.length);
                out.write(iv2Bytes);
                out.writeInt(cResp.length);
                out.write(cResp);
                out.writeInt(hResp.length);
                out.write(hResp);
                out.flush();

                sock.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
