// Cliente.java
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.DHPublicKey;

public class Cliente {

    private static final String DATA_DIR               = "datos";
    private static final String SERVER_PUBLIC_KEY_FILE = "server_public.key";
    private static final String HOST                   = "localhost";
    private static final int    PORT                   = 4000;

    public static void main(String[] args) throws Exception {
        // 1) Cargar llave pública del servidor desde datos/server_public.key
        Path pubKeyPath = Paths.get(DATA_DIR, SERVER_PUBLIC_KEY_FILE);
        String spk = new String(Files.readAllBytes(pubKeyPath), "UTF-8").trim();
        PublicKey serverPub = ManejadorDeCifrado.generarLlavePublica(spk);

        // 2) Conectar al servidor principal
        Socket sock = new Socket(HOST, PORT);
        DataInputStream  in  = new DataInputStream(sock.getInputStream());
        DataOutputStream out = new DataOutputStream(sock.getOutputStream());

        //
        // 3) Recibir public key DH + firma desde el servidor
        //
        int lenPubS = in.readInt();
        byte[] pubS = new byte[lenPubS];
        in.readFully(pubS);

        int lenSigS = in.readInt();
        byte[] sigS = new byte[lenSigS];
        in.readFully(sigS);

        // Verificar firma DH
        if (!ManejadorDeCifrado.validarFirma(serverPub, pubS, sigS)) {
            System.err.println("Firma DH inválida. Abortando.");
            sock.close();
            return;
        }

        //
        // 4) Generar nuestro par DH usando los mismos parámetros y enviar public key
        //
        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(pubS);
        DHPublicKey dhPub = (DHPublicKey) kf.generatePublic(xspec);
        DHParameterSpec dhSpec = dhPub.getParams();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(dhSpec);
        KeyPair clientKP = kpg.generateKeyPair();

        byte[] pubC = clientKP.getPublic().getEncoded();
        out.writeInt(pubC.length);
        out.write(pubC);
        out.flush();

        // Derivar secreto compartido
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(clientKP.getPrivate());
        ka.doPhase(dhPub, true);
        byte[] z = ka.generateSecret();

        // Derivar claves AES/HMAC
        SecretKey[] keys = ManejadorDeCifrado.generarLlavesSimetricas(z);
        SecretKey kEnc  = keys[0];
        SecretKey kHmac = keys[1];

        //
        // 5) Recibir tabla cifrada y protegerla con HMAC
        //
        int ivLen = in.readInt();
        byte[] iv  = new byte[ivLen];
        in.readFully(iv);

        int cLen = in.readInt();
        byte[] cTab = new byte[cLen];
        in.readFully(cTab);

        int hLen = in.readInt();
        byte[] hTab = new byte[hLen];
        in.readFully(hTab);

        // Verificar HMAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(kHmac);
        mac.update(iv);
        mac.update(cTab);
        byte[] ourH = mac.doFinal();
        if (!MessageDigest.isEqual(hTab, ourH)) {
            System.err.println("HMAC de tabla inválido.");
            sock.close();
            return;
        }

        // Descifrar tabla
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(iv));
        String tabla = new String(cipher.doFinal(cTab), "UTF-8");
        System.out.println("Servicios disponibles:\n" + tabla);

        // 6) Selección de servicio
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Seleccione un servicio (por ID): ");
        String serviceId = reader.readLine().trim();

        //
        // 7) Enviar petición cifrada
        //
        System.out.println("Servicio seleccionado (antes de cifrar): " + serviceId);

        SecureRandom rnd = new SecureRandom();
        byte[] iv2 = new byte[16];
        rnd.nextBytes(iv2);
        cipher.init(Cipher.ENCRYPT_MODE, kEnc, new IvParameterSpec(iv2));
        byte[] cReq = cipher.doFinal(serviceId.getBytes("UTF-8"));

        System.out.println("Petición cifrada (Base64):");
        System.out.println(Base64.getEncoder().encodeToString(cReq));


        mac.reset();
        mac.init(kHmac);
        mac.update(iv2);
        mac.update(cReq);
        byte[] hReq = mac.doFinal();

        out.writeInt(iv2.length);
        out.write(iv2);
        out.writeInt(cReq.length);
        out.write(cReq);
        out.writeInt(hReq.length);
        out.write(hReq);
        out.flush();
        System.out.println("→ Petición enviada al servidor: " + serviceId);


        //
        // 8) Recibir y procesar la respuesta cifrada
        //
        int iv3Len = in.readInt();
        byte[] iv3 = new byte[iv3Len];
        in.readFully(iv3);

        int c3Len = in.readInt();
        byte[] c3   = new byte[c3Len];
        in.readFully(c3);

        int h3Len = in.readInt();
        byte[] h3   = new byte[h3Len];
        in.readFully(h3);

        mac.reset();
        mac.init(kHmac);
        mac.update(iv3);
        mac.update(c3);
        byte[] ourH3 = mac.doFinal();
        if (!MessageDigest.isEqual(h3, ourH3)) {
            System.err.println("HMAC de respuesta inválido.");
            sock.close();
            return;
        }

        System.out.println("Respuesta cifrada (Base64):");
        System.out.println(Base64.getEncoder().encodeToString(c3));


        cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(iv3));
        String respuesta = new String(cipher.doFinal(c3), "UTF-8");
   

        System.out.println("→ Respuesta del servicio (descifrada): " + respuesta);

        sock.close();
    }
}
