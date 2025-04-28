import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.DHPublicKey;
import java.util.Scanner;
import java.util.Base64;

public class Cliente {

    private static final String DATA_DIR = "datos";
    private static final String SERVER_PUBLIC_KEY_FILE = "server_public.key";
    private static final String HOST = "localhost";
    private static final int PORT = 4000;
    private static SecretKey kEnc; // Clave para cifrado AES
    private static SecretKey kHmac; // Clave para HMAC

    public static void main(String[] args) throws Exception {
        // 1) Cargar llave pública del servidor desde datos/server_public.key
        Path pubKeyPath = Paths.get(DATA_DIR, SERVER_PUBLIC_KEY_FILE);
        String spk = new String(Files.readAllBytes(pubKeyPath), "UTF-8").trim();
        PublicKey serverPub = ManejadorDeCifrado.generarLlavePublica(spk);

        // Conectar al servidor principal
        Socket sock = new Socket(HOST, PORT);
        DataInputStream in = new DataInputStream(sock.getInputStream());
        DataOutputStream out = new DataOutputStream(sock.getOutputStream());

        // Menú para elegir el escenario
        Scanner scanner = new Scanner(System.in);
        System.out.println("Selecciona el escenario:");
        System.out.println("1. Un servidor de consulta y un cliente iterativo (1 consulta)");
        System.out.println("2. Un servidor de consulta y un cliente iterativo (32 consultas secuenciales)");
        System.out.println("3. Servidor y clientes concurrentes");
        System.out.print("Opción (1, 2 o 3): ");
        int opcion = scanner.nextInt();

        // Según la opción seleccionada, ejecutar el escenario adecuado
        if (opcion == 1) {
            // Ejecutar solo 1 consulta
            System.out.print("Ingrese el servicio a consultar (S1, S2, S3): ");
            String serviceId = scanner.next();
            enviarSolicitud(sock, in, out, serviceId);
        } else if (opcion == 2) {
            // Ejecutar 32 consultas secuenciales
            ejecutarEscenario1(sock, in, out);
        } else if (opcion == 3) {
            // Ejecutar escenario de clientes concurrentes
            ejecutarEscenario2(sock, in, out);
        } else {
            System.out.println("Opción no válida.");
        }

        sock.close();
        scanner.close();
    }

    // Método para ejecutar el Escenario 1: Cliente iterativo con 32 consultas secuenciales
    private static void ejecutarEscenario1(Socket sock, DataInputStream in, DataOutputStream out) throws Exception {
        System.out.println("\nEjecutando Escenario 1: 32 consultas secuenciales...");

        // Paso 3: Ejecutar 32 consultas secuenciales
        for (int i = 0; i < 32; i++) {
            // Selección aleatoria de servicio
            String serviceId = "S" + (i % 3 + 1); // Generar un ID de servicio aleatorio (S1, S2, S3)

            System.out.println("→ Enviando solicitud para el servicio: " + serviceId);
            // Enviar la solicitud (con cifrado y verificación HMAC)
            enviarSolicitud(sock, in, out, serviceId);
        }
    }

    // Método para ejecutar el Escenario 2: Servidor y clientes concurrentes
    private static void ejecutarEscenario2(Socket sock, DataInputStream in, DataOutputStream out) throws Exception {
        System.out.println("\nEjecutando Escenario 2: Servidor y clientes concurrentes...");

        // Para simular la concurrencia, usaremos hilos
        int numClientes = 4;  // Cambia este valor a 16, 32 o 64 según el escenario
        for (int i = 0; i < numClientes; i++) {
            new Thread(() -> {
                try {
                    String serviceId = "S" + (int)(Math.random() * 3 + 1); // Servicio aleatorio
                    System.out.println("→ Enviando solicitud aleatoria para el servicio: " + serviceId);
                    // Enviar la solicitud (con cifrado y verificación HMAC)
                    enviarSolicitud(sock, in, out, serviceId);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }

    // Método para enviar la solicitud al servidor
    private static void enviarSolicitud(Socket sock, DataInputStream in, DataOutputStream out, String serviceId) throws Exception {
        System.out.println("Servicio seleccionado (antes de cifrar): " + serviceId);

        // Generar un IV aleatorio para cifrar la solicitud
        SecureRandom rnd = new SecureRandom();
        byte[] iv2 = new byte[16];
        rnd.nextBytes(iv2);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kEnc, new IvParameterSpec(iv2));
        byte[] cReq = cipher.doFinal(serviceId.getBytes("UTF-8"));

        // Petición cifrada (Base64)
        if (cReq != null) {
            System.out.println("Petición cifrada (Base64):");
            System.out.println(Base64.getEncoder().encodeToString(cReq)); //error en Base64.
        }

        out.writeInt(iv2.length);
        out.write(iv2);
        out.writeInt(cReq.length);
        out.write(cReq);
        out.flush();

        // Recibir y procesar la respuesta cifrada
        int iv3Len = in.readInt();
        byte[] iv3 = new byte[iv3Len];
        in.readFully(iv3);

        int c3Len = in.readInt();
        byte[] c3 = new byte[c3Len];
        in.readFully(c3);

        int h3Len = in.readInt();
        byte[] h3 = new byte[h3Len];
        in.readFully(h3);

        // Verificar HMAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(kHmac);
        mac.update(iv3);
        mac.update(c3);
        byte[] ourH3 = mac.doFinal();
        if (!MessageDigest.isEqual(h3, ourH3)) {
            System.err.println("HMAC de respuesta inválido.");
            sock.close();
            return;
        }

        cipher.init(Cipher.DECRYPT_MODE, kEnc, new IvParameterSpec(iv3)); //error en KEnc
        String respuesta = new String(cipher.doFinal(c3), "UTF-8");
        System.out.println("→ Respuesta descifrada: " + respuesta);
    }
}
