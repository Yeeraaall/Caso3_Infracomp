import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.math.BigInteger;

public class Cliente {

    private static final String SECRET_KEY = "clave_secreta"; // Clave para HMAC

    public static String generarHMAC(String data, String key) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] hash = sha256_HMAC.doFinal(data.getBytes());
        return bytesToHex(hash);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String serverAddress = "localhost";
        int port = 4000;
        Socket socket = null;

        try {
            socket = new Socket(serverAddress, port);
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Recibir la tabla de servicios
            String serviciosDisponibles = input.readUTF();
            System.out.println("Servicios disponibles:\n" + serviciosDisponibles);

            // Selección de servicio
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Seleccione un servicio (S1, S2, S3): ");
            String servicioSeleccionado = reader.readLine();

            // Enviar servicio con HMAC
            String mensaje = "Solicitar: " + servicioSeleccionado;
            String hmacCliente = generarHMAC(mensaje, SECRET_KEY);
            output.writeUTF(servicioSeleccionado + "," + hmacCliente);

            // Recibir respuesta del servidor
            String respuesta = input.readUTF();
            String hmacRespuesta = respuesta.split(",")[1];
            String datosServicio = respuesta.split(",")[0];

            // Verificar HMAC de la respuesta
            if (hmacRespuesta.equals(generarHMAC(datosServicio, SECRET_KEY))) {
                System.out.println("Respuesta válida: " + datosServicio);
            } else {
                System.out.println("Error en la consulta. HMAC inválido.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (socket != null) socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

