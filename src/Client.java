import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Enviar el identificador de servicio
            out.println("3");

            // Leer la respuesta
            String response = in.readLine();
            if (response != null) {
                System.out.println("Service response: " + response);

                // Verificar la integridad de la respuesta usando HMAC
                String secretKey = "secret";  // La clave secreta debe coincidir entre cliente y servidor
                String hmac = calculateHMAC(response, secretKey);
                System.out.println("HMAC: " + hmac);
            } else {
                System.out.println("No response from server.");
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para calcular HMAC
    public static String calculateHMAC(String data, String key) throws Exception {
        if (data == null || key == null) {
            throw new IllegalArgumentException("Data or key cannot be null");
        }

        System.out.println("Calculating HMAC for data: " + data + " with key: " + key);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return bytesToHex(hmacBytes);
    }

    // Convertir bytes a hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
