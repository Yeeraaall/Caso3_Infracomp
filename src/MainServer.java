import java.io.*;
import java.net.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainServer {
    private static final int PORT = 12345;
    private static final String[] services = {"Flight Status", "Available Flights", "Flight Cost"};
    
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                // Esperar conexiones de los clientes
                Socket clientSocket = serverSocket.accept();
                // Crear un nuevo hilo delegado para gestionar la consulta del cliente
                new ClientHandler(clientSocket).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Clase interna para manejar cada consulta del cliente
    static class ClientHandler extends Thread {
        private Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try {
                // Leer las solicitudes del cliente y procesarlas
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                // Leer el identificador del servicio
                String serviceId = in.readLine();
                if (serviceId.equals("1")) {
                    out.println("Flight Status");
                } else if (serviceId.equals("2")) {
                    out.println("Available Flights");
                } else {
                    out.println("Service not found");
                }

                // Cerrar la conexión
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

