import java.io.*;
import java.net.*;
import java.util.*;

public class DelegadoServidor {

    private static Map<String, String> serviciosDelegados = new HashMap<>();

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(5000);
            System.out.println("Servidor delegado esperando conexiones...");

            // Definir servicios disponibles
            serviciosDelegados.put("S1", "Estado de vuelo: En horario");
            serviciosDelegados.put("S2", "Disponibilidad: Hay 5 vuelos");
            serviciosDelegados.put("S3", "Costo: $200 USD");

            while (true) {
                Socket clienteSocket = serverSocket.accept();
                System.out.println("Conexión de servidor delegado con: " + clienteSocket.getRemoteSocketAddress());
                new DelegadoHandler(clienteSocket).start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Maneja las consultas delegadas
    static class DelegadoHandler extends Thread {
        private Socket clienteSocket;

        public DelegadoHandler(Socket socket) {
            this.clienteSocket = socket;
        }

        public void run() {
            try {
                DataInputStream input = new DataInputStream(clienteSocket.getInputStream());
                DataOutputStream output = new DataOutputStream(clienteSocket.getOutputStream());

                // Recibir la solicitud del servidor principal
                String servicioId = input.readUTF();
                String respuesta = serviciosDelegados.getOrDefault(servicioId, "Servicio no encontrado");

                output.writeUTF(respuesta);

                clienteSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

