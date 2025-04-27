import java.io.*;
import java.net.*;
import java.util.*;

public class ServidorPrincipal {

    private static Map<String, String> servicios = new HashMap<>();

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(4000);
            System.out.println("Servidor principal esperando conexiones...");
            
            // Definir servicios disponibles
            servicios.put("S1", "Estado de vuelo");
            servicios.put("S2", "Disponibilidad de vuelos");
            servicios.put("S3", "Costo de un vuelo");

            while (true) {
                Socket clienteSocket = serverSocket.accept();
                System.out.println("Cliente conectado: " + clienteSocket.getRemoteSocketAddress());
                new ClienteHandler(clienteSocket).start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Maneja las solicitudes del cliente
    static class ClienteHandler extends Thread {
        private Socket clienteSocket;

        public ClienteHandler(Socket socket) {
            this.clienteSocket = socket;
        }

        public void run() {
            try {
                DataInputStream input = new DataInputStream(clienteSocket.getInputStream());
                DataOutputStream output = new DataOutputStream(clienteSocket.getOutputStream());

                // Enviar la tabla de servicios
                StringBuilder tablaServicios = new StringBuilder();
                for (Map.Entry<String, String> entry : servicios.entrySet()) {
                    tablaServicios.append(entry.getKey() + ": " + entry.getValue() + "\n");
                }
                output.writeUTF(tablaServicios.toString());

                // Recibir la solicitud del cliente
                String solicitud = input.readUTF();
                String servicioId = solicitud.split(",")[0];
                String hmacCliente = solicitud.split(",")[1];

                // Validar HMAC
                String mensaje = "Solicitar: " + servicioId;
                if (!hmacCliente.equals(ManejadorDeCifrado.generarHMAC(nn, mensaje.getBytes()))) {
                    output.writeUTF("Error en la consulta");
                    return;
                }

                // Delegar la consulta a un servidor delegado
                Socket delegadoSocket = new Socket("localhost", 5000); // Delegado escucha en puerto 5000
                DataOutputStream delegadoOutput = new DataOutputStream(delegadoSocket.getOutputStream());
                delegadoOutput.writeUTF(servicioId);

                DataInputStream delegadoInput = new DataInputStream(delegadoSocket.getInputStream());
                String respuestaDelegado = delegadoInput.readUTF();
                output.writeUTF(respuestaDelegado);

                delegadoSocket.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

