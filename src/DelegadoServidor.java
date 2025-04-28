import java.io.*;
import java.net.*;
import java.util.*;

public class DelegadoServidor {

    // Puerto en el que escucha el delegado
    private static final int PORT = 5000;

    // Simula la respuesta concreta de cada servicio
    private static Map<String,String> resps = new HashMap<>();
    static {
        resps.put("S1", "Estado de vuelo: En horario");
        resps.put("S2", "Disponibilidad: Hay 5 vuelos");
        resps.put("S3", "Costo: $200 USD");
    }

    public static void main(String[] args) throws IOException {
        ServerSocket ss = new ServerSocket(PORT);
        System.out.println("Delegado escuchando en puerto " + PORT);
        while (true) {
            Socket s = ss.accept();
            new Thread(() -> {
                try (DataInputStream in  = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    String id = in.readUTF();
                    out.writeUTF(resps.getOrDefault(id, "Servicio no encontrado"));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
}

