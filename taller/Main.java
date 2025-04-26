import java.security.Key;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.Scanner;

public class Main {

    private final static String ALGORITMO = "AES";

    public static void main(String[] args) {
        // Crear una instancia de la clase Simetrico
        Simetrico simetrico = new Simetrico();

        // Recibir el texto por teclado
        Scanner sc = new Scanner(System.in);
        System.out.print("Escriba el texto que desea cifrar: ");
        String texto = sc.nextLine();
        
        // Imprimir el texto recibido
        System.out.println("Texto ingresado: " + texto);

        // Convertir texto a byte[]
        byte[] textoClaro = texto.getBytes();

        // Imprimir el texto claro
        simetrico.imprimir(textoClaro);

        try {
            // Generar la llave secreta
            KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO);
            SecretKey secretKey = keygen.generateKey();

            // Cifrar el texto
            byte[] textoCifrado = simetrico.cifrar(secretKey, texto);
            System.out.println("Texto cifrado:");
            simetrico.imprimir(textoCifrado);

            // Descifrar el texto
            byte[] textoDescifrado = simetrico.descifrar(secretKey, textoCifrado);
            System.out.println("Texto descifrado:");
            simetrico.imprimir(textoDescifrado);

            // Convertir byte[] de texto descifrado a String
            String textoFinal = new String(textoDescifrado);
            System.out.println("Texto final: " + textoFinal);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        sc.close();
    }
}
