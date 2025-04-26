import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.util.Scanner;

public class Main2 {

    private final static String ALGORITMO = "AES";

    public static void main(String[] args) {
        // Crear una instancia de la clase Simetrico
        Simetrico simetrico = new Simetrico();

        // Generar dos llaves simétricas k1 y k2
        SecretKey k1 = generarLlave();
        SecretKey k2 = generarLlave();

        // Solicitar mensaje de entrada
        Scanner sc = new Scanner(System.in);
        System.out.print("Escriba el texto que desea cifrar: ");
        String texto = sc.nextLine();
        sc.close();

        // Cifrar con la llave k1 y obtener el mensaje cifrado tc1
        byte[] tc1 = simetrico.cifrar(k1, texto);
        System.out.println("Texto cifrado con k1 (tc1):");
        simetrico.imprimir(tc1);

        // Cifrar con la llave k2 y obtener el mensaje cifrado tc2
        byte[] tc2 = simetrico.cifrar(k2, texto);
        System.out.println("Texto cifrado con k2 (tc2):");
        simetrico.imprimir(tc2);

        // Descifrar tc1 con la llave k1
        byte[] textoDescifradoConK1 = simetrico.descifrar(k1, tc1);
        System.out.println("Texto descifrado con k1:");
        simetrico.imprimir(textoDescifradoConK1);

        // Convertir el texto descifrado de byte[] a String
        String textoFinal = new String(textoDescifradoConK1);
        System.out.println("Texto final descifrado: " + textoFinal);
    }

    // Método para generar llaves simétricas
    public static SecretKey generarLlave() {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO);
            return keygen.generateKey();
        } catch (Exception e) {
            System.out.println("Error al generar la llave: " + e.getMessage());
            return null;
        }
    }
}
