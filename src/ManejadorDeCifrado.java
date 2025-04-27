import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class ManejadorDeCifrado {

    private static final String ALG_GENERADOR_SIMETRICO = "AES/CBC/PKCS5Padding";
    private static final String ALG_GENERADOR_FIRMA = "SHA256withRSA";
    private static final String ALG_GENERADOR_HASH = "SHA-512";
    private static final String ALG_GENERADOR_HMAC = "HmacSHA256";
    private static final String ALGORITMO_SIMETRICO = "AES";
    private static final String ALGORITMO_ASIMETRICO = "RSA";

    // Método para cifrar de forma simétrica un texto convertido a bytes
    public static byte[] cifrar(SecretKey llave, byte[] textoClaro, IvParameterSpec iv) {
        byte[] textoCifrado = null;
        try {
            Cipher cifrador = Cipher.getInstance(ALG_GENERADOR_SIMETRICO);
            cifrador.init(Cipher.ENCRYPT_MODE, llave, iv);
            textoCifrado = cifrador.doFinal(textoClaro);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
        return textoCifrado;
    }

    // Método para descifrar de forma simétrica un texto cifrado convertido a bytes
    public static byte[] descifrar(SecretKey llave, byte[] texto, IvParameterSpec iv) {
        byte[] textoClaro = null;
        try {
            Cipher cifrador = Cipher.getInstance(ALG_GENERADOR_SIMETRICO);
            cifrador.init(Cipher.DECRYPT_MODE, llave, iv);
            textoClaro = cifrador.doFinal(texto);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
        return textoClaro;
    }

    // Método para generar un HMAC de un texto convertido a bytes
    public static byte[] generarHMAC(SecretKey key, byte[] texto) {
        byte[] hmacBytes = null;
        try {
            Mac mac = Mac.getInstance(ALG_GENERADOR_HMAC);
            mac.init(key);
            hmacBytes = mac.doFinal(texto);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hmacBytes;
    }

    // Método para generar una firma digital
    public static byte[] generarFirma(PrivateKey llavePrivada, byte[] mensaje) {
        byte[] firma = null;
        try {
            Signature signature = Signature.getInstance(ALG_GENERADOR_FIRMA);
            signature.initSign(llavePrivada);
            signature.update(mensaje);
            firma = signature.sign();
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
        return firma;
    }

    // Método para validar una firma digital
    public static boolean validarFirma(PublicKey llavePublica, byte[] actual, byte[] recibido) {
        boolean esValida = false;
        try {
            Signature firma = Signature.getInstance(ALG_GENERADOR_FIRMA);
            firma.initVerify(llavePublica);
            firma.update(actual);
            esValida = firma.verify(recibido);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
        return esValida;
    }

    // Método que genera dos llaves simétricas a partir de un arreglo de bytes
    public static SecretKey[] generarLlavesSimetricas(byte[] z) {
        SecretKey K_AB1 = null;
        SecretKey K_AB2 = null;
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(ALG_GENERADOR_HASH);
            byte[] hash = digest.digest(z);
            int longitudMitad = hash.length / 2;
            byte[] primeraMitad = new byte[longitudMitad];
            byte[] segundaMitad = new byte[longitudMitad];
            System.arraycopy(hash, 0, primeraMitad, 0, longitudMitad);
            System.arraycopy(hash, longitudMitad, segundaMitad, 0, longitudMitad);
            K_AB1 = generarLlave(primeraMitad);
            K_AB2 = generarLlave(segundaMitad);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKey[] llaves = {K_AB1, K_AB2};
        return llaves;
    }

    // Método que genera una llave a partir de un arreglo de bytes
    private static SecretKey generarLlave(byte[] bytesMitadLlave) {
        SecretKey nuevaLlave = new SecretKeySpec(bytesMitadLlave, 0, bytesMitadLlave.length, ALGORITMO_SIMETRICO);
        return nuevaLlave;
    }

    // Método que genera una llave privada a partir de una llave codificada en base64 (String)
    public static PrivateKey generarLlavePrivada(String llaveCodificada) {
        PrivateKey llavePrivada = null;
        try {
            byte[] llavePrivadaEnBytes = Base64.getDecoder().decode(llaveCodificada);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_ASIMETRICO);
            llavePrivada = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(llavePrivadaEnBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return llavePrivada;
    }

// Método que genera una llave pública a partir de una llave codificada en base64 (String)
    public static PublicKey generarLlavePublica(String llaveCodificada) throws InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey llavePublica = null;
    try {
        byte[] llavePublicaEnBytes = Base64.getDecoder().decode(llaveCodificada);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_ASIMETRICO);
        llavePublica = keyFactory.generatePublic(new X509EncodedKeySpec(llavePublicaEnBytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
    return llavePublica; 
}


}