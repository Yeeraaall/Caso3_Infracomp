import java.security.*;
import java.util.Base64;

public class KeyGen {
    public static void main(String[] args) throws Exception {
        // 1) Generar par RSA de 1024 bits
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        // 2) Codificar en Base64 PKCS#8 y X.509
        String privB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pubB64  = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        // 3) Imprimir al stdout
        System.out.println("PRIVATE_KEY:");
        System.out.println(privB64);
        System.out.println("PUBLIC_KEY:");
        System.out.println(pubB64);
    }
}
