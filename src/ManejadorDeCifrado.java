// ManejadorDeCifrado.java
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class ManejadorDeCifrado {

    // AES/CBC y HMAC
    private static final String AES_TRANSFORM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALG     = "HmacSHA256";
    private static final String SIGN_ALG     = "SHA256withRSA";
    private static final String HASH_ALG     = "SHA-512";
    private static final String RSA         = "RSA";
    private static final String AES         = "AES";

    public static byte[] generarFirma(PrivateKey pk, byte[] msg) throws Exception {
        Signature sig = Signature.getInstance(SIGN_ALG);
        sig.initSign(pk);
        sig.update(msg);
        return sig.sign();
    }

    public static boolean validarFirma(PublicKey pub, byte[] msg, byte[] firma) throws Exception {
        Signature sig = Signature.getInstance(SIGN_ALG);
        sig.initVerify(pub);
        sig.update(msg);
        return sig.verify(firma);
    }

    public static SecretKey[] generarLlavesSimetricas(byte[] z) throws Exception {
        MessageDigest md = MessageDigest.getInstance(HASH_ALG);
        byte[] hash = md.digest(z);
        int half = hash.length/2;
        byte[] k1 = new byte[half], k2 = new byte[half];
        System.arraycopy(hash, 0,    k1, 0, half);
        System.arraycopy(hash, half, k2, 0, half);
        SecretKey sk1 = new SecretKeySpec(k1, AES);
        SecretKey sk2 = new SecretKeySpec(k2, AES);
        return new SecretKey[]{sk1, sk2};
    }

    public static PrivateKey generarLlavePrivada(String base64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public static PublicKey generarLlavePublica(String base64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(new X509EncodedKeySpec(bytes));
    }
}
