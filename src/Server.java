import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.Signature;

public class Server {
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA";

    // Método para cifrar con AES
    public static byte[] encryptAES(byte[] data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    // Método para firmar con RSA
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}
