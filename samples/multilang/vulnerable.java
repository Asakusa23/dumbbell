import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;

class Vulnerable {
    void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    void load(InputStream stream) throws Exception {
        new ObjectInputStream(stream).readObject();
    }

    byte[] weakHash() throws Exception {
        return MessageDigest.getInstance("MD5").digest();
    }
}
