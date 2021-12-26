import java.io.FileInputStream;

public class Main {
	public static void main(String[] args) throws Exception {
		char[] keyStoreAPassword = args[0].toCharArray();
		char[] keyStoreBPassword = args[1].toCharArray();
		String plainText = args[2];
		String decrypted = args[3];

		Encrypter encrypter = new Encrypter(keyStoreAPassword);
		encrypter.Encrypt(new FileInputStream(plainText));
		encrypter.generateSignature(new FileInputStream("cipherText.txt"));

		Decrypter decrypter = new Decrypter(keyStoreBPassword);
		decrypter.decryptFile(decrypted);
	}
}
