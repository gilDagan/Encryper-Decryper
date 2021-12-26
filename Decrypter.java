import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;

public class Decrypter {
	
	final String SYMMETRIC_KEY = "symmetricKey";
	final String CERTIFICATE_A = "self-signed-certificateA";
	final String KEY_ENCRYPTION_ALG = "RSA";
	final String IV = "IV";
	final String KEYSTORE_TYPE = "pkcs12";
	final String PRIVATE_KEY = "KeyB";
	final String DIGITAL_SIGNATURE = "digitalSignature";
	
	Properties m_Properties;
	private char[] m_KeyStorePassword;
	Cipher m_Cipher;
	KeyStore m_KeyStore;
	SecretKey m_SymmetricKey;
	
	// Cipher properties
	String m_CipherProvider;
	String m_CipherAlgorithm;
	
	// Signature properties
	String m_SigningAlgorithm;
	String m_SigningProvider;
	
	// Constructor
	public Decrypter(char[] i_keyStorePassword) throws Exception {
		m_KeyStorePassword = i_keyStorePassword;
		init();
	}
	
	/**
	 * Initialize the decrypter properties
	 * We use class Cipher in a way that the client can easily change the algorithm and th provider.
	 * More specifically we use 'Cipher.getInstance' that Returns a Cipher object that implements the specified
	 * transformation and save it as a 'decrypter' class member.
	 * @throws Exception
	 */
	public void init() throws Exception {
		m_Properties = new Properties();
		getPropertiesFromFile();
		setKeyStore();
		m_SymmetricKey = decryptKey();
	}

	 /**
	 * load the decrypter properties from config file using the 'getProperty' operation
	 * and save this properties as decrypter class members (done by the 'setPropertiesInClassMembers' function.
	 * @throws Exception if property doesn't exist.
	 */
	private void getPropertiesFromFile() throws Exception 
	{
		try {
			FileInputStream fis = new FileInputStream(".\\resources.\\config.properties");
			m_Properties.load(fis);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		setPropertiesInClassMembers(m_Properties);
	}
	
	private void setPropertiesInClassMembers(Properties i_Properties) 
	{
		m_CipherProvider = i_Properties.getProperty("cipherProvider");
		m_CipherAlgorithm = i_Properties.getProperty("cipherAlgorithm");
		m_SigningProvider = i_Properties.getProperty("signingProvider");
		m_SigningAlgorithm = i_Properties.getProperty("signingAlgorithm");
	}

	/**
	 * initialize the key store by 'KeyStore.getInstance' that returns a keystore object of the
	 * specified type, in our case we defines the type as "pkcs12" because it has improved security.
	 * we are loading the key store from the given input stream using the kew store password
	 * @throws Exception
	 */	
	private void setKeyStore() throws Exception 
	{
        FileInputStream fis = new FileInputStream(".\\resources.\\privateKeyB.pkcs12");
        m_KeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        m_KeyStore.load(fis, m_KeyStorePassword);
    }

	/**
	 * Reads encrypted key from config file, decrypt the given key and returns it using SecretKeySpec that
	 * constructs a secret key from the given byte array 'key bytes'.
	 *
	 * @return the decrypted secret key
	 * @throws Exception
	 */
	private SecretKey decryptKey() throws Exception {
		PrivateKey privateKey = (PrivateKey) m_KeyStore.getKey(PRIVATE_KEY, m_KeyStorePassword);
		m_Cipher = Cipher.getInstance(KEY_ENCRYPTION_ALG);
		m_Cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedKey = Base64.getDecoder().decode(m_Properties.getProperty(SYMMETRIC_KEY));
		byte[] keyBytes = m_Cipher.doFinal(decryptedKey);
		m_Cipher = Cipher.getInstance(m_CipherAlgorithm, m_CipherProvider);
		return new SecretKeySpec(keyBytes, m_Cipher.getParameters().getAlgorithm());
	}

	/**
	 * Check if the signature of the encrypted text is verified, using the public key from the certificate saved
	 * in the key store.
	 *
	 * @return True if the signature is verified, else false.
	 * @throws Exception
	 */
	public boolean verifySignature() throws Exception {
		byte[] signatureArr = Base64.getDecoder().decode(m_Properties.getProperty(DIGITAL_SIGNATURE));
		PublicKey publicKey = m_KeyStore.getCertificate(CERTIFICATE_A).getPublicKey();
        Signature signature = Signature.getInstance(m_SigningAlgorithm, m_SigningProvider);
        signature.initVerify(publicKey);
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream("cipherText.txt"));
		String text = new String(bis.readAllBytes());
		signature.update(text.getBytes());
        return signature.verify(signatureArr);
	}

	 /**
	 * Reads the cipher text, decrypts it and writes it to output file.
     * @param fis - File stream
     * @param cos - Cipher stream
	 * @throws Exception
	 */
    private void decryptToFile(FileInputStream i_Fis, CipherOutputStream i_Cos) {
        byte[] buff = new byte[256];
        try {
            int hasMoreToRead = i_Fis.read(buff);
            while (hasMoreToRead != -1) {
                i_Cos.write(buff, 0 ,hasMoreToRead);
                hasMoreToRead = i_Fis.read(buff);
            }
            i_Fis.close();
            i_Cos.close();

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

	 /**
	 * Gets a file name,create a file and decrypt the text and write it into the file.
	 * The function check if the signutre is verify, if not its throw exception and 
	 * don`t decrypt the text.
	 *
	 * @param String
	 * @throws Exception
	 */
	public void decryptFile(String i_OutputFile) throws Exception {
		String ivValue = m_Properties.getProperty(IV);
		byte[] ivByteArray = Base64.getDecoder().decode(ivValue);
        IvParameterSpec ivSpec = new IvParameterSpec(ivByteArray);
        m_Cipher = Cipher.getInstance(m_CipherAlgorithm, m_CipherProvider);
        m_Cipher.init(Cipher.DECRYPT_MODE, m_SymmetricKey, ivSpec);
        boolean verify = verifySignature();
        if(verify) {
        	   System.out.println("Signature is valid, decrypting file...");
               FileInputStream fis = new FileInputStream("cipherText.txt");
               CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(i_OutputFile), m_Cipher);
               decryptToFile(fis, cos);
               System.out.println("Decryption complete!");
        }
        else {
            System.out.println("Signature is not valid, no decryption initialized");
        }
	}
}