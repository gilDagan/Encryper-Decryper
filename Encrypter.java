import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;

public class Encrypter {
	final String KEYSTORE_TYPE = "pkcs12";
	final String SYMMETRIC_KEY = "symmetricKey";
	final String PRIVATE_KEY = "KeyA";
	final String KEY_ENCRYPTION_ALG = "RSA";
	final String CERTIFICATE_B = "self-signed-certificateB";
	final String DIGITAL_SIGNATURE = "digitalSignature";
	final String IV = "IV";
	final int IV_NUM_BYTES = 16;
	final int NUM_BIT_KEY = 128;

	// Config file properties
	final String IV_ALG = "SHA1PRNG";
	final String CIPHER_ALG = "AES/CTR/NoPadding";
	final String SIGNING_ALG = "SHA256withRSA";
	final String CIPHER_PROVIDER = "SunJCE";
	final String SIGNING_PROVIDER = "SunRsaSign";
		
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
	
	// IV properties
	String m_IVAlgorithm;
	
	// Constructor
	public Encrypter(char[] i_keyStorePassword) throws Exception 
	{
		m_KeyStorePassword = i_keyStorePassword;
		init();
	}
	
	/**
	 * Initialize the encrypter properties
	 * We use class Cipher in a way that the client can easily change the algorithm and the provider.
	 * More specifically we use 'Cipher.getInstance' that Returns a Cipher object that implements the specified
	 * transformation and save it as a 'encrypter' class member.
	 * @throws Exception
	 */	
	public void init() throws Exception
	{
		m_Properties = new Properties();
		initConfigFile();
		getPropertiesFromFile();
		setKeyStore();
		m_SymmetricKey = generateRandKey();
		encryptKey(m_SymmetricKey);
		m_Cipher = Cipher.getInstance(m_CipherAlgorithm, m_CipherProvider);
	}

	/**
	 * Initialize the Config File
	 * We create a config file with all the chosen properties, which can easily get change.
	 * @throws Exception
	 */	
	private void initConfigFile() throws Exception
    {
		File configFile = new File(".\\resources.\\config.properties");
		FileOutputStream fos = new FileOutputStream(".\\resources.\\config.properties");
		m_Properties.setProperty("IvAlgorithm",IV_ALG);
		m_Properties.setProperty("cipherAlgorithm", CIPHER_ALG);
		m_Properties.setProperty("signingAlgorithm", SIGNING_ALG);
		m_Properties.setProperty("cipherProvider", CIPHER_PROVIDER);
		m_Properties.setProperty("signingProvider", SIGNING_PROVIDER);
		m_Properties.store(fos,null);
		fos.close();
	}

	/**
	 * Load the encrypter properties from config file
	 *
	 * @throws Exception if property does not exist
	 */
	private void getPropertiesFromFile() throws Exception 
	{
		try {
			FileInputStream fis = new FileInputStream(".\\resources.\\config.properties");
			m_Properties.load(fis);
			setPropertiesInClassMembers(m_Properties);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
	
	private void setPropertiesInClassMembers(Properties i_Properties) 
	{
		m_CipherProvider = i_Properties.getProperty("cipherProvider");
		m_CipherAlgorithm = i_Properties.getProperty("cipherAlgorithm");
		m_SigningProvider = i_Properties.getProperty("signingProvider");
		m_SigningAlgorithm = i_Properties.getProperty("signingAlgorithm");
		m_IVAlgorithm = i_Properties.getProperty("IvAlgorithm");
	}

	/**
	 * initialize the key store by 'KeyStore.getInstance' that returns a keystore object of the
	 * specified type, in our case we defines the type as "pkcs12" because it has improved security.
	 * we are loading the key store from the given input stream using the kew store password
	 * @throws Exception
	 */	
    private void setKeyStore() throws Exception 
	{
        FileInputStream fis = new FileInputStream(".\\resources.\\privateKeyA.pkcs12");
        m_KeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        m_KeyStore.load(fis, m_KeyStorePassword);
    }
    
	/**
	 * Generate a new random key
	 *
	 * @throws Exception
	 * @return the new Secret Key 
	 */
     private SecretKey generateRandKey() throws Exception 
     {
	   // Creating a new instance of SecureRandom class.
       SecureRandom securerandom = new SecureRandom();
       m_Cipher = Cipher.getInstance(m_CipherAlgorithm, m_CipherProvider);
       // Passing the string to KeyGenerator
       KeyGenerator keygenerator= KeyGenerator.getInstance(m_Cipher.getParameters().getAlgorithm(), m_Cipher.getParameters().getProvider());
       // Initializing the KeyGenerator with 128 bits.
       keygenerator.init(NUM_BIT_KEY, securerandom);
       SecretKey key = keygenerator.generateKey();
       return key;
	   }
   
	 /**
	 * Encrypt the key by using the chosen key encryption 
	 * algoruthem and store it in the configuration file
	 * @param SecretKey
	 * @throws Exception
	 */
   private void encryptKey(SecretKey i_Key) throws Exception
   {
		PublicKey publicKeyB = m_KeyStore.getCertificate(CERTIFICATE_B).getPublicKey();
		m_Cipher = Cipher.getInstance(KEY_ENCRYPTION_ALG, m_CipherProvider);
		m_Cipher.init(Cipher.ENCRYPT_MODE, publicKeyB);
		byte[] encryptedKey = m_Cipher.doFinal(i_Key.getEncoded());
		saveInConfigFile(SYMMETRIC_KEY, encryptedKey);
   }
   
    /**
	 * Save encrypter deatails in the config file
	 * @param i_PropertyToSave
	 * @param i_Value
	 * @throws Exception
	 */
   private void saveInConfigFile(String i_PropertyToSave, byte[] i_Value) throws Exception
    {
		FileOutputStream fos = new FileOutputStream(".\\resources.\\config.properties");
		String valueStr = Base64.getEncoder().encodeToString(i_Value);
		m_Properties.setProperty(i_PropertyToSave, valueStr);
		m_Properties.store(fos,null);
		fos.close();
	}
   
    /**
	 * Generate a new IV and save it in the config file
	 * @throws Exception
	 * @return IvParameterSpec
	 */ 	
   private IvParameterSpec generateIV() throws Exception
   {
       SecureRandom secureRandom = SecureRandom.getInstance(m_IVAlgorithm);
       byte[] ivArr = new byte[IV_NUM_BYTES];
       secureRandom.nextBytes(ivArr);
       saveInConfigFile(IV, ivArr);
       return new IvParameterSpec(ivArr);
   }

   /**
	 * Generate a new signature using the chosen signing algorithm 
	 *  and the signing provider  and save it in the config file
	 * @throws Exception
	 * @return digital Signature byte array 
	 */ 
   public byte[] generateSignature(FileInputStream i_Fis) throws Exception
   {
	    byte[] digitalSignature; 
		BufferedInputStream bufferedInputStream = new BufferedInputStream(i_Fis);
		Signature signature = Signature.getInstance(m_SigningAlgorithm, m_SigningProvider);
		String input = new String(bufferedInputStream.readAllBytes());
		
		signature.initSign((PrivateKey) m_KeyStore.getKey(PRIVATE_KEY, m_KeyStorePassword));
		signature.update(input.getBytes());
		digitalSignature = signature.sign();
		System.out.println("Sigining successfully");
		saveInConfigFile(DIGITAL_SIGNATURE, digitalSignature);
		return digitalSignature;
    }
   
	/**
	 * Encrypt the given file using the encrypter properties
	 * @param FileInputStream
	 * @throws Exception
	 */ 
	public void Encrypt(FileInputStream i_Fis) throws Exception {
		IvParameterSpec IV = generateIV();
		m_Cipher.init(Cipher.ENCRYPT_MODE, m_SymmetricKey, IV);
		BufferedInputStream bis = new BufferedInputStream(i_Fis);
		FileOutputStream fos = new FileOutputStream("cipherText.txt");
		CipherOutputStream cos = new CipherOutputStream(fos, m_Cipher);
		cos.write(bis.readAllBytes());
		cos.close();
		System.out.println("File encrypted successfully");
	}
}