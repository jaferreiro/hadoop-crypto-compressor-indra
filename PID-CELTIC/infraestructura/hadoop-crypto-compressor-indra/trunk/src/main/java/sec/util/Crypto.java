package sec.util;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.io.IOUtils;

/**
 * Main Crypto class it's responsible for
 * encrypt and decrypt all the data based on a public key.
 * 
 * @author someone
 * @modify geisbruch
 * @modify howie
 * 
 */
public class Crypto {

	private static final Log log = LogFactory.getLog(Crypto.class);

	Cipher ecipher;

	Cipher dcipher;
	int decipherCurrentBlock ;
	int decipherNumBlocks ;
	
	/**
	 * Input a string that will be md5 hashed to create the key.
	 * 
	 * @return void, cipher initialized
	 */

	public Crypto(String key) {
		SecretKeySpec skey = new SecretKeySpec(getMD5(key), "AES");
		this.setupCrypto(skey);
		this.decipherCurrentBlock = 0 ;
		this.decipherNumBlocks = 0 ;
	}

	private void setupCrypto(SecretKey key) {
		// Create an 8-byte initialization vector
		byte[] iv = new byte[]{	0x00,
								0x01,
								0x02,
								0x03,
								0x04,
								0x05,
								0x06,
								0x07,
								0x08,
								0x09,
								0x0a,
								0x0b,
								0x0c,
								0x0d,
								0x0e,
								0x0f};

		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		try {
            ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			// CBC requires an initialization vector
			ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
		}
		catch(Exception e) {
			log.error(e);
		}
	}

	// Buffer used to transport the bytes from one stream to another
	byte[] buf = new byte[1024];

	public void encrypt(InputStream in, OutputStream out) {
		try {
			// Bytes written to out will be encrypted
			out = new CipherOutputStream(out, ecipher);

			// Read in the cleartext bytes and write to out to encrypt
			int numRead = 0;
			while((numRead = in.read(buf)) >= 0) {
				out.write(buf, 0, numRead);
			}
		}
		catch(java.io.IOException e) {
			log.error(e);
		}
		finally {
			try { in.close(); } catch (Exception e1) {}
			try { out.close(); } catch (Exception e2) {}
		}
	}

	/**
	 * Input is a string to encrypt.
	 * 
	 * @return a Hex string of the byte array
	 */
	public String encrypt(String plaintext) {
		try {
			byte[] ciphertext = ecipher.doFinal(plaintext.getBytes("UTF-8"));
			return byteToHex(ciphertext);
		}
		catch(Exception e) {
			log.error(e);
			return null;
		}

	}

	/**
	 * Input is a string to encrypt.
	 * 
	 * @return a Hex string of the byte array
	 */
	public byte[] encrypt(byte[] plainBytes) {
		try {
		  int numBlocks = (plainBytes.length+4) / 512 + 1 ;
		  ByteBuffer outDataBuf = ByteBuffer.allocate(plainBytes.length + 4 + 512) ;
		  outDataBuf.putInt(numBlocks) ;

		  for (int numBlock=0 ; numBlock < numBlocks-1; numBlock++) {
		    byte[] ciphertext = ecipher.update(ArrayUtils.subarray(plainBytes, numBlock*512, (numBlock+1)*512));
		    outDataBuf.put(ciphertext) ;
		  }
		  
      byte[] ciphertext = ecipher.doFinal(ArrayUtils.subarray(plainBytes, (numBlocks-1)*512, numBlocks*512));
      outDataBuf.put(ciphertext) ;

      return Arrays.copyOf(outDataBuf.array(), outDataBuf.position());
		}
		catch(Exception e) {
			log.error(e);
			return null;
		}
	}

	public void decrypt(InputStream in, OutputStream out) {
		try {
			// Bytes read from in will be decrypted
			in = new CipherInputStream(in, dcipher);

			// Read in the decrypted bytes and write the cleartext to out
			int numRead = 0;
			while((numRead = in.read(buf)) >= 0) {
				out.write(buf, 0, numRead);
			}
		}
		catch(java.io.IOException e) {
			log.error(e);
		}
		finally {
            try { in.close(); } catch (Exception e1) {}
            try { out.close(); } catch (Exception e2) {}
		}
	}

	/**
	 * Input encrypted String represented in HEX
	 * 
	 * @return a string decrypted in plain text
	 */
	public String decrypt(String hexCipherText) {
		try {
			String plaintext = new String(dcipher.doFinal(hexToByte(hexCipherText)), "UTF-8");
			return plaintext;
		}
		catch(Exception e) {
			log.error(e);
			return null;
		}
	}

	public byte[] decrypt(byte[] ciphertext) {
	  // Here arrives always 512 bytes

	  byte[] arrayToDecipher = ciphertext ;
	  
	  if (this.decipherNumBlocks == 0) { // => First call to decipher
	    ByteBuffer inDataBuf = ByteBuffer.wrap(ciphertext) ;
	    this.decipherNumBlocks = inDataBuf.getInt() ;
	    arrayToDecipher = Arrays.copyOfRange(ciphertext, 4, ciphertext.length) ;
	  }

	  this.decipherCurrentBlock++ ;

	  try {      
      if (this.decipherCurrentBlock < this.decipherNumBlocks) {
        return dcipher.update(arrayToDecipher);
      }
      
  	  if (this.decipherCurrentBlock == this.decipherNumBlocks) {
        return dcipher.doFinal(arrayToDecipher);
  	  }
		}
		catch(Exception e) {
			log.error("Lenght: " + ciphertext.length, e);
			log.error(e);
			return null;
		}
	  return null ; // should never get here but...
	}
	
	private static byte[] getMD5(String input) {
		try {
			byte[] bytesOfMessage = input.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("MD5");
			return md.digest(bytesOfMessage);
		}
		catch(Exception e) {
			return null;
		}
	}

	static final String HEXES = "0123456789ABCDEF";

	public static String byteToHex(byte[] raw) {
		if(raw == null) {
			return null;
		}
		final StringBuilder hex = new StringBuilder(2 * raw.length);
		for(final byte b : raw) {
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
		}
		return hex.toString();
	}

	public static byte[] hexToByte(String hexString) {
		int len = hexString.length();
		byte[] ba = new byte[len / 2];
		for(int i = 0; i < len; i += 2) {
			ba[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(	hexString.charAt(i + 1),
																									16));
		}
		return ba;
	}

}
