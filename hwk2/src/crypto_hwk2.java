import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class crypto_hwk2 {

	public static BigInteger aes(BigInteger b, BigInteger key, int mode) {
		BigInteger result = null;
		try {
			SecretKeySpec k = new SecretKeySpec(key.toByteArray(), "AES");
			Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
			c.init(mode, k);
			result = new BigInteger(c.doFinal(b.toByteArray()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	public static BigInteger decryptCBC(BigInteger iv, BigInteger ct,
			BigInteger key) {
		return iv.xor(aes(ct, key, Cipher.DECRYPT_MODE));
	}

	public static BigInteger encryptCBC(BigInteger iv, BigInteger pt,
			BigInteger key) {
		return aes(iv.xor(pt), key, Cipher.ENCRYPT_MODE);
	}

	public static BigInteger decryptCTR(BigInteger iv, BigInteger ct,
			BigInteger key) {
		return ct.xor(aes(iv, key, Cipher.ENCRYPT_MODE));
	}

	public static BigInteger encryptCTR(BigInteger iv, BigInteger pt,
			BigInteger key) {
		return pt.xor(aes(iv, key, Cipher.ENCRYPT_MODE));
	}

	public static BigInteger extractCt(byte[] ciphertext, int idx) {
		int start = 16 * idx;
		int end = start + 16;
		return new BigInteger(Arrays.copyOfRange(ciphertext, start, end));
	}

	public static byte[] parseHexString(String str) {
		byte[] vals = new byte[str.length() / 2];
		for (int i = 0; i < str.length(); i += 2) {
			vals[i / 2] = (byte) Integer.parseInt(str.substring(i, i + 2), 16);
		}
		return vals;
	}

	public static void problemCBC(BigInteger key, BigInteger iv,
			String ciphertext) {
		String pt = "";
		byte[] ct = parseHexString(ciphertext);
		System.out.println("Key: " + key.toString(16));
		for (int i = 0; ct.length > i * 16; i++) {
			int unusedLen = ct.length - i * 16;
			BigInteger ci = extractCt(ct, i);
			if (unusedLen < 16) {
				for (int j = unusedLen - 1; j < 16; j++) {
					// Figure out padded part...
				}
			}
			BigInteger mi = decryptCBC(iv, ci, key);
			System.out.println("iv[" + i + "]: " + iv.toString(16) + "\nm[" + i
					+ "]: " + mi.toString(16) + "\nc[" + i + "]: "
					+ ci.toString(16));
			pt += new String(mi.toByteArray());
			iv = ci;
		}
		System.out.println("Plaintext: " + pt + "\n");
	}

	public static void problemCTR(BigInteger key, BigInteger iv,
			String ciphertext) {
		String pt = "";
		byte[] ct = parseHexString(ciphertext);
		System.out.println("Key: " + key.toString(16));
		for (int i = 0; ct.length > i * 16; i++) {
			int unusedLen = ct.length - i * 16;
			BigInteger ci = extractCt(ct, i);
			if (unusedLen < 16) {
				for (int j = unusedLen - 1; j < 16; j++) {
					// Figure out padded part...
				}
			}
			BigInteger mi = decryptCTR(iv, ci, key);
			System.out.println("iv[" + i + "]: " + iv.toString(16) + "\nm[" + i
					+ "]: " + mi.toString(16) + "\nc[" + i + "]: "
					+ ci.toString(16));
			pt += new String(mi.toByteArray());
			iv = iv.add(BigInteger.ONE);
		}
		System.out.println("Plaintext: " + pt + "\n");
	}

	public static void main(String[] args) {
		// Question 1
		System.out.println("Question 1:");
		problemCBC(
				new BigInteger("140b41b22a29beb4061bda66b6747e14", 16),
				new BigInteger("4ca00ff4c898d61e1edbf1800618fb28", 16),
				"28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");

		// Question 2
		System.out.println("Question 2:");
		problemCBC(
				new BigInteger("140b41b22a29beb4061bda66b6747e14", 16),
				new BigInteger("5b68629feb8606f9a6667670b75b38a5", 16),
				"b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253");

		// Question 3
		System.out.println("Question 3:");
		problemCTR(
				new BigInteger("36f18357be4dbd77f050515c73fcf9f2", 16),
				new BigInteger("69dda8455c7dd4254bf353b773304eec", 16),
				"0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329");

		// Question 4
		System.out.println("Question 4:");
		problemCTR(new BigInteger("36f18357be4dbd77f050515c73fcf9f2", 16),
				new BigInteger("770b80259ec33beb2561358a9f2dc617", 16),
				"e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451");
	}
}