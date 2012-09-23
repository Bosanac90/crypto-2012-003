import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class crypto_hwk3 {

	public static String hexify(byte[] b) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < b.length; i++) {
			sb.append(String.format("%02x", b[i]));
		}
		return sb.toString();
	}

	public static byte[] computeHash(byte[] block, int blockLen, byte[] hash,
			int hashLen) {
		byte[] result = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(block, 0, blockLen);
			md.update(hash, 0, hashLen);
			result = md.digest();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	public static byte[] unhashFile(BufferedInputStream bis, byte[] hash0,
			int blockLen, int hashLen) throws IOException {
		int streamLen = bis.available();
		int segementLen = blockLen + hashLen;
		int numSegments = streamLen / segementLen;
		int blockBytes = numSegments * blockLen;
		int lastBlockLen = streamLen - numSegments * segementLen;
		int fileLen = blockBytes + lastBlockLen;
		byte[] file = new byte[fileLen];
		byte[][] blocks = new byte[numSegments + 1][blockLen];
		byte[][] hashes = new byte[numSegments + 1][hashLen];
		hashes[0] = Arrays.copyOf(hash0, hashLen);

		// Verify blocks 1 .. n - 1
		for (int i = 0; i < numSegments; i++) {
			bis.read(blocks[i], 0, blockLen);
			bis.read(hashes[i + 1], 0, hashLen);
			if (!Arrays.equals(hashes[i],
					computeHash(blocks[i], blockLen, hashes[i + 1], hashLen))) {
				throw new SecurityException("Invalid File Hash");
			} else {
				System.arraycopy(blocks[i], 0, file, i * blockLen, blockLen);
			}
		}

		// Verify last block
		bis.read(blocks[numSegments], 0, lastBlockLen);
		if (!Arrays.equals(hashes[numSegments],
				computeHash(blocks[numSegments], lastBlockLen, new byte[0], 0))) {
			throw new SecurityException("Invalid File Hash");
		} else {
			System.arraycopy(blocks[numSegments], 0, file, numSegments
					* blockLen, lastBlockLen);
		}

		return file;
	}

	public static byte[] unhashFile(File f, byte[] hash0, int blockLen,
			int hashLen) throws FileNotFoundException, IOException {
		return unhashFile(new BufferedInputStream(new FileInputStream(f)),
				hash0, blockLen, hashLen);
	}

	public static byte[] hashFile(BufferedInputStream bis, int blockLen,
			int hashLen) throws IOException {
		int bisLen = bis.available();
		int numSegments = bisLen / blockLen;
		int segmentLen = blockLen + hashLen;
		int lastBlockLen = bisLen % blockLen;
		int hashedFileLen = numSegments * segmentLen + lastBlockLen + hashLen;
		byte[][] blocks = new byte[numSegments + 1][blockLen];
		byte[][] hashes = new byte[numSegments + 1][hashLen];
		byte[] hashedFile = new byte[hashedFileLen];

		// Obtain blocks
		for (int i = 0; i <= numSegments; i++) {
			bis.read(blocks[i], 0, blockLen);
		}

		// Hash Last Block
		hashes[numSegments] = computeHash(blocks[numSegments], lastBlockLen,
				new byte[0], 0);

		// Hash remaining blocks
		for (int i = numSegments - 1; i >= 0; i--) {
			hashes[i] = computeHash(blocks[i], blockLen, hashes[i + 1], hashLen);
		}

		// Put it together
		for (int i = 0; i < numSegments; i++) {
			System.arraycopy(hashes[i], 0, hashedFile, i * segmentLen, hashLen);
			System.arraycopy(blocks[i], 0, hashedFile,
					i * segmentLen + hashLen, blockLen);
		}
		System.arraycopy(hashes[numSegments], 0, hashedFile, numSegments
				* segmentLen, hashLen);
		System.arraycopy(blocks[numSegments], 0, hashedFile, numSegments
				* segmentLen + hashLen, lastBlockLen);

		return hashedFile;
	}

	public static byte[] hashFile(File f, int blockLen, int hashLen)
			throws FileNotFoundException, IOException {
		return hashFile(new BufferedInputStream(new FileInputStream(f)),
				blockLen, hashLen);
	}

	public static void writeFile(byte[] buf, String name) throws IOException {
		File out = new File(name);
		BufferedOutputStream bos = new BufferedOutputStream(
				new FileOutputStream(out));
		bos.write(buf);
		bos.close();
	}

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException {
		try {
			byte[] fileHash, hash0;
			int blockLen = 1024, hashLen = 256 / 8;

			// First file
			String file1 = "6 - 1 - Introduction (11 min).mp4";
			fileHash = hashFile(new File(file1), blockLen, hashLen);
			hash0 = Arrays.copyOf(fileHash, hashLen);
			System.out.println("File 1 hash 0: " + hexify(hash0));
			writeFile(Arrays.copyOfRange(fileHash, hashLen, fileHash.length),
					file1 + ".hash");
			unhashFile(new File(file1 + ".hash"), hash0, blockLen, hashLen);

			// Second file
			String file2 = "6 - 2 - Generic birthday attack (16 min).mp4";
			fileHash = hashFile(new File(file2), blockLen, hashLen);
			hash0 = Arrays.copyOf(fileHash, hashLen);
			System.out.println("File 2 hash 0: " + hexify(hash0));
			writeFile(Arrays.copyOfRange(fileHash, hashLen, fileHash.length),
					file2 + ".hash");
			unhashFile(new File(file2 + ".hash"), hash0, blockLen, hashLen);

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
