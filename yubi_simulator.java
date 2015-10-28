/*
 * yubikey simulator class + demo program
 * (c) 2015 Joerg Dorchain <joerg@dorchian.net>
 * freely interpreted after https://code.google.com/p/yubisim/
 * GNU LGPL 
 *
 */


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.Random;
import java.io.*;

class yubikey {
	/* The following are stored on the token (or disk) */
	String public_id; /* 12 modhex bytes */
	String secret_aes_key; /* 128 hex bits = 32 chars */
	String secret_id; /* 48 hex bits = 32 chars */
	int counter; /* 16 bit Usage counter within session + flags (what flags?) */
	/* this is internal state */
	int counter_session; /* 8 bit button presses within the session */
	int timer; /* 24 bit increased at about 8 Hz */ /* XXX: we use epoch here! */
	int random; /* 16 bit pseudo random */
	/* This is implementation specific */
	/* XXX: use cryptographicvally secure random, not Knuth's PRNG */
	Random rnd;
	
	/* Basically a tr */
	private String modhex_encode(String h) throws IllegalArgumentException {
		final String cset="cbdefghijklnrtuv";
		final String hset="0123456789abcdef";
		String m = h.toLowerCase();
		int len = m.length();
		int i,ord;
		String encoded = "";

		/* XXX range checking! */
		for (i = 0; i < len; i++) {
			ord = hset.indexOf(m.charAt(i));
			if ((ord < 0) || (ord > 15)) {
				throw new IllegalArgumentException("modhex incorrect");
			}
			encoded += cset.charAt(ord);
		}
		return encoded;
	}
	/* XXX: range checking!  (arbitrary size is possible) */
	private int crc(String buffer) throws IllegalArgumentException {
		byte[] buf;
		int bpos,i,j;
		int m_crc = 0x5af0; /* Magic start value */

		if (buffer.length() != 28) {
			throw new IllegalArgumentException("bufferlength incorrect");
		}
		buf = DatatypeConverter.parseHexBinary(buffer);

		/* Carefully simulating 16-bit unsigned Calaculation */
		/* Hints: Always & operator length; >>> operator fill in 0's as we need */
		for (bpos = 0; bpos < 14; bpos++) {
			m_crc ^= buf[bpos] & 0xff;
			for (i = 0; i < 8; i++) {
				j = m_crc & 1;
				m_crc >>>= 1;
				if (j != 0) {
					m_crc ^= 0x8408 & 0xffff;
				}
			}
		}
		return m_crc;
	}
	/* return current state as string */
	private String token() throws IllegalStateException {
		String hextok;
		int crc;
		SecretKey key;
		Cipher cipher;

		if (secret_aes_key.length() != 32) {
			throw new IllegalStateException("keylength incorrect");
		}
		try {
			key = new SecretKeySpec(DatatypeConverter.parseHexBinary(secret_aes_key), "AES");
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			hextok = secret_id +
				String.format("%02x%02x%02x%02x%02x%02x%02x%02x",
					counter%256, counter/256,
					timer%256, (timer/256)%256, timer/65536,
					counter_session,
					random%256, random/256);
			crc = crc(hextok);
			hextok += String.format("%02x%02x", crc%256, crc/256);
			return public_id+modhex_encode(DatatypeConverter.printHexBinary(cipher.doFinal(DatatypeConverter.parseHexBinary(hextok))));
		} catch (Exception e) {
		/* NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException */
		/* Should not happen */
			throw new IllegalStateException("Internal Encryption Parameters", e);
		}
		/* not reached */
	}
	private void sanitize() {
		random = rnd.nextInt(65536);
		counter %= 65536;
		counter_session %= 256;
		timer = (int)(System.currentTimeMillis()/1000/256/8); /* make epoch time in 24 bit - hope it is monoton */
	}
	private String rndhexstring(int c) {
		byte[] bytes;

		bytes = new byte[c];;
		rnd.nextBytes(bytes);
		return DatatypeConverter.printHexBinary(bytes).toLowerCase();
	}
	private String rndmodhexstring(int c) {
		return modhex_encode(rndhexstring(c));
	}
	/* new token from scratch */
	public yubikey() {
		rnd = new Random();
		public_id = rndmodhexstring(6);
		secret_aes_key = rndhexstring(16);
		secret_id = rndhexstring(6);
		counter = 0;
		insert();
	}
	/* new token from file */
	public yubikey(String s) throws Exception {
		String t;
		rnd = new Random();
		String[] lines = s.split(System.getProperty("line.separator"));
		try {
			if (lines.length != 5) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}

			if (lines[0].compareTo("Yubisim Token 0.1") != 0 ) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}

			if (! lines[1].startsWith("Public ID: ")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			t = lines[1].substring(11);
			if (! t.matches("^[cbdefghijklnrtuv]{12}$")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			public_id = t.trim();

			if (! lines[2].startsWith("Secret AES Key: ")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			t = lines[2].substring(16);
			if (! t.matches("^[0-9a-f]{32}$")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			secret_aes_key = t.trim();

			if (! lines[3].startsWith("Secret ID: ")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			t = lines[3].substring(11);
			if (! t.matches("^[0-9a-f]{12}$")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			secret_id = t.trim();

			if (! lines[4].startsWith("Counter: ")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			t = lines[4].substring(9);
			if (! t.matches("^[0-9]{1,5}$")) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}
			counter = Integer.parseInt(t);
			if ((counter < 0 ) || (counter > 65535)) {
				throw new IllegalArgumentException("format incorrect in "+s);
			}

		} catch (Exception e) {
			throw new Exception("Problem parsing string "+s, e);
		}
		insert();
	}

	/* simulated (re-)insert */
	public void insert() {
		counter++;
		counter_session = 0;
		sanitize();
	}
	/* simulated button press and return key sequence */
	public String button() {
		counter_session++;
		sanitize();
		return token();
	}
	/* return string containing state */
	public String serialise() {
		return	"Yubisim Token 0.1\n"+
			"Public ID: "+public_id+"\n"+
			"Secret AES Key: "+secret_aes_key+"\n"+
			"Secret ID: "+secret_id+"\n"+
			"Counter: "+counter+"\n";
	}
}

public class yubi_simulator {

	private static yubikey load(String fn) throws Exception { /* FileNotFoundException, IOException, Exception from yubikey */
	File f = new File(fn);
	InputStream in = new FileInputStream(f);
	byte[] b  = new byte[(int)f.length()];
	int len = b.length;
	int total = 0;

	while (total < len) {
		int result = in.read(b, total, len - total);
		if (result == -1) {
			break; /* EOF */
		}
		total += result;
	}
	in.close();
	return new yubikey(new String(b));
	}

	private static void save(yubikey yk, String fn) throws FileNotFoundException {
		PrintStream out = new PrintStream(fn);
		out.print(yk.serialise());
		out.close();
	}

	public static void main(String []args) throws Exception {
		String fn;

		if (args.length != 1) {
			System.err.println("Usage: yubi_simulator <tokenfile>");
			System.exit(1);
		}
		fn  = args[0];
		yubikey yk = load(fn);
		System.out.println(yk.button());
		save(yk, fn);
	}
}
