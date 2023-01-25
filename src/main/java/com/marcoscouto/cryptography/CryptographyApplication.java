package com.marcoscouto.cryptography;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;

@Slf4j
@SpringBootApplication
public class CryptographyApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(CryptographyApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {

		var password = "password";
		var wrongPassword = "wrong_password";

		// Bcrypt
		var salt = BCrypt.gensalt();
			// generate hash
		var hashPassword = BCrypt.hashpw(password, salt);
			// verify correct hash
		var result = BCrypt.checkpw(password, hashPassword);
		log.info("[BCRYPT] It's {} that password \"{}\" check with hash {}", result, password, hashPassword);
			// verify wrong hash
		result = BCrypt.checkpw(wrongPassword, hashPassword);
		log.info("[BCRYPT] It's {} that password \"{}\" check with hash {}", result, wrongPassword, hashPassword);

		// Message Digest
		var digest = MessageDigest.getInstance("SHA-256");
		digest.update("salt".getBytes());
		var digestHash = digest.digest(password.getBytes());
		log.info("[MESSAGE DIGEST] Hash with sha-256 algorithm {}", Hex.encodeHexString(digestHash));

		// Cipher
		var keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		var key = keyGen.generateKey();
		var secret = new SecretKeySpec(key.getEncoded(), "AES");
		var cipherAlgorithm = Cipher.getInstance("AES");
			// encrypt
		cipherAlgorithm.init(Cipher.ENCRYPT_MODE, secret);
		var cipherEncryptResult = cipherAlgorithm.doFinal(password.getBytes());
		log.info("[CIPHER] Encrypt result with AES is {}", new String(cipherEncryptResult));
			// decrypt
		cipherAlgorithm.init(Cipher.DECRYPT_MODE, secret);
		var cipherDecryptResult = cipherAlgorithm.doFinal(cipherEncryptResult);
		log.info("[CIPHER] Decrypt result with AES is {}", new String(cipherDecryptResult));

	}

}
