/* 
 * Class Name:         DH2048
 * Class Dependencies: SecureRandom, BigInteger
 * Author: Hussien Yousef (l0ve)
 * CLASS DISCRIPTION:  THIS CLASS IMPLMENENTS DIFFIE-HELLMAN 2048 bit IN JAVA LANGUAGE
 * Follows RFC 3526 :  https://www.ietf.org/rfc/rfc3526.txt
 */

import java.math.BigInteger;
import java.security.SecureRandom;

class DH2048 {
	private final String prime_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
	private BigInteger p;
	private SecureRandom sec_rand;
	
	/* class constructor */
	public DH2048(){
		this.sec_rand = new SecureRandom();
		this.warmupRandom();
		this.generate_p();
	}
	
	/* this function generates random "myComponent" to be used in [g^myComponent mod p] */
	public BigInteger generateRandomComponent(){
		byte [] rnd = new byte[256];
		this.sec_rand.nextBytes(rnd);
		BigInteger random_component = new BigInteger(rnd);
		return random_component;
	}
	
	/* this function generates the public key of one party to be sent to the other */
	public BigInteger computePubKey(BigInteger myComponent){
		BigInteger g = BigInteger.valueOf((long) 2);
		return g.modPow(myComponent, this.p);
	}
	
	/* this function computes the common secret [(received_PublicKey)^MyComponent mod p ] */
	public BigInteger computeDHKey(BigInteger received_PublicKey, BigInteger myComponent){
		return received_PublicKey.modPow(myComponent, this.p);
	}
	
	/* generates the p component of g^a mod p
	   p here is recommended by RFC 3526 for DH 2048 bit (proven secure) */
	public void generate_p(){
		this.p = new BigInteger(this.prime_hex, 16);
	}
	
	/* generate some random bytes to warm up the random number generator */
	public void warmupRandom(){
		byte [] rnd = new byte[256];
		for(int x = 0; x < 5; x++)
			this.sec_rand.nextBytes(rnd);
	}
	
	/* exctracts the number of bits you want from the common secret to be used as session(symmetric) key */
	public byte [] extractSmallerCommonKey(int numberOfBits, BigInteger commonSecret){
		byte [] shortenedSecretInBytes = new byte[(int) Math.ceil((numberOfBits/8))];
		byte [] fullSecretInBytes = commonSecret.toByteArray();
		
		System.arraycopy(fullSecretInBytes, 0, shortenedSecretInBytes, 0, shortenedSecretInBytes.length);
		return shortenedSecretInBytes;
	}
}
