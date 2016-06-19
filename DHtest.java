public class DHtest {

	public static void main(String[] args) {
		
		DH2048 dh_api = new DH2048();
		
		/* THIS IS ALICE's SIDE STEP 1 */

		BigInteger a = dh_api.generateRandomComponent(); // Alice generates a random number
		
		BigInteger alice_pub_key = dh_api.computePubKey(a); // Alice Computes her public key using the random number

		// Now you need to send Alice's public key to Bob (obviously we are not doing so here)

		/* END OF ALICE's SIDE STEP 1 */



		/* Bob's SIDE STEP 1 */
		BigInteger b = dh_api.generateRandomComponent(); // Bob generates a random number
		
		BigInteger bob_pub_key = dh_api.computePubKey(b); // Bob computes his public key using his random number

		// Now you need to send Bob's public key to Alice (obviously we are not doing so here)

		/* END OF Bob's SIDE STEP 1 */

		
		/* THIS IS ALICE's SIDE STEP 2 */
	
		BigInteger alice_common = dh_api.computeDHKey(bob_pub_key, a); // Alice computes the common secret using Bob's received public key and her random number
		byte [] session_key = dh_api.extractSmallerCommonKey(512, alice_common); // Alice exctracts 512 bits of the common secret
		System.out.println("Alice's common secret: "+session_key); // this key should be used for symmetric encryptin between Alice and Bob
		// you're done here
		/* END OF ALICE's SIDE STEP 2 */



		/* THIS IS Bob's SIDE STEP 2 */
		BigInteger bob_common = dh_api.computeDHKey(alice_pub_key, b); // Bob computes the common secret using Alice's received public key and his random number
		byte [] session_key2 = dh_api.extractSmallerCommonKey(512, bob_common); // Bob exctracts 512 bits of the common secret		
		
		System.out.println("Bob's common secret: "+bob_common); // this key should be used for symmetric encryptin between Alice and Bob
		// you're done here
		/* END OF Bob's SIDE STEP 2 */
		
	}
	
}

