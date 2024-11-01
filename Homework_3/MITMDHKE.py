from Example_code.Example_DH_KDF_AES_AEAD import *

def start_keyExchange():

    # Step 1: Generate ECDH key pairs for Alice, Bob and Adversary
    alice_private_key, alice_public_key = generate_ecdh_key_pair()  # Alice has (x, X = g^x)
    bob_private_key, bob_public_key = generate_ecdh_key_pair()  # Bob has (y, B = g^y)

    #Step 2: Adversary generates ECDH key pairs for Alice and Bob
    adversary_private_key_alice, adversary_public_key_alice = generate_ecdh_key_pair()  # Adversary has (x_prime, E = g^x_prime)
    adversary_private_key_bob, adversary_public_key_2_bob = generate_ecdh_key_pair()  # Adversary has (y_prime , E = g^y_prime)

    # Step 3: Adversary intercepts Alice's public key and sends his own public key to Bob
    alice_public_key_for_bob = adversary_public_key_alice  # Adversary sends E to Bob
    bob_public_key_for_alice = adversary_public_key_2_bob  # Bob sends B to Alice

    # Step 3: Compute shared secret for adversary
    K_prime_alice = compute_shared_secret(adversary_private_key_bob, alice_public_key)  # Adversary computes X^y_prime
    K_prime_bob = compute_shared_secret(adversary_private_key_alice, bob_public_key)  # Adversary computes Y^x_pri

    # Step 4: Compute shared secret using ECDH for Alice and Bob
    K_bob = compute_shared_secret(bob_private_key, alice_public_key_for_bob)  # Bob computes X_prime^b
    K_alice = compute_shared_secret(alice_private_key, bob_public_key_for_alice)  # Alice computes Y_prime^x_prime

    # Ensure both shared secrets are the same
    assert K_prime_bob == K_alice, "Shared secrets do not match!"
    assert K_prime_alice == K_bob, "Shared secrets do not match!"




if __name__ == "__main__":
    start_keyExchange()
