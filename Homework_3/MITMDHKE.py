from Example_code.Example_DH_KDF_AES_AEAD import *

def start_keyExchange():

    # Step 1: Generate ECDH key pairs for Alice, Bob and Adversary
    alice_x, alice_X = generate_ecdh_key_pair()  # Alice has (x, X = g^x)
    bob_y, bob_Y = generate_ecdh_key_pair()  # Bob has (y, B = g^y)

    #Step 2: Adversary generates ECDH key pairs for Alice and Bob
    adversary_x_prime, adversary_X_prime = generate_ecdh_key_pair()  # Adversary has (x_prime, E = g^x_prime)
    adversary_y_prime, adversary_Y_prime = generate_ecdh_key_pair()  # Adversary has (y_prime , E = g^y_prime)

    # Step 3: Compute shared secrets MitM attack
    K_prime_alice = compute_shared_secret(adversary_y_prime, alice_X)  # Adversary computes X^y_prime
    K_alice = compute_shared_secret(alice_x, adversary_Y_prime)  # Alice computes Y_prime^x

    K_prime_bob = compute_shared_secret(adversary_x_prime, bob_Y)  # Adversary computes Y^x_prime
    K_bob = compute_shared_secret(bob_y, adversary_X_prime)  # Bob computes X_prime^y


    # Ensure both shared secrets are the same
    assert K_prime_alice == K_alice, "Shared secrets do not match!"
    assert K_prime_bob == K_bob, "Shared secrets do not match!"




if __name__ == "__main__":
    start_keyExchange()
