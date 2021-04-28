
export declare class IBOASodium {
    init (): Promise<void>

    crypto_core_ed25519_BYTES: number;
    crypto_core_ed25519_UNIFORMBYTES: number;
    crypto_core_ed25519_SCALARBYTES: number;
    crypto_core_ed25519_NONREDUCEDSCALARBYTES: number;
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number;
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number;

    crypto_core_ed25519_random(): Uint8Array;
    crypto_core_ed25519_from_uniform(r: Uint8Array): Uint8Array;
    crypto_core_ed25519_add(p: Uint8Array, q: Uint8Array): Uint8Array;
    crypto_core_ed25519_sub(p: Uint8Array, q: Uint8Array): Uint8Array;
    crypto_core_ed25519_is_valid_point(p: Uint8Array): boolean;
    crypto_core_ed25519_scalar_random(): Uint8Array;
    crypto_core_ed25519_scalar_add(x: Uint8Array, y: Uint8Array): Uint8Array;
    crypto_core_ed25519_scalar_sub(x: Uint8Array, y: Uint8Array): Uint8Array;
    crypto_core_ed25519_scalar_negate(s: Uint8Array): Uint8Array;
    crypto_core_ed25519_scalar_complement(s: Uint8Array): Uint8Array;
    crypto_core_ed25519_scalar_mul(x: Uint8Array, y: Uint8Array): Uint8Array;
    crypto_core_ed25519_scalar_invert(s: Uint8Array): Uint8Array;
    crypto_core_ed25519_scalar_reduce(s: Uint8Array): Uint8Array;

    crypto_scalarmult_ed25519(n: Uint8Array, p: Uint8Array): Uint8Array;
    crypto_scalarmult_ed25519_base(n: Uint8Array): Uint8Array;
    crypto_scalarmult_ed25519_base_noclamp(n: Uint8Array): Uint8Array;
    crypto_scalarmult_ed25519_noclamp(n: Uint8Array, p: Uint8Array): Uint8Array;

    randombytes_buf(n: number): Uint8Array;

    crypto_generichash(hash_length: number, message: Uint8Array, key?: Uint8Array): Uint8Array;

    crypto_aead_chacha20poly1305_ietf_keygen(): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        message: Uint8Array,
        additional_data: Uint8Array | null,
        secret_nonce: Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array
    ): Uint8Array;

    crypto_aead_xchacha20poly1305_ietf_decrypt(
        secret_nonce: Uint8Array | null,
        ciphertext: Uint8Array,
        additional_data: Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array
    ): Uint8Array;
}

