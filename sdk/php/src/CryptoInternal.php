<?php

declare(strict_types=1);

namespace Ubc;

/**
 * Shared AES-256-GCM / HMAC-SHA-256 primitives (SPEC.md sections 3-4), used by both the
 * one-shot {@see Crypto} path and the streaming encoder/decoder. Keeping a single
 * implementation here means the two paths cannot silently diverge on nonce, AAD, or
 * root-key derivation.
 */
final class CryptoInternal
{
    public const int GCM_TAG_SIZE = 16;
    private const string ROOT_INFO = 'UBC1 root authentication';
    private const int NONCE_SIZE = 12;

    private function __construct()
    {
    }

    public static function rootKey(string $key, string $baseNonce): string
    {
        $prk = hash_hmac('sha256', $key, $baseNonce, true);
        return hash_hmac('sha256', self::ROOT_INFO . "\x01", $prk, true);
    }

    public static function chunkNonce(string $baseNonce, int $index): string
    {
        $indexBytes = pack('P', $index) . "\x00\x00\x00\x00";
        $nonce = '';
        for ($i = 0; $i < self::NONCE_SIZE; $i++) {
            $nonce .= chr(ord($baseNonce[$i]) ^ ord($indexBytes[$i]));
        }
        return $nonce;
    }

    public static function chunkAad(string $headerBytes, string $metadataDigest, int $index): string
    {
        return $headerBytes . $metadataDigest . pack('P', $index);
    }

    public static function gcmEncrypt(string $key, string $nonce, string $plaintext, string $aad): string
    {
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, self::GCM_TAG_SIZE);
        if ($ciphertext === false) {
            throw new \RuntimeException('AES-256-GCM encryption failed unexpectedly');
        }
        return $ciphertext . $tag;
    }

    /**
     * Returns null (not plaintext) on a tag mismatch — caller maps that to ERR_CHUNK_AUTH.
     * Uses a strict === false check against openssl_decrypt's return value rather than a
     * loose/falsy check, since a legitimately empty-string plaintext is also falsy in PHP.
     */
    public static function gcmDecrypt(string $key, string $nonce, string $body, string $aad): ?string
    {
        $ciphertextLength = strlen($body) - self::GCM_TAG_SIZE;
        $ciphertext = substr($body, 0, $ciphertextLength);
        $tag = substr($body, $ciphertextLength);
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        return $plaintext === false ? null : $plaintext;
    }

    public static function sha256(string $data): string
    {
        return hash('sha256', $data, true);
    }
}
