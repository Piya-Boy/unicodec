<?php

declare(strict_types=1);

namespace Ubc;

/**
 * A write-then-close streaming UBC v1 encoder. Plaintext is spooled to a temp file until its
 * final size is known, because the v1 header precedes the payload and carries both size and
 * chunk count (SPEC.md section 2.1).
 *
 * Uses tmpfile() for the spool: PHP creates it with safe (owner-only) permissions and
 * automatically unlinks it when the resource is closed or the script ends, even on an
 * abandoned Encoder — unlike the Java/.NET ports, no deleteOnExit()/finalizer safety net is
 * needed here because the PHP runtime already provides that guarantee natively.
 */
final class Encoder
{
    /** @var resource */
    private $sink;

    /** @var resource */
    private $spool;

    private readonly string $metadata;
    private readonly EncodeOptions $options;
    private int $totalSize = 0;
    private bool $finished = false;
    private bool $closed = false;

    /**
     * @param resource $sink
     * @param MetadataEntry[] $entries
     */
    public function __construct($sink, array $entries, ?EncodeOptions $options = null)
    {
        $this->sink = $sink;
        $this->options = $options ?? new EncodeOptions();
        $this->metadata = Metadata::encode($entries);
        $spool = tmpfile();
        if ($spool === false) {
            throw new UbcException(ErrorCode::Truncated);
        }
        $this->spool = $spool;
    }

    public function write(string $data): int
    {
        if ($this->finished) {
            throw new \LogicException('encoder is already finished');
        }
        $written = fwrite($this->spool, $data);
        if ($written === false) {
            throw new \RuntimeException('spool write failed');
        }
        $this->totalSize += $written;
        return $written;
    }

    /** Writes the header, payload, authenticated root, and footer to the sink, then closes it. */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        try {
            if (!$this->finished) {
                $this->finish();
            }
        } finally {
            fclose($this->spool);
        }
    }

    private function finish(): void
    {
        $this->finished = true;
        $chunkSize = $this->options->chunkSize;
        $encrypted = $this->options->key !== null;
        if ($encrypted && $chunkSize > 0xFFFF_FFEF) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        $chunkCount = $this->totalSize === 0 ? 0 : intdiv($this->totalSize + $chunkSize - 1, $chunkSize);
        if ($encrypted) {
            $baseNonce = $this->options->baseNonce ?? random_bytes(12);
        } else {
            $baseNonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        }

        $header = new Header(
            ($encrypted ? Header::FLAG_ENCRYPTED : 0) | ($this->metadata !== '' ? Header::FLAG_HAS_METADATA : 0),
            $encrypted ? Header::HASH_HMAC_SHA256 : Header::HASH_SHA256,
            $encrypted ? Header::AEAD_AES_256_GCM : Header::AEAD_NONE,
            $chunkSize,
            $chunkCount,
            $this->totalSize,
            $baseNonce,
        );
        $headerBytes = $header->toBytes();
        fwrite($this->sink, $headerBytes);
        fwrite($this->sink, $this->metadata);

        $metadataDigest = CryptoInternal::sha256($this->metadata);
        $root = $encrypted
            ? RootAccumulator::keyed(CryptoInternal::rootKey($this->options->key, $baseNonce))
            : RootAccumulator::plain();
        $root->update($headerBytes);
        $root->update($this->metadata);

        fseek($this->spool, 0);
        $index = 0;
        for ($written = 0; $written < $this->totalSize; $written += $chunkSize, $index++) {
            $length = min($chunkSize, $this->totalSize - $written);
            $chunk = self::readExact($this->spool, $length);
            if ($encrypted) {
                $aad = CryptoInternal::chunkAad($headerBytes, $metadataDigest, $index);
                $body = CryptoInternal::gcmEncrypt($this->options->key, CryptoInternal::chunkNonce($baseNonce, $index), $chunk, $aad);
            } else {
                $body = $chunk;
            }
            fwrite($this->sink, pack('V', strlen($body)));
            fwrite($this->sink, $body);
            $root->update(CryptoInternal::sha256($body));
        }

        fwrite($this->sink, $root->finish());
        fwrite($this->sink, 'UBCE');
    }

    /** @param resource $stream */
    private static function readExact($stream, int $length): string
    {
        $data = '';
        while (strlen($data) < $length) {
            $chunk = fread($stream, $length - strlen($data));
            if ($chunk === false || $chunk === '') {
                throw new \RuntimeException('unexpected end of spool file');
            }
            $data .= $chunk;
        }
        return $data;
    }
}
