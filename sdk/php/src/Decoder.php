<?php

declare(strict_types=1);

namespace Ubc;

/**
 * A pull-based streaming UBC v1 decoder. Each encrypted chunk is authenticated (GCM tag
 * verified) before any of its plaintext is returned (SPEC.md section 3, verify-before-release).
 */
final class Decoder
{
    private const int FOOTER_SIZE = 36;
    private const string FOOTER_MAGIC = 'UBCE';

    /** @var resource */
    private $source;

    private readonly DecodeOptions $options;
    private readonly Header $header;
    private readonly string $headerBytes;
    private readonly string $metadataDigest;
    private readonly RootAccumulator $root;
    private readonly ?string $baseNonce;

    /** @var MetadataEntry[] */
    public readonly array $metadata;

    private int $chunkIndex = 0;
    private int $plaintextSize = 0;
    private ?string $pending = null;
    private int $pendingOffset = 0;
    private ?string $prefetchedFooter = null;
    private bool $finished = false;
    private ?UbcException $terminalError = null;

    /** @param resource $source */
    public function __construct($source, ?DecodeOptions $options = null)
    {
        $this->source = $source;
        $this->options = $options ?? new DecodeOptions();

        $this->headerBytes = self::readExact($source, Header::SIZE);
        $this->header = Header::parse($this->headerBytes);

        $entries = [];
        $metadataRegion = '';
        if ($this->header->hasMetadata()) {
            $metadataRegion = self::readMetadataRegion($source, $this->options->maxMetaBytes);
            [$entries] = Metadata::parse($metadataRegion, 0, self::boundedCap($this->options->maxMetaBytes));
        }
        $this->metadata = $entries;

        $key = $this->options->key;
        if ($this->header->encrypted() && ($key === null || strlen($key) !== 32)) {
            throw new UbcException(ErrorCode::MissingKey);
        }
        if ($this->header->chunkCount > $this->options->maxChunkCount || $this->header->totalSize > $this->options->maxTotalSize) {
            throw new UbcException(ErrorCode::Truncated);
        }

        $this->metadataDigest = CryptoInternal::sha256($metadataRegion);
        $this->baseNonce = $this->header->encrypted() ? $this->header->baseNonce : null;
        $this->root = $this->header->encrypted()
            ? RootAccumulator::keyed(CryptoInternal::rootKey($key, $this->baseNonce))
            : RootAccumulator::plain();
        $this->root->update($this->headerBytes);
        $this->root->update($metadataRegion);
    }

    /** Reads up to $length bytes; returns '' at end of stream. */
    public function read(int $length): string
    {
        if ($this->terminalError !== null) {
            throw $this->terminalError;
        }
        if ($length === 0) {
            return '';
        }
        try {
            while ($this->pending === null && !$this->finished) {
                $this->loadNextChunk();
            }
        } catch (UbcException $e) {
            $this->terminalError = $e;
            throw $e;
        }
        if ($this->pending === null) {
            return '';
        }
        $available = strlen($this->pending) - $this->pendingOffset;
        $toCopy = min($available, $length);
        $output = substr($this->pending, $this->pendingOffset, $toCopy);
        $this->pendingOffset += $toCopy;
        if ($this->pendingOffset === strlen($this->pending)) {
            $this->pending = null;
            $this->pendingOffset = 0;
        }
        return $output;
    }

    /** Reads and discards everything, returning the fully assembled plaintext. */
    public function readAll(): string
    {
        $output = '';
        while (($chunk = $this->read(32 << 10)) !== '') {
            $output .= $chunk;
        }
        return $output;
    }

    private function loadNextChunk(): void
    {
        if ($this->chunkIndex === $this->header->chunkCount) {
            $this->verifyFooter();
            return;
        }
        $lengthPrefix = self::readExact($this->source, 4);
        $chunkLength = unpack('V', $lengthPrefix)[1];
        if ($chunkLength > $this->options->maxChunkLen) {
            throw new UbcException(ErrorCode::Truncated);
        }
        $body = self::readExact($this->source, $chunkLength);
        $this->root->update(CryptoInternal::sha256($body));

        $isLastChunk = $this->chunkIndex + 1 === $this->header->chunkCount;
        if ($this->header->encrypted() && $isLastChunk) {
            // Preflight the footer before authenticating the final chunk so a truncated
            // stream surfaces ERR_TRUNCATED rather than a misleading ERR_CHUNK_AUTH —
            // SPEC.md section 5's precedence requires truncation to win over chunk-auth
            // failure.
            $this->prefetchedFooter = self::readExact($this->source, self::FOOTER_SIZE);
        }

        if ($this->header->encrypted()) {
            if ($chunkLength < CryptoInternal::GCM_TAG_SIZE) {
                throw new UbcException(ErrorCode::ChunkAuth);
            }
            $aad = CryptoInternal::chunkAad($this->headerBytes, $this->metadataDigest, $this->chunkIndex);
            $plain = CryptoInternal::gcmDecrypt($this->options->key, CryptoInternal::chunkNonce($this->baseNonce, $this->chunkIndex), $body, $aad);
            if ($plain === null) {
                throw new UbcException(ErrorCode::ChunkAuth);
            }
        } else {
            $plain = $body;
        }

        if (strlen($plain) > $this->header->totalSize - $this->plaintextSize) {
            throw new UbcException(ErrorCode::RootMismatch);
        }
        $this->plaintextSize += strlen($plain);
        $this->chunkIndex++;
        $this->pending = $plain === '' ? null : $plain;
        $this->pendingOffset = 0;
    }

    private function verifyFooter(): void
    {
        $footer = $this->prefetchedFooter ?? self::readExact($this->source, self::FOOTER_SIZE);
        $footerRoot = substr($footer, 0, 32);
        $footerMagic = substr($footer, 32, 4);
        if ($footerMagic !== self::FOOTER_MAGIC) {
            throw new UbcException(ErrorCode::Truncated);
        }
        if ($this->plaintextSize !== $this->header->totalSize || !hash_equals($this->root->finish(), $footerRoot)) {
            throw new UbcException(ErrorCode::RootMismatch);
        }
        $trailing = fread($this->source, 1);
        if ($trailing !== false && $trailing !== '') {
            throw new UbcException(ErrorCode::TrailingData);
        }
        $this->finished = true;
    }

    /** @param resource $source */
    private static function readMetadataRegion($source, int $maxMetaBytes): string
    {
        $prefix = self::readExact($source, 4);
        $metadataLength = unpack('V', $prefix)[1];
        if ($metadataLength === 0 || $metadataLength > $maxMetaBytes) {
            throw new UbcException(ErrorCode::MetaMalformed);
        }
        try {
            $body = self::readExact($source, $metadataLength);
        } catch (UbcException $e) {
            if ($e->errorCode === ErrorCode::Truncated) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            throw $e;
        }
        return $prefix . $body;
    }

    /** @param resource $source */
    private static function readExact($source, int $length): string
    {
        $data = '';
        while (strlen($data) < $length) {
            $chunk = fread($source, $length - strlen($data));
            if ($chunk === false || $chunk === '') {
                throw new UbcException(ErrorCode::Truncated);
            }
            $data .= $chunk;
        }
        return $data;
    }

    private static function boundedCap(int $cap): int
    {
        return $cap > 0xFFFF_FFFF ? 0xFFFF_FFFF : $cap;
    }
}
