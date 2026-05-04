import {X509Certificates} from "@peculiar/x509";
import {getCertificateFor, ProcessorGeneration} from "./certificate-chain";
const webcrypto = require('crypto')?.webcrypto ?? window.crypto

const Buffer: typeof import("node:buffer").Buffer = require("buffer/").Buffer
globalThis.Buffer = Buffer

/**
 * Wraps an AMD SEV-SNP attestation with accessors to access its different fields
 *
 * https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf (page 46 - table 22)
 */
export class Attestation {
    constructor(
        private readonly buffer: Buffer
    ) {
    }

    /**
     * @return 32bits unsigned integer
     */
    get version() {
        return this.buffer.readUInt32LE(0x00)
    }

    /**
     * @return 32bits unsigned integer
     */
    get guest_svn() {
        return this.buffer.readUInt32LE(0x04)
    }

    /**
     * @return 64bits unsigned integer / bitfield
     *
     * TODO: table 9
     */
    get policy() {
        return this.buffer.readBigUInt64LE(0x08)
    }

    get family_id() {
        return this.buffer.subarray(0x10, 0x20)
    }

    get image_id() {
        return this.buffer.subarray(0x20, 0x30)
    }

    /**
     * @return 32bits unsigned integer
     */
    get vmpl() {
        return this.buffer.readUInt32LE(0x30)
    }

    get signature_algo(): SignatureAlgo {
        return this.buffer.readUInt32LE(0x34) as SignatureAlgo
    }

    /**
     * @return 64bits unsigned integer
     */
    get current_tcb() {
        return new TCBVersion(Buffer.from(this.buffer.subarray(0x38, 0x40)));
    }


    /**
     * @return 64bits unsigned integer
     *
     * TODO table 23
     */
    get platform_info() {
        return this.buffer.readBigUInt64LE(0x40)
    }

    get platform_info_flags(): Set<PlatformInfoFlag> {
        const bitField = this.buffer.readUInt8(0x47);
        const flags = Object.values(PlatformInfoFlag).flatMap((offset: unknown) => {
            if (typeof offset !== 'number') {
                return [];
            }

            const bitValue = (bitField >> offset) & 0x01;

            if (bitValue == 1) {
                return [offset as PlatformInfoFlag]
            } else {
                return [];
            }
        })
        return new Set(flags);
    }

    get signing_key(): SigningKey {
        const v = (this.buffer.readUInt8(0x4B) >> 2) & 7;
        return v as SigningKey
    }

    get mask_chip_key(): boolean {
        const v = (this.buffer.readUInt8(0x4B) >> 1) & 1;
        return v == 1
    }

    /**
     * Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
     */
    get author_key_en(): boolean {
        const v = (this.buffer.readUInt8(0x4B)) & 1;
        return v == 1
    }

    get report_data(): Buffer {
        return Buffer.from(this.buffer.subarray(0x50, 0x90))
    }

    get measurement(): Buffer {
        return Buffer.from(this.buffer.subarray(0x90, 0xC0))
    }

    get host_data(): Buffer {
        return Buffer.from(this.buffer.subarray(0xC0, 0xE0))
    }

    get id_key_digest(): Buffer {
        return Buffer.from(this.buffer.subarray(0xE0, 0x110))
    }

    get author_key_digest(): Buffer {
        return Buffer.from(this.buffer.subarray(0x110, 0x140))
    }

    get report_id(): Buffer {
        return Buffer.from(this.buffer.subarray(0x140, 0x160))
    }

    get report_id_ma(): Buffer {
        return Buffer.from(this.buffer.subarray(0x160, 0x180))
    }

    /**
     * Reported TCB version used to derive the VCEK that signed this report.
     */
    get reported_tcb(): TCBVersion {
        return new TCBVersion(Buffer.from(this.buffer.subarray(0x180, 0x188)));
    }

    /**
     * if MaskChipId is set to 0, Identifier unique to the chip as output by GET_ID. Otherwise, set to 0h.
     */
    get chip_id(): Buffer {
        return Buffer.from(this.buffer.subarray(0x1A0, 0x1E0))
    }

    get committed_tcb(): TCBVersion {
        return new TCBVersion(Buffer.from(this.buffer.subarray(0x1E0, 0x1E8)));
    }

    /**
     * The build number of CurrentVersion (uint8)
     */
    get current_build(): number {
        return this.buffer.readUInt8(0x1E8)
    }

    /**
     * The minor number of CurrentVersion (uint8)
     */
    get current_minor(): number {
        return this.buffer.readUInt8(0x1E9)
    }

    /**
     * The major number of CurrentVersion (uint8)
     */
    get current_major(): number {
        return this.buffer.readUInt8(0x1EA)
    }

    /**
     * The build number of CommittedVersion (uint8)
     */
    get committed_build(): number {
        return this.buffer.readUInt8(0x1EC)
    }

    /**
     * The minor number of CommittedVersion (uint8)
     */
    get committed_minor(): number {
        return this.buffer.readUInt8(0x1ED)
    }

    /**
     * The major number of CommittedVersion (uint8)
     */
    get committed_major(): number {
        return this.buffer.readUInt8(0x1EE)
    }

    /**
     * The CurrentTcb at the time the guest was launched or imported. (uint64)
     */
    get launch_tcb(): TCBVersion {
        return new TCBVersion(Buffer.from(this.buffer.subarray(0x1F0, 0x1F8)));
    }

    get signature(): Buffer {
        return Buffer.from(this.buffer.subarray(0x2A0, Math.min(this.buffer.length, 0x5A0)))
    }

    get parsed_signature(): Buffer {
        const base = this.signature;

        switch (this.signature_algo) {
            case SignatureAlgo.ECDSA_P384_SHA384:
                const signature_length = 48; // 384bits = 48bytes
                const midpoint = 72;
                return Buffer.from(
                    [
                        ...(base.subarray(0, signature_length).reverse()),
                        ...(base.subarray(midpoint, midpoint + signature_length).reverse()),
                    ])

            default:
                throw new Error("Unknown signature algorithm")
        }
    }

    get has_signature(): boolean {
        return this.buffer.length >= 0x2A1
    }

    /**
     * Retrieves the key chain for the processor generation and verifies the attestation matches
     * @param processorFamily
     */
    async verifyForFamily(processorFamily: ProcessorGeneration = ProcessorGeneration.Genoa) {
        const cert = await getCertificateFor(this, processorFamily);
        return this.verifyWithCertificate(cert)
    }

    /**
     * Verifies that an attestation is correct
     * @param certificates a chain of certificates, of which the first one is the self-signed root and the last one
     *  is the device key ; or a public key
     * @param signature the signature to use, defaults to the one present in the attestation (if present)
     */
    async verifyWithCertificate(certificates: X509Certificates, signature?: Buffer) {
        if (!this.has_signature && !signature) {
            throw new Error("No embedded signature and no signature provided.");
        }

        for (let i = 0 ; i < certificates.length ; ++i) {
            const previous = (i > 0 ? certificates[i - 1] : undefined);
            if (!await certificates[i].verify(previous)) {
                throw new Error(`Invalid certificate chain. Certificate ${i + 1} (${certificates[i].subject}) not signed by previous (${previous?.subject ?? 'N/A'}).`)
            }
        }

        // Valid certificate chain - keep public key from last one
        const publicKey = await certificates[certificates.length - 1].publicKey.export();
        return this.verifyWithPublicKey(publicKey, signature);
    }

    async verifyWithPublicKey(key: CryptoKey, signature?: Buffer) {
        if (!this.has_signature && !signature) {
            throw new Error("No embedded signature and no signature provided.");
        }

        const result = await webcrypto.subtle.verify(signatureAlgoToCryptoAlgo(this.signature_algo), key, signature ?? this.parsed_signature, this.signed_data);

        if (!result) {
            throw new Error("Incorrect attestation signature!")
        }
    }

    get signed_data(): Buffer {
        return Buffer.from(this.buffer.subarray(0x00, 0x2A0));
    }
}

export enum SigningKey {
    VCEK = 0,
    VLEK = 1,
    NONE = 7
}

export enum SignatureAlgo {
    /**
     * ECDSA P-384 with SHA-384
     */
    ECDSA_P384_SHA384 = 0x1
}

export enum PlatformInfoFlag {

    /**
     * Indicates that SMT is enabled in the system.
     */
    SMT_ENABLED = 0x00,

    /**
     * Indicates that TSME is enabled in the system.
     */
    TSME_ENABLED = 0x01,

    /**
     * Indicates that the platform is using error correcting codes for memory.
     * Present when EccMemReporting feature bit is set.
     */
    ECC_ENABLED = 0x02,

    /**
     * Indicates that the RAPL feature is disabled
     */
    RAPL_DISABLED = 0x3,

    /**
     * Indicates ciphertext hiding is enabled.
     */
    CIPHERTEXT_HIDING_ENABLED = 0x4
}

export function signatureAlgoToCryptoAlgo(algo: SignatureAlgo): Algorithm | EcdsaParams | undefined {
    switch (algo) {
        case SignatureAlgo.ECDSA_P384_SHA384:
            return { name: 'ECDSA', hash: { name: 'SHA-384' } } satisfies EcdsaParams;

        default:
            return undefined;
    }
}

export class TCBVersion {
    constructor(private readonly buffer: Buffer) {
    }

    // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf, section 2.2 TCB_VERSION

    /**
     * @return uint8
     */
    get bootloader(): number {
        return this.buffer.readUInt8(0)
    }

    /**
     * @return uint8
     */
    get tee(): number {
        return this.buffer.readUInt8(1)
    }

    /**
     * @return uint8
     */
    get snp(): number {
        return this.buffer.readUInt8(6)
    }

    /**
     * @return uint8
     */
    get microcode(): number {
        return this.buffer.readUInt8(7)
    }

    toString(): string {
        return `TCBVersion{microcode=${this.microcode}, snp=${this.snp}, tee=${this.tee}, bootloader=${this.bootloader}}`
    }
}