import {Attestation} from "./attestation";
import * as x509 from "@peculiar/x509";
import {X509Certificate} from "@peculiar/x509";

export enum ProcessorGeneration {
    /**
     * 3rd Gen AMD EPYC Processor (Standard)
     */
    Milan = 'Milan',

    /**
     * 4th Gen AMD EPYC Processor (Standard)
     */
    Genoa = 'Genoa',

    /**
     * 4th Gen AMD EPYC Processor (Performance)
     */
    Bergamo = 'Bergamo',

    /**
     * 4th Gen AMD EPYC Processor (Edge)
     */
    Siena = 'Siena',
}

const ProcessorGenerationName: Record<ProcessorGeneration, string> = {
    [ProcessorGeneration.Milan]: 'Milan',
    [ProcessorGeneration.Genoa]: 'Genoa',
    [ProcessorGeneration.Bergamo]: 'Genoa',
    [ProcessorGeneration.Siena]: 'Genoa',
}

const AMD_KDS_URL = "https://kdsintf.amd.com"

const known_chains = new Map<ProcessorGeneration, X509Certificate[]>;
const vceks = new Map<string, X509Certificate>;

async function getCertificateChain(generation: ProcessorGeneration) {
    if (known_chains.has(generation)) {
        return known_chains.get(generation)!;
    }

    const cert_chain_url = `${AMD_KDS_URL}/vcek/v1/${ProcessorGenerationName[generation]}/cert_chain`
    const cert_chain_data = await fetch(cert_chain_url).then(async data => {
        const text = await data.text();
        const lines = text.split('\n');
        const cert_ends = lines.flatMap((data, index) => {
            if (data.includes("END CERTIFICATE")) {
                return [index]
            }
            return []
        });
        const cert_begins = [0, ...cert_ends.slice(0, cert_ends.length - 1).map(i => i + 1)];

        return cert_begins.map((begin, index) => {
            const cert_end = cert_ends[index];
            const cert_data = lines.slice(begin, cert_end + 1);
            return new x509.X509Certificate(cert_data.join('\n'))
        }).reverse();
    });

    known_chains.set(generation, cert_chain_data);
    return cert_chain_data;
}

async function getVCEK(attestation: Attestation, generation: ProcessorGeneration) {
    const cpuid = attestation.chip_id.toString('hex');
    const tcbver = attestation.reported_tcb;
    const vcek_url = `${AMD_KDS_URL}/vcek/v1/${ProcessorGenerationName[generation]}/${cpuid}?blSPL=${tcbver.bootloader}&teeSPL=${tcbver.tee}&snpSPL=${tcbver.snp}&ucodeSPL=${tcbver.microcode}`

    if (vceks.has(vcek_url)) {
        return vceks.get(vcek_url)!;
    }

    const veck_data = await fetch(vcek_url);
    const vcek_cert = new x509.X509Certificate(await veck_data.arrayBuffer());
    vceks.set(vcek_url, vcek_cert);

    return vcek_cert;
}

/**
 * Gets the certificate chain for a specific attestation
 * @param attestation the attestation containing the chip_id
 */
export async function getCertificateFor(attestation: Attestation, generation: ProcessorGeneration = ProcessorGeneration.Genoa) {
    const cert_chain_data = await getCertificateChain(generation);
    const vcek_cert = await getVCEK(attestation, generation);

    return new x509.X509Certificates([...cert_chain_data, vcek_cert]);
}