// Local demo harness for <attestto-signature-card>. Renders the three signature
// kinds with sample data so the shared card can be reviewed in isolation before
// wiring it into the website and the desktop station.
import '../src/components/attestto-signature-card.js'
import type { SignatureCardModel } from '../src/model/signature-card.js'
import { setLang, currentLang } from '../src/i18n.js'

const samples: SignatureCardModel[] = [
  {
    index: 1,
    signerName: 'EIDAS Certificado Pruebas',
    country: 'ES',
    status: 'structure-only',
    subtitle: 'Test certificate · AC FNMT Usuarios',
    jurisdiction: 'Spain · España',
    method: 'PAdES · adbe.pkcs7',
    methodTech: 'adbe.pkcs7.detached',
    signedAt: null, // real EIDAS test sig carries no parseable signing time → "Unknown"
    cert: { validFrom: '2024-03-11', validTo: '2028-03-11' },
    nationalId: { masked: 'IDCES-•••••72C', full: 'IDCES-99999972C' },
    capabilities: [
      { label: 'Authentication', kind: 'eku' },
      { label: 'Document signing', kind: 'eku' },
      { label: '1.2.840.113583.1.1.5', kind: 'eku' },
    ],
    officialVerifier: { name: 'VALIDe (Gobierno de España)', url: 'https://valide.redsara.es' },
    signatureImage: null,
    handle: null,
    ltv: { tier: 'none', hasTimestamp: false, revocationSource: 'none' },
    trustMarks: [{ label: 'eIDAS (test certificate)', scheme: 'untrusted' }],
    tech: {
      standard: 'adbe.pkcs7.detached',
      producer: 'Attestto Desktop Station',
      byteRange: [0, 1420, 22380, 4120],
      pkcs7Size: 8859,
      // Structure-only ≠ no chain: the certs parse, they just don't chain to a trusted root.
      chain: [
        { name: 'Unknown', issuer: 'FNMT-RCM', from: '2008-10-29', to: '2030-01-01', country: 'ES' },
        { name: 'AC FNMT Usuarios', issuer: 'FNMT-RCM', from: '2014-10-28', to: '2029-10-28', country: 'ES' },
        { name: 'EIDAS CERTIFICADO PRUEBAS - 99999972C', from: '2024-03-11', to: '2028-03-11', country: 'ES' },
      ],
    },
  },
  {
    index: 2,
    signerName: 'José Javier Badilla Torres',
    country: 'CR',
    status: 'verified',
    subtitle: 'Persona Física · CR Firma Digital',
    jurisdiction: 'Costa Rica',
    method: 'CAdES · ETSI.CAdES',
    methodTech: 'ETSI.CAdES.detached',
    signedAt: '2026-07-19 15:55',
    cert: { validFrom: '2023-03-09', validTo: '2027-03-08' },
    nationalId: { masked: 'CPF-•••••••748', full: 'CPF-01130748' },
    capabilities: [
      { label: 'Non-repudiation', kind: 'keyusage' },
      { label: 'Document signing', kind: 'keyusage' },
      { label: 'Email protection', kind: 'eku' },
    ],
    officialVerifier: { name: 'Firma Digital CR', url: 'https://firmadigital.go.cr' },
    trustLinks: [
      { label: 'did:pki:cr:sinpe:persona-fisica (resolver)', url: 'https://resolver.attestto.com/1.0/identifiers/did:pki:cr:sinpe:persona-fisica' },
    ],
    signatureImage: null,
    handle: null,
    ltv: {
      tier: 'LT',
      hasTimestamp: true,
      timestampAt: '2026-07-19 15:56',
      timestampAuthority: 'TSA BCCR',
      revocationSource: 'embedded',
    },
    trustMarks: [
      { label: 'CR Firma Digital', scheme: 'cr-firma' },
      { label: 'Qualified (CR)', scheme: 'qualified' },
    ],
    tech: {
      standard: 'ETSI.CAdES.detached',
      signedAtISO: '2026-07-19T15:55:20.000Z',
      reason: 'Aprobación del documento',
      producer: 'Attestto Desktop Station',
      digestAlgorithm: 'SHA-256',
      byteRange: [0, 27428, 71352, 151319],
      pkcs7Size: 21961,
      pkcs7Hex: '308206a906092a864886f70d010702a082069a308206960201013100...',
      location: 'Liberia, CR',
      chain: [
        { name: 'CA RAÍZ NACIONAL — Costa Rica v2', issuer: 'MICITT', from: '2015', to: '2039', country: 'CR' },
        { name: 'CA POLÍTICA PERSONA FÍSICA v2', issuer: 'MICITT', from: '2015', to: '2031', country: 'CR' },
        { name: 'CA SINPE — PERSONA FÍSICA v2', issuer: 'BCCR', from: '2023', to: '2031', country: 'CR' },
        { name: 'José Javier Badilla Torres (FIRMA)', issuer: 'Persona Física', from: '2023', to: '2027', country: 'CR' },
      ],
    },
  },
  {
    index: 3,
    signerName: 'Eduardo Antonio Chongkan Lios',
    country: 'CR',
    status: 'self-attested',
    subtitle: 'Attestto self-attested · Nivel B',
    jurisdiction: 'Costa Rica',
    method: 'Ed25519 · self-attested',
    methodTech: 'attestto.self-attested.v1',
    signedAt: '2026-07-16 20:12',
    nationalId: null,
    // Relying-party-relevant capabilities (what the signature can DO), mapped
    // from the DID verification relationships — not internal/defensive framing.
    capabilities: [
      { label: 'Document signing', kind: 'attestto' },
      { label: 'Identity assertion', kind: 'attestto' },
      { label: 'Authentication', kind: 'attestto' },
    ],
    officialVerifier: { name: 'Attestto resolver', url: 'https://resolver.attestto.com' },
    signatureImage: null,
    handle: 'cr-111290877.attestto.id',
    trustMarks: [{ label: 'Attestto · Nivel B', scheme: 'attestto' }],
    tech: {
      standard: 'attestto.self-attested.v1',
      signedAtISO: '2026-07-16T20:12:49.000Z',
      digestAlgorithm: 'SHA-256',
    },
  },
]

const root = document.getElementById('cards')!
for (const s of samples) {
  const el = document.createElement('attestto-signature-card')
  ;(el as any).signature = s
  root.appendChild(el)
}

document.getElementById('lang')!.addEventListener('click', () => {
  setLang(currentLang() === 'en' ? 'es' : 'en')
})
