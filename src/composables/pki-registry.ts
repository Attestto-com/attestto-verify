/**
 * PKI Registry — Multi-country trust store for certificate recognition.
 *
 * Each entry defines how to identify certificates from a national PKI:
 * - OID-based detection (most reliable)
 * - Root CA name matching (fallback)
 * - National ID prefix detection (heuristic)
 * - Signer name patterns (last resort)
 *
 * Adding a country: add an entry here + a test in certificate-parser.spec.ts.
 * No other code changes needed — identifyPki() iterates the registry.
 */

export interface PkiRegistryEntry {
  /** ISO 3166-1 alpha-2 */
  countryCode: string
  /** Short display name: "CR Firma Digital" */
  name: string
  /** Full official name */
  fullName: string
  /** OID arc root (e.g. "2.16.188" for CR) */
  oidArc: string
  /** Specific policy OIDs to match against certificate policies */
  policyOids: string[]
  /** Root CA common names (uppercase for matching) */
  rootCaNames: string[]
  /** Intermediate CA name patterns (uppercase) */
  intermediateCaPatterns: string[]
  /** Issuer organization patterns (uppercase) */
  issuerOrgPatterns: string[]
  /** National ID prefixes in serialNumber field */
  idPrefixes: string[]
  /** Signer name suffixes/patterns (e.g. "(FIRMA)" for CR) */
  signerPatterns: string[]
  /** Certificate type mapping: policy OID or CA name pattern → label */
  certTypeRules: CertTypeRule[]
  /** Governing law reference */
  governingLaw: string
  /** Root authority institution name */
  rootAuthority: string
}

export interface CertTypeRule {
  /** Match type: 'oid' checks policy OIDs, 'ca-name' checks intermediate CN */
  match: 'oid' | 'ca-name'
  /** Pattern to match (OID string or uppercase CA name substring) */
  pattern: string
  /** Label to display */
  label: string
}

// ── Registry ────────────────────────────────────────────────────────

export const PKI_REGISTRY: PkiRegistryEntry[] = [
  // ── Costa Rica ──────────────────────────────────────────────────
  {
    countryCode: 'CR',
    name: 'CR Firma Digital',
    fullName: 'Sistema Nacional de Certificación Digital — Firma Digital Costa Rica',
    oidArc: '2.16.188',
    policyOids: [
      '2.16.188.1.1.1',     // Root: Jerarquía Nacional
      '2.16.188.1.1.1.1',   // Persona Física (BCCR)
      '2.16.188.1.1.1.2',   // Persona Jurídica
      '2.16.188.1.1.1.3',   // Sellado de Tiempo
    ],
    rootCaNames: [
      'CA RAIZ NACIONAL - COSTA RICA',
      'CA RAIZ NACIONAL COSTA RICA',
      'CA RAIZ NACIONAL - COSTA RICA V2',
    ],
    intermediateCaPatterns: [
      'CA POLITICA PERSONA FISICA',
      'CA POLITICA PERSONA JURIDICA',
      'CA POLITICA SELLADO DE TIEMPO',
      'CA POLITICA SELLO ELECTRONICO',
    ],
    issuerOrgPatterns: ['SINPE', 'BCCR', 'BANCO CENTRAL DE COSTA RICA'],
    idPrefixes: ['CPF-', 'CPJ-', 'DIMEX-', 'DIDI-'],
    signerPatterns: ['(FIRMA)'],
    certTypeRules: [
      { match: 'oid', pattern: '2.16.188.1.1.1.1', label: 'Persona Física' },
      { match: 'oid', pattern: '2.16.188.1.1.1.2', label: 'Persona Jurídica' },
      { match: 'oid', pattern: '2.16.188.1.1.1.3', label: 'Sellado de Tiempo' },
      { match: 'ca-name', pattern: 'PERSONA FISICA', label: 'Persona Física' },
      { match: 'ca-name', pattern: 'PERSONA JURIDICA', label: 'Persona Jurídica' },
      { match: 'ca-name', pattern: 'SELLO ELECTRONICO', label: 'Sello Electrónico' },
    ],
    governingLaw: 'Ley 8454',
    rootAuthority: 'CA RAIZ NACIONAL - COSTA RICA',
  },

  // ── Mexico ──────────────────────────────────────────────────────
  {
    countryCode: 'MX',
    name: 'MX e.firma / FIEL',
    fullName: 'Firma Electrónica Avanzada — Servicio de Administración Tributaria',
    oidArc: '2.16.484',
    policyOids: [
      '2.16.484.101.10.8.1',  // SAT CPS policy (e.firma)
      '2.16.484.101.10.8.2',  // SAT subordinate policy
    ],
    rootCaNames: [
      'AC RAIZ SAT',
      'AC RAIZ DE LA SECRETARIA DE LA FUNCION PUBLICA',
      'AC RAIZ DE LA SECRETARIA DE ECONOMIA',
    ],
    intermediateCaPatterns: ['AC1 SAT', 'AC2 SAT', 'ARC0 IES', 'ARC1 IES'],
    issuerOrgPatterns: ['SAT', 'SERVICIO DE ADMINISTRACION TRIBUTARIA', 'SECRETARIA DE HACIENDA'],
    idPrefixes: [], // RFC has no prefix — 13 chars = PF, 12 chars = PM
    signerPatterns: [],
    certTypeRules: [
      // MX distinguishes by RFC length, not OID
      { match: 'ca-name', pattern: 'AC1 SAT', label: 'e.firma' },
      { match: 'ca-name', pattern: 'AC2 SAT', label: 'CSD (Sello Digital)' },
    ],
    governingLaw: 'Ley de Firma Electrónica Avanzada (2012)',
    rootAuthority: 'Servicio de Administración Tributaria (SAT)',
  },

  // ── Colombia ────────────────────────────────────────────────────
  {
    countryCode: 'CO',
    name: 'CO Certicámara',
    fullName: 'Certificación Digital — Certicámara S.A.',
    oidArc: '2.16.170',
    policyOids: [
      '2.16.170.1.1',         // Root policy
      '2.16.170.1.2',         // Subordinate policy
      '2.16.170.10.1.11',     // Persona Natural
      '2.16.170.10.1.12',     // Persona Jurídica
    ],
    rootCaNames: [
      'AC RAIZ CERTICAMARA S.A.',
      'AC RAIZ CERTICAMARA',
    ],
    intermediateCaPatterns: [
      'AC FIRMA DIGITAL CERTICAMARA',
      'AC PERSONAS CERTICAMARA',
      'AC JURIDICA CERTICAMARA',
      'AC GSE FIRMA DIGITAL',
    ],
    issuerOrgPatterns: ['CERTICAMARA', 'GSE'],
    idPrefixes: ['NIT-', 'CC-'],
    signerPatterns: [],
    certTypeRules: [
      { match: 'oid', pattern: '2.16.170.10.1.11', label: 'Persona Natural' },
      { match: 'oid', pattern: '2.16.170.10.1.12', label: 'Persona Jurídica' },
      { match: 'ca-name', pattern: 'PERSONAS', label: 'Persona Natural' },
      { match: 'ca-name', pattern: 'JURIDICA', label: 'Persona Jurídica' },
    ],
    governingLaw: 'Ley 527 de 1999',
    rootAuthority: 'ONAC under MinTIC',
  },

  // ── Brazil ──────────────────────────────────────────────────────
  {
    countryCode: 'BR',
    name: 'BR ICP-Brasil',
    fullName: 'Infraestrutura de Chaves Públicas Brasileira',
    oidArc: '2.16.76',
    policyOids: [
      '2.16.76.1.1.0',      // AC Raiz CPS
      '2.16.76.1.2.1',      // A1 (software signature)
      '2.16.76.1.2.3',      // A3 (hardware signature)
      '2.16.76.1.2.101',    // S1 (confidentiality)
      '2.16.76.1.2.103',    // S3
      '2.16.76.1.2.201',    // T3 (timestamp)
    ],
    rootCaNames: [
      'AUTORIDADE CERTIFICADORA RAIZ BRASILEIRA V1',
      'AUTORIDADE CERTIFICADORA RAIZ BRASILEIRA V2',
      'AUTORIDADE CERTIFICADORA RAIZ BRASILEIRA V5',
      'AUTORIDADE CERTIFICADORA RAIZ BRASILEIRA V10',
    ],
    intermediateCaPatterns: [
      'AC SERPRO', 'AC CERTISIGN', 'AC VALID', 'AC SOLUTI',
      'AC SAFEWEB', 'AC CAIXA', 'AC FENACOR',
      'AUTORIDADE CERTIFICADORA DA PRESIDENCIA',
    ],
    issuerOrgPatterns: ['ICP-BRASIL'],
    idPrefixes: [], // CPF/CNPJ embedded in SAN OIDs, not serialNumber prefix
    signerPatterns: [],
    certTypeRules: [
      { match: 'oid', pattern: '2.16.76.1.2.1', label: 'e-CPF A1 (Pessoa Física)' },
      { match: 'oid', pattern: '2.16.76.1.2.3', label: 'e-CPF A3 (Pessoa Física)' },
      { match: 'oid', pattern: '2.16.76.1.2.101', label: 'Sigilo S1' },
      { match: 'oid', pattern: '2.16.76.1.2.201', label: 'Carimbo do Tempo T3' },
      { match: 'ca-name', pattern: 'SERPRO', label: 'SERPRO' },
      { match: 'ca-name', pattern: 'CERTISIGN', label: 'Certisign' },
    ],
    governingLaw: 'MP 2.200-2 de 2001',
    rootAuthority: 'ITI — Instituto Nacional de Tecnologia da Informação',
  },

  // ── Chile ───────────────────────────────────────────────────────
  {
    countryCode: 'CL',
    name: 'CL Firma Electrónica',
    fullName: 'Firma Electrónica Avanzada — Chile',
    oidArc: '2.16.152',
    policyOids: [
      '2.16.152.1.1',   // E-Certchile root
      '2.16.152.1.2',   // Subordinate
    ],
    rootCaNames: [
      'E-CERT ROOT CA',
      'AC RAIZ E-CERTCHILE',
      'CERTINET ROOT CA',
    ],
    intermediateCaPatterns: ['E-CERTCHILE', 'E-CERT CHILE', 'CERTINET', 'FIRMA.CL'],
    issuerOrgPatterns: ['E-CERTCHILE', 'CERTINET', 'SUBSECRETARIA DE ECONOMIA'],
    idPrefixes: [], // RUT has no prefix — pattern: /^\d{7,8}-[\dkK]$/
    signerPatterns: [],
    certTypeRules: [
      { match: 'ca-name', pattern: 'E-CERT', label: 'Firma Electrónica Avanzada' },
      { match: 'ca-name', pattern: 'CERTINET', label: 'Firma Electrónica Avanzada' },
    ],
    governingLaw: 'Ley 19.799 de 2002',
    rootAuthority: 'Ministerio de Economía — División de Acreditación',
  },

  // ── Peru ────────────────────────────────────────────────────────
  {
    countryCode: 'PE',
    name: 'PE RENIEC / IOFE',
    fullName: 'Infraestructura Oficial de Firma Electrónica — Perú',
    oidArc: '2.16.604',
    policyOids: [
      '2.16.604.1.1',   // ECERNEP root
      '2.16.604.1.2',   // RENIEC CA
      '2.16.604.1.3',   // Private CA
    ],
    rootCaNames: [
      'ECERNEP PERU CA ROOT 1',
      'ECERNEP PERU CA ROOT 2',
      'ECERNEP PERU CA ROOT 3',
      'AC RAIZ ECERNEP PERU',
    ],
    intermediateCaPatterns: [
      'RENIEC CLASS I', 'RENIEC CLASS II', 'RENIEC CLASS III',
      'AC SUNAT', 'GLOBALSIGN PERU',
    ],
    issuerOrgPatterns: ['ECERNEP', 'RENIEC', 'INDECOPI'],
    idPrefixes: ['DNI-', 'RUC-'],
    signerPatterns: [],
    certTypeRules: [
      { match: 'ca-name', pattern: 'RENIEC', label: 'DNI Electrónico' },
      { match: 'ca-name', pattern: 'SUNAT', label: 'Certificado SUNAT' },
    ],
    governingLaw: 'Ley 27269 de 2000',
    rootAuthority: 'INDECOPI — Autoridad Administrativa Competente',
  },

  // ── Argentina ───────────────────────────────────────────────────
  {
    countryCode: 'AR',
    name: 'AR Firma Digital',
    fullName: 'Infraestructura de Firma Digital — República Argentina',
    oidArc: '2.16.32',
    policyOids: [
      '2.16.32.1.1',   // AC Raíz root
      '2.16.32.1.3',   // AC ONTI
    ],
    rootCaNames: [
      'AC RAIZ DE LA REPUBLICA ARGENTINA',
      'AC RAIZ DE LA REPUBLICA ARGENTINA 2007',
      'AC RAIZ DE LA REPUBLICA ARGENTINA 2016',
    ],
    intermediateCaPatterns: [
      'AC ONTI', 'AUTORIDAD CERTIFICANTE DE LA ADMINISTRACION PUBLICA',
      'AC BANCO DE LA NACION', 'AC AFIP', 'AC GCBA',
    ],
    issuerOrgPatterns: [
      'PRESIDENCIA DE LA NACION', 'JEFATURA DE GABINETE',
      'OFICINA NACIONAL DE TECNOLOGIAS DE LA INFORMACION',
    ],
    idPrefixes: ['CUIL-', 'CUIT-'],
    signerPatterns: [],
    certTypeRules: [
      { match: 'ca-name', pattern: 'ONTI', label: 'Persona Física' },
      { match: 'ca-name', pattern: 'AFIP', label: 'AFIP' },
      { match: 'ca-name', pattern: 'BANCO DE LA NACION', label: 'Banco Nación' },
    ],
    governingLaw: 'Ley 25.506 de 2001',
    rootAuthority: 'Jefatura de Gabinete de Ministros',
  },

  // ── Ecuador ─────────────────────────────────────────────────────
  {
    countryCode: 'EC',
    name: 'EC Firma Electrónica',
    fullName: 'Firma Electrónica — Banco Central del Ecuador / ECIBCE',
    oidArc: '2.16.218',
    policyOids: [
      '2.16.218.1.1',   // ECIBCE root
      '2.16.218.1.2',   // Subordinate
    ],
    rootCaNames: [
      'ENTIDAD DE CERTIFICACION DE INFORMACION DEL BCE',
      'ECIBCE',
      'SECURITY DATA CA ROOT',
    ],
    intermediateCaPatterns: [
      'ECIBCE PERSONA NATURAL', 'ECIBCE PERSONA JURIDICA',
      'SECURITY DATA', 'CONSEJO DE LA JUDICATURA',
    ],
    issuerOrgPatterns: ['BANCO CENTRAL DEL ECUADOR', 'BCE', 'SECURITY DATA'],
    idPrefixes: ['CI-', 'RUC-'],
    signerPatterns: [],
    certTypeRules: [
      { match: 'ca-name', pattern: 'PERSONA NATURAL', label: 'Persona Natural' },
      { match: 'ca-name', pattern: 'PERSONA JURIDICA', label: 'Persona Jurídica' },
      { match: 'ca-name', pattern: 'SECURITY DATA', label: 'Security Data' },
    ],
    governingLaw: 'Ley 67 de 2002',
    rootAuthority: 'MINTEL / Banco Central del Ecuador',
  },

  // ── Uruguay ─────────────────────────────────────────────────────
  {
    countryCode: 'UY',
    name: 'UY Firma Electrónica',
    fullName: 'Firma Electrónica Avanzada — AGESIC Uruguay',
    oidArc: '2.16.858',
    policyOids: [
      '2.16.858.1.1',   // ACRN root
      '2.16.858.1.2',   // AGESIC subordinate
      '2.16.858.1.3',   // PSCA
    ],
    rootCaNames: [
      'AUTORIDAD CERTIFICADORA RAIZ NACIONAL',
      'ACRN URUGUAY',
      'AC RAIZ NACIONAL URUGUAY',
    ],
    intermediateCaPatterns: [
      'ACPA AGESIC', 'AC CORREO URUGUAYO', 'AC ABITAB', 'UCE CA',
    ],
    issuerOrgPatterns: ['AGESIC', 'UCE', 'UNIDAD DE CERTIFICACION ELECTRONICA'],
    idPrefixes: ['CI-', 'RUT-'],
    signerPatterns: [],
    certTypeRules: [
      { match: 'ca-name', pattern: 'AGESIC', label: 'Firma Electrónica Avanzada' },
      { match: 'ca-name', pattern: 'CORREO URUGUAYO', label: 'Correo Uruguayo' },
    ],
    governingLaw: 'Ley 18.600 de 2009',
    rootAuthority: 'AGESIC — Unidad de Certificación Electrónica',
  },
]

/**
 * Find a PKI registry entry by country code.
 */
export function findPkiByCountry(code: string): PkiRegistryEntry | undefined {
  return PKI_REGISTRY.find((e) => e.countryCode === code)
}
