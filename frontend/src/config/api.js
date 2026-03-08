const trimTrailingSlash = (value) => String(value || '').replace(/\/+$/, '')

const withFallback = (value, fallback) => {
  const cleaned = trimTrailingSlash(value)
  return cleaned || fallback
}

const joinBaseAndPath = (base, path = '') => {
  if (!path) return base
  return `${base}${path.startsWith('/') ? path : `/${path}`}`
}

const isAbsoluteUrl = (value) => /^https?:\/\//i.test(value)

const getBaseOrigin = (base) => {
  if (!isAbsoluteUrl(base)) return ''

  try {
    const parsed = new URL(base)
    return `${parsed.protocol}//${parsed.host}`
  } catch {
    return ''
  }
}

export const API_BASES = {
  orchestrator: withFallback(import.meta.env.VITE_ORCHESTRATOR_API_BASE, '/api'),
  malware: withFallback(import.meta.env.VITE_MALWARE_API_BASE, '/api/malware-analyzer'),
  steg: withFallback(import.meta.env.VITE_STEG_API_BASE, '/api/steg-analyzer'),
  recon: withFallback(import.meta.env.VITE_RECON_API_BASE, '/api/Recon-Analyzer'),
  web: withFallback(import.meta.env.VITE_WEB_API_BASE, '/api/web-analyzer'),
  macro: withFallback(import.meta.env.VITE_MACRO_API_BASE, '/api/macro-analyzer'),
}

export const WEB_ANALYZER_PATHS = {
  status: '/status',
  dns: '/dns',
  ssl: '/ssl',
  headers: '/headers',
  techStack: '/tech-stack',
  whois: '/whois',
  robotsTxt: '/robots-txt',
  sitemap: '/sitemap',
  hsts: '/hsts',
  securityHeaders: '/security-headers',
  securityTxt: '/security-txt',
  cookies: '/cookies',
  redirects: '/redirects',
  ports: '/ports',
  getIp: '/get-ip',
  socialTags: '/social-tags',
  txtRecords: '/txt-records',
  linkedPages: '/linked-pages',
  traceRoute: '/trace-route',
  mailConfig: '/mail-config',
  dnssec: '/dnssec',
  firewall: '/firewall',
  dnsServer: '/dns-server',
  tls: '/tls',
  archives: '/archives',
  carbon: '/carbon',
  rank: '/rank',
  features: '/features',
  blockLists: '/block-lists',
  screenshot: '/screenshot',
  redirectChain: '/redirect-chain',
  urlParse: '/url-parse',
  malwareCheck: '/malware-check',
  aiAnalyze: '/ai-analyze',
  batch: '/batch',
}

export const API_ENDPOINTS = {
  orchestrator: {
    health: joinBaseAndPath(API_BASES.orchestrator, '/health'),
    smartAnalyze: joinBaseAndPath(API_BASES.orchestrator, '/smart-analyze'),
    report: (jobId, format) => joinBaseAndPath(API_BASES.orchestrator, `/report/${jobId}/${format}`),
  },
  malware: {
    health: joinBaseAndPath(API_BASES.malware, '/health'),
    decompile: joinBaseAndPath(API_BASES.malware, '/decompile'),
    fileAnalysis: joinBaseAndPath(API_BASES.malware, '/file-analysis'),
    aiSummary: joinBaseAndPath(API_BASES.malware, '/ai-summary'),
    diagramGenerator: joinBaseAndPath(API_BASES.malware, '/diagram-generator'),
  },
  steg: {
    health: joinBaseAndPath(API_BASES.steg, '/'),
    upload: joinBaseAndPath(API_BASES.steg, '/upload'),
    status: (submissionHash) => joinBaseAndPath(API_BASES.steg, `/status/${submissionHash}`),
    infos: (submissionHash) => joinBaseAndPath(API_BASES.steg, `/infos/${submissionHash}`),
    result: (submissionHash) => joinBaseAndPath(API_BASES.steg, `/result/${submissionHash}`),
    download: (submissionHash, tool) => joinBaseAndPath(API_BASES.steg, `/download/${submissionHash}/${tool}`),
    image: (path) => joinBaseAndPath(API_BASES.steg, path),
  },
  recon: {
    health: joinBaseAndPath(API_BASES.recon, '/health'),
    scan: joinBaseAndPath(API_BASES.recon, '/scan'),
    footprint: joinBaseAndPath(API_BASES.recon, '/footprint'),
  },
  web: {
    health: joinBaseAndPath(API_BASES.web, '/health'),
    route: (path) => joinBaseAndPath(API_BASES.web, path),
  },
  macro: {
    health: joinBaseAndPath(API_BASES.macro, '/health'),
    analyze: joinBaseAndPath(API_BASES.macro, '/analyze'),
  },
}

export const resolveReportUrl = (reportPath) => {
  if (!reportPath) return null
  if (isAbsoluteUrl(reportPath)) return reportPath

  const normalizedPath = reportPath.startsWith('/') ? reportPath : `/${reportPath}`
  const origin = getBaseOrigin(API_BASES.orchestrator)

  return origin ? `${origin}${normalizedPath}` : normalizedPath
}
