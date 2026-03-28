import type { TransportTlsReport } from '../../types';
import {
  detectDowngradeSignals,
  detectHstsPosture,
  detectHttpsAdoption,
  detectSensitiveDataOverEncryptedChannel,
} from './detectors';
import {
  buildOverview,
  deriveOverallConfidence,
  deriveOverallCoverage,
  deriveOverallStatus,
  emptyTransportReport,
  hostnameFromUrl,
  summarizeChecks,
  type TransportTlsInputs,
} from './helpers';

export type { TransportTlsInputs } from './helpers';
export {
  detectDowngradeSignals,
  detectHstsPosture,
  detectHttpsAdoption,
  detectSensitiveDataOverEncryptedChannel,
};

export function buildTransportTlsSummary(report: TransportTlsReport): string {
  return `${report.summary.fail} fail, ${report.summary.warn} warn, ${report.summary.pass} pass, ${report.summary.inconclusive} inconclusive`;
}

export function buildTransportTlsSection(inputs: TransportTlsInputs): TransportTlsReport {
  if (!inputs.activeUrl) {
    return emptyTransportReport(inputs.activeUrl);
  }

  const checks = [
    detectHttpsAdoption(inputs),
    detectSensitiveDataOverEncryptedChannel(inputs),
    detectHstsPosture(inputs),
    detectDowngradeSignals(inputs),
  ];
  const summary = summarizeChecks(checks);

  return {
    activeUrl: inputs.activeUrl,
    primaryHost: hostnameFromUrl(inputs.activeUrl),
    capturedRequestCount: inputs.requests.length,
    observedHttpRequestCount: inputs.requests.filter(request => request.url.startsWith('http://')).length,
    observedHttpsRequestCount: inputs.requests.filter(request => request.url.startsWith('https://')).length,
    domObservation: inputs.domObservation,
    checks,
    summary,
    overallStatus: deriveOverallStatus(checks),
    overview: buildOverview(summary),
    coverage: deriveOverallCoverage(checks),
    confidence: deriveOverallConfidence(checks),
  };
}