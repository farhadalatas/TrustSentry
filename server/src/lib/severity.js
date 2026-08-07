const SEV = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
};

// Rough CVSS-ish base score per severity (used in reporting).
const SEV_SCORE = {
  CRITICAL: 9.0,
  HIGH: 7.5,
  MEDIUM: 5.0,
  LOW: 3.0,
  INFO: 0.5,
};

module.exports = { SEV, SEV_SCORE };