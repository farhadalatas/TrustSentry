/** Shared success matcher: gunakan flow.successCodes bila ada, jika tidak pakai res.ok. */
function isSuccess(flow, res) {
  return Array.isArray(flow && flow.successCodes)
    ? flow.successCodes.includes(res.status)
    : res.ok;
}

module.exports = { isSuccess };