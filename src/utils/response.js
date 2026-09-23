// Every API response uses one envelope:
//   success: { success: true,  message, data, timestamp }
//   error:   { success: false, detail, ...extra, timestamp }
// `detail` is kept as the error field because the panel and existing SIEM integrations read it.
const successResponse = (res, data, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data,
    timestamp: new Date().toISOString(),
  });
};

const errorResponse = (res, error, statusCode = 400, extra = null) => {
  return res.status(statusCode).json({
    success: false,
    detail: typeof error === 'string' ? error : error?.message || 'Request failed',
    ...(extra || {}),
    timestamp: new Date().toISOString(),
  });
};

module.exports = {
  successResponse,
  errorResponse,
};
