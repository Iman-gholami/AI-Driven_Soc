const fs = require('node:fs/promises');
const multer = require('multer');
const { settings } = require('../../core/config');
const { AppError } = require('../../core/errors');
const { errorResponse } = require('../../utils/response');

function notFoundHandler(req, res) {
  return errorResponse(res, `Route ${req.method} ${req.path} not found`, 404);
}

function errorHandler(error, req, res, next) {
  cleanupUploadedFiles(req);
  if (res.headersSent) return next(error);

  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      const limitMb = Math.round(settings.reportImportMaxFileBytes / 1024 / 1024);
      return errorResponse(res, `Each uploaded file must be smaller than ${limitMb} MB`, 413);
    }
    return errorResponse(res, `Upload rejected: ${error.message}`, 400);
  }

  if (error?.type === 'entity.too.large') {
    return errorResponse(res, 'Payload too large', 413);
  }

  if (error?.type === 'entity.parse.failed') {
    return errorResponse(res, 'Request body is not valid JSON', 400);
  }

  if (error?.name === 'ZodError') {
    req.log?.warn({ err: error }, 'invalid_llm_output');
    return errorResponse(res, 'Invalid model output', 502);
  }

  if (error instanceof AppError) {
    const log = error.status >= 500 ? 'error' : 'warn';
    req.log?.[log]({ err: error.cause || error, status: error.status }, 'request_failed');
    return errorResponse(res, error.publicMessage, error.status, error.details);
  }

  req.log?.error({ err: error }, 'unhandled_route_error');
  return errorResponse(res, 'Internal server error', 500);
}

function cleanupUploadedFiles(req) {
  const files = [
    ...(Array.isArray(req.files) ? req.files : []),
    ...(req.file ? [req.file] : []),
  ];
  for (const file of files) {
    if (file?.path) fs.unlink(file.path).catch(() => {});
  }
}

module.exports = { errorHandler, notFoundHandler };
