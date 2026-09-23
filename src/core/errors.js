// Errors that carry their own HTTP mapping, so routes can simply throw and let the
// central error handler (src/api/middleware/errorHandler.js) build the response.
class AppError extends Error {
  constructor(message, { status = 500, publicMessage, details, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = new.target.name;
    this.status = status;
    // Message safe to return to clients; defaults to the error message for 4xx only.
    this.publicMessage = publicMessage || (status < 500 ? message : "Internal server error");
    this.details = details;
  }
}

class InputError extends AppError {
  constructor(message, options = {}) {
    super(message, { ...options, status: 400 });
  }
}

class NotFoundError extends AppError {
  constructor(message = "Not found", options = {}) {
    super(message, { ...options, status: 404 });
  }
}

class ConflictError extends AppError {
  constructor(message, options = {}) {
    super(message, { ...options, status: 409 });
  }
}

module.exports = { AppError, InputError, NotFoundError, ConflictError };
