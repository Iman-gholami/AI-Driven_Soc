const Alert = require("../models/Alert");

class AlertRepository {
  constructor({ alertModel = Alert } = {}) {
    this.alertModel = alertModel;
  }

  async create(alertRecord) {
    return this.alertModel.create(alertRecord);
  }
}

module.exports = { AlertRepository };
