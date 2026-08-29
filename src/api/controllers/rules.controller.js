const ruleService = require('../../services/rule.service');
const { successResponse, errorResponse } = require('../../utils/response');

class RuleController {
  /**
   * Import rules from JSON file
   * POST /api/rules/import
   * Accepts multipart/form-data with file field 'rulesFile'
   */
  async importRules(req, res, next) {
    let tempFilePath = null;

    try {
      // Check if file was uploaded
      if (!req.file) {
        return errorResponse(
          res,
          'No file uploaded. Please provide a rules file.',
          400,
        );
      }

      // Get file path
      tempFilePath = req.file.path;

      // Read file content
      const fileContent = await fs.readFile(tempFilePath, 'utf8');

      // Parse JSON file - handle both array and line-by-line JSON
      let rulesData;
      try {
        // Try parsing as JSON array first
        const parsed = JSON.parse(fileContent);
        if (Array.isArray(parsed)) {
          // If it's an array of objects, convert to string lines
          rulesData = parsed.map(item => JSON.stringify(item));
        } else {
          // If it's a single object, make it an array
          rulesData = [JSON.stringify(parsed)];
        }
      } catch (parseError) {
        // If not valid JSON array, try line-by-line JSON
        const lines = fileContent
          .split('\n')
          .map(line => line.trim())
          .filter(line => line.length > 0);

        // Validate each line is valid JSON
        const validLines = [];
        for (const line of lines) {
          try {
            JSON.parse(line);
            validLines.push(line);
          } catch (e) {
            // Skip invalid lines
            console.warn(
              `Skipping invalid JSON line: ${line.substring(0, 50)}...`,
            );
          }
        }

        if (validLines.length === 0) {
          return errorResponse(res, 'No valid JSON data found in file', 400);
        }

        rulesData = validLines;
      }

      const { batchSize } = req.query;

      // Import rules
      const stats = await ruleService.importRules(
        rulesData,
        parseInt(batchSize) || 1000,
      );

      // Clean up temp file
      if (tempFilePath && req.file) {
        await fs.unlink(tempFilePath).catch(() => {});
      }

      return successResponse(res, {
        message: 'Rules imported successfully',
        fileName: req.file.originalname,
        fileSize: req.file.size,
        stats,
      });
    } catch (error) {
      // Clean up temp file on error
      if (tempFilePath) {
        await fs.unlink(tempFilePath).catch(() => {});
      }
      next(error);
    }
  }

  /**
   * Get all rules with pagination
   * GET /api/rules
   */
  async getRules(req, res, next) {
    try {
      const { page = 1, limit = 50, action, protocol, search } = req.query;

      const result = await ruleService.getRules(
        { action, protocol, search },
        parseInt(page),
        parseInt(limit),
      );

      return successResponse(res, result);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get rule by ID
   * GET /api/rules/:ruleId
   */
  async getRuleById(req, res, next) {
    try {
      const { ruleId } = req.params;
      const rule = await ruleService.getRuleById(ruleId);

      if (!rule) {
        return errorResponse(res, 'Rule not found', 404);
      }

      return successResponse(res, { rule });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete rule by ID
   * DELETE /api/rules/:ruleId
   */
  async deleteRule(req, res, next) {
    try {
      const { ruleId } = req.params;
      const rule = await ruleService.deleteRule(ruleId);

      if (!rule) {
        return errorResponse(res, 'Rule not found', 404);
      }

      return successResponse(res, {
        message: 'Rule deleted successfully',
        ruleId,
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new RuleController();
