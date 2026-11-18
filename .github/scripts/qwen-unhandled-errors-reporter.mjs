import { writeFileSync } from 'node:fs';

export default class UnhandledErrorsReporter {
  onInit(context) {
    this.context = context;
  }

  onFinished() {
    const reportPath = process.env.QWEN_VALIDATION_ERROR_REPORT;
    if (!reportPath) throw new Error('Missing validation error report path');
    const errors = this.context.state.getUnhandledErrors();
    if (!Array.isArray(errors)) {
      throw new Error('Unexpected Vitest unhandled-error collection');
    }
    writeFileSync(
      reportPath,
      JSON.stringify({
        count: errors.length,
        errors: errors.map((error) => ({
          name: String(error?.name ?? 'Error'),
          message: String(error?.message ?? error),
        })),
      }) + '\n',
    );
  }
}
