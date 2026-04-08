import type { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError }                   from 'zod';

/**
 * Zod request validator.
 *
 * Validates `req[source]` against the provided schema and responds with 400
 * on failure.  On success, the parsed (and coerced) value is written back to
 * `req[source]` so downstream handlers receive typed data.
 *
 * @param schema  Zod schema to validate against.
 * @param source  Which request property to validate (default: 'body').
 */
export function validate<T>(
  schema: ZodSchema<T>,
  source: 'body' | 'params' | 'query' = 'body',
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      const details = (result.error as ZodError).errors.map((e) => ({
        field:   e.path.join('.'),
        message: e.message,
      }));
      res.status(400).json({ error: 'Validation failed', details });
      return;
    }

    // Write coerced value back so routes always get parsed types
    (req as Request & Record<string, unknown>)[source] = result.data;
    next();
  };
}
