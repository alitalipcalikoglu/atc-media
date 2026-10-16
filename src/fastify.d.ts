// Type-only augmentation for the `apiKeyId` request decorator set in auth.js. No runtime code.
import 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    apiKeyId: string;
  }
  interface FastifyContextConfig {
    /** Opt in to Idempotency-Key replay (core Idempotency); never on routes answering with secrets. */
    idempotent?: boolean;
    audit?: import('@atc-web/atc-service-core/audit').AuditRouteConfig;
  }
}
