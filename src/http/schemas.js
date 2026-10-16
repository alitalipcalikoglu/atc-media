import { Ids } from '@atc-web/atc-service-core/ids';
/** JSON Schemas for the HTTP surface. */
export class Schemas {
  static fileId = { type: 'string', pattern: Ids.pattern('fil') };
  static visibility = { type: 'string', enum: ['public', 'private'] };
  static name = { type: 'string', minLength: 1, maxLength: 255 };
  static mimeList = { type: 'array', minItems: 1, maxItems: 20, uniqueItems: true, items: { type: 'string', pattern: '^[a-z]+/[a-z0-9.+-]+$' } };

  static idParams = { type: 'object', properties: { id: Schemas.fileId }, required: ['id'] };
  static idVariantParams = { type: 'object', properties: { id: Schemas.fileId, variant: { type: 'string', pattern: '^[a-z][a-z0-9-]{0,31}$' } }, required: ['id', 'variant'] };
  static tokenParams = { type: 'object', properties: { token: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' } }, required: ['token'] };

  static uploadQuery = {
    type: 'object', additionalProperties: false,
    properties: { visibility: Schemas.visibility, name: Schemas.name },
  };
  static ticketUploadQuery = { type: 'object', additionalProperties: false, properties: { name: Schemas.name } };
  static downloadQuery = {
    type: 'object', additionalProperties: false,
    properties: { exp: { type: 'string', pattern: '^\\d{1,12}$' }, sig: { type: 'string', maxLength: 64 }, download: { type: 'string', enum: ['1'] } },
  };
  static listQuery = {
    type: 'object', additionalProperties: false,
    properties: { limit: { type: 'string', pattern: '^([1-9]|[1-9][0-9]|100)$' }, cursor: { type: 'string', maxLength: 128 }, owner: { type: 'string', pattern: '^[A-Za-z0-9_.-]{1,64}$' } },
  };
  static quarantineParams = { type: 'object', properties: { id: { type: 'string', pattern: Ids.pattern('qua') } }, required: ['id'] };
  static quarantineQuery = { type: 'object', additionalProperties: false, properties: { limit: { type: 'string', pattern: '^([1-9]|[1-9][0-9]|1[0-9][0-9]|200)$' }, cursor: { type: 'string', maxLength: 128 } } };
  static signQuery = { type: 'object', additionalProperties: false, properties: { ttl: { type: 'string', pattern: '^\\d{1,7}$' } } };

  static ticketBody = {
    type: 'object', additionalProperties: false,
    properties: {
      visibility: Schemas.visibility,
      maxBytes: { type: 'integer', minimum: 1 },
      allowedTypes: Schemas.mimeList,
      name: Schemas.name,
    },
  };
  static patchBody = {
    type: 'object', additionalProperties: false, minProperties: 1,
    properties: { visibility: Schemas.visibility, name: Schemas.name },
  };
}
