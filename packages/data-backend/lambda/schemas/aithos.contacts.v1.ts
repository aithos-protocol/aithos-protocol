// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos.contacts.v1` — bundled at build time.
 *
 * The source of truth is `spec/data/schemas/aithos.contacts.v1.json`.
 * This TypeScript copy is inlined so the Lambda doesn't need a runtime
 * fetch. A future build step may auto-generate this from the JSON.
 *
 * Doc: spec/data/schemas/aithos.contacts.v1.md
 */

import type { AithosSchema } from "./registry.js";

export const contactsV1Schema: AithosSchema = {
  "aithos:schema": "aithos.contacts.v1",
  "aithos:version": "0.1.0",
  title: "Contact (prospect or customer)",
  type: "object",
  required: ["name"],
  additionalProperties: false,
  properties: {
    name: {
      type: "string",
      minLength: 1,
      maxLength: 200,
      "aithos:indexable": true,
    },
    email: {
      type: "string",
      format: "email",
      maxLength: 200,
      "aithos:indexable": true,
    },
    phone_hash: {
      type: "string",
      pattern: "^blake3:[0-9a-f]{64}$",
      "aithos:indexable": true,
      "aithos:derived_from": "phone",
    },
    status: {
      type: "string",
      enum: ["lead", "contact", "opportunity", "won", "lost", "archived"],
      default: "lead",
      "aithos:indexable": true,
    },
    tags: {
      type: "array",
      items: { type: "string", minLength: 1, maxLength: 64 },
      maxItems: 32,
      uniqueItems: true,
      "aithos:indexable": true,
    },
    source: {
      type: "string",
      maxLength: 100,
      "aithos:indexable": true,
    },
    created_at: {
      type: "string",
      format: "date-time",
      "aithos:indexable": true,
      "aithos:auto": "on_insert",
    },
    modified_at: {
      type: "string",
      format: "date-time",
      "aithos:indexable": true,
      "aithos:auto": "on_modify",
    },
    last_contacted_at: {
      type: "string",
      format: "date-time",
      "aithos:indexable": true,
    },
    phone: {
      type: "string",
      maxLength: 50,
      "aithos:encrypted": true,
      "aithos:pii": true,
    },
    notes: {
      type: "string",
      maxLength: 100000,
      "aithos:encrypted": true,
    },
    conversation_log: {
      type: "array",
      "aithos:encrypted": true,
    },
    form_responses: {
      type: "object",
      "aithos:encrypted": true,
    },
    custom_fields: {
      type: "object",
      "aithos:encrypted": true,
    },
  },
};
