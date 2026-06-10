// Isomorphism gate: the server CORE must bundle for the browser with zero
// node builtins (run: npm run check:browser). bin.ts is the node host and
// is deliberately NOT part of this graph.
import { createServer } from "../dist/server.js";
export const probe = () =>
  createServer({ storage: { defaultHandle: async () => null } });
