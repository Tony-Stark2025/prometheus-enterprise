/**
 * Pure Node.js Standard Library Multi-Tenant Benchmark Server
 * Exposes real endpoints with BOLA (API1:2023) and BFLA (API5:2023) flaws.
 * Zero npm dependencies (runs on stock Node.js).
 */

const http = require("node:http");
const url = require("node:url");

// Seeded Multi-Tenant Databases
const INVOICES_DB = {
  "inv-alpha-992": {
    id: "inv-alpha-992",
    tenantId: "org-alpha-victim-001",
    title: "Q3 Strategic Enterprise Retainer",
    amount: 85000.0,
    secret_marker: "CONFIDENTIAL_PAYROLL_DATA_ALPHA_8832",
  },
  "inv-beta-101": {
    id: "inv-beta-101",
    tenantId: "org-beta-attacker-002",
    title: "Standard Platform Tier",
    amount: 1200.0,
    secret_marker: "PUBLIC_TIER_BETA",
  },
};

const WORKSPACES_DB = {
  "ws-alpha-001": {
    id: "ws-alpha-001",
    tenantId: "org-alpha-victim-001",
    name: "Alpha Production Workspace",
    secret_marker: "CONFIDENTIAL_WORKSPACE_ALPHA_001",
  },
};

function parseJwt(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = Buffer.from(parts[1], "base64").toString("utf8");
    return JSON.parse(payload);
  } catch (e) {
    return null;
  }
}

function createServer(patched = false) {
  return http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const user = parseJwt(req.headers["authorization"]);

    // BOLA Vulnerable Route: GET /api/v1/invoices/:id
    const invoiceMatch = pathname.match(/^\/api\/v1\/invoices\/([a-zA-Z0-9_-]+)$/);
    if (req.method === "GET" && invoiceMatch) {
      const invoiceId = invoiceMatch[1];
      const invoice = INVOICES_DB[invoiceId];

      if (!invoice) {
        res.writeHead(404, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Invoice not found" }));
      }

      // If patched, enforce tenant isolation
      if (patched) {
        const userTenant = user ? (user.tenant_id || user.tenantId) : null;
        if (!userTenant || invoice.tenantId !== userTenant) {
          res.writeHead(404, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "Invoice not found" }));
        }
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify(invoice));
    }

    // BFLA Vulnerable Route: DELETE /api/v1/workspaces/:id
    const workspaceMatch = pathname.match(/^\/api\/v1\/workspaces\/([a-zA-Z0-9_-]+)$/);
    if (req.method === "DELETE" && workspaceMatch) {
      const wsId = workspaceMatch[1];
      const ws = WORKSPACES_DB[wsId];

      if (!ws) {
        res.writeHead(404, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Workspace not found" }));
      }

      // If patched, enforce admin role
      if (patched) {
        if (!user || user.role !== "admin") {
          res.writeHead(403, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "Forbidden: Admin role required" }));
        }
      }

      delete WORKSPACES_DB[wsId];
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ status: "DELETED", workspaceId: wsId }));
    }

    // Health check
    if (pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ status: "ok" }));
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Route not found" }));
  });
}

if (require.main === module) {
  const port = parseInt(process.env.PORT || "8895", 10);
  const isPatched = process.argv.includes("--patched");
  const server = createServer(isPatched);
  server.listen(port, "127.0.0.1", () => {
    console.log(`[node_benchmark_app] Listening on http://127.0.0.1:${port} (patched=${isPatched})`);
  });
}

module.exports = { createServer };
