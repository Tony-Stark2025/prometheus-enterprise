/**
 * Express & Prisma Multi-Tenant Invoice Service (Benchmark Fixture)
 * Contains real-world BOLA (API1:2023) and BFLA (API5:2023) authorization flaws.
 */

import { Request, Response, Router } from "express";

export interface AuthenticatedUser {
  userId: string;
  tenantId: string;
  role: string;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

export const router = Router();

// ============================================================================
// Endpoint 1: BOLA / IDOR Flaw (Prisma ORM pattern)
// ============================================================================
router.get("/api/v1/invoices/:id", async (req: AuthenticatedRequest, res: Response) => {
  const invoiceId = req.params.id;

  // Unscoped findUnique: fetches invoice by primary key without checking tenantId
  const invoice = await prisma.invoice.findUnique({
    where: { id: invoiceId },
  });

  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  return res.status(200).json(invoice);
});

// ============================================================================
// Endpoint 2: BOLA / IDOR Flaw (Repository / In-memory Map pattern)
// ============================================================================
router.get("/api/v1/documents/:id", async (req: AuthenticatedRequest, res: Response) => {
  const docId = req.params.id;
  const document = documentsStore.get(docId);

  if (!document) {
    return res.status(404).json({ error: "Document not found" });
  }

  return res.status(200).json(document);
});

// ============================================================================
// Endpoint 3: BFLA Flaw (Privileged workspace deletion without role check)
// ============================================================================
router.delete("/api/v1/workspaces/:id", async (req: AuthenticatedRequest, res: Response) => {
  const workspaceId = req.params.id;

  // Destructive administrative action executed without verifying req.user.role === 'admin'
  await workspaceService.delete(workspaceId);

  return res.status(200).json({
    status: "DELETED",
    workspaceId: workspaceId,
  });
});
