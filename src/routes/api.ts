import { Router } from "express";
import type { Dependencies } from "../dependencies.ts";
import { getCurrentSession } from "../auth/sessions.ts";
import { findApiKey } from "../auth/apiKeys.ts";
import {
  findOrderById,
  listAllOrders,
  listOrderItems,
  listOrdersForUser,
} from "../orders/index.ts";
import { listAllProducts } from "../products.ts";

export function createApiRouter(deps: Dependencies): Router {
  const { db } = deps;
  const router = Router();

  router.get("/api/account/orders", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    res.json({ orders: listOrdersForUser(db, current.user.id) });
  });

  router.get("/api/orders/:id", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const orderId = Number(req.params.id);
    if (!Number.isSafeInteger(orderId)) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    const order = findOrderById(db, orderId);
    if (!order || order.user_id !== current.user.id) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    res.json({ order, items: listOrderItems(db, order.id) });
  });

  router.get("/api/products", (_req, res) => {
    res.json({ products: listAllProducts(db) });
  });

  router.get("/api/integrations/warehouse/orders", (req, res) => {
  // 1. Read the API key from the request header
  const apiKey = req.header("x-api-key");

  // 2. Check whether the key is valid
  const key = findApiKey(db, apiKey ?? "");

  if (!key) {
    res.status(401).json({
      error: "Invalid or missing API key",
    });
    return;
  }

  // 3. Check whether the key has permission
  const scopes = key.scope.split(/\s+/);

  if (!scopes.includes("orders:read")) {
    res.status(403).json({
      error: "Insufficient permissions",
    });
    return;
  }

  // 4. Return orders to authorized clients
  const orders = listAllOrders(db).map((order) => ({
    id: order.id,
    status: order.status,
    total_cents: order.total_cents,
    created_at: order.created_at,
  }));

  res.json({
    integration: "Warehouse Fulfillment Integration",
    orders,
  });
});

  return router;
}
