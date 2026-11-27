import { Router } from "express";
import type { Dependencies } from "../dependencies.ts";
import { getCurrentSession  } from "../auth/sessions.ts";
import { listPublicProducts } from "../products.ts";
import {
  findOrderById,
  listAllOrders,
  listOrderItems,
  listOrdersForUser,
  type Order,
  type OrderItem,
} from "../orders/index.ts";
import {  type Product } from "../products.ts";
import { findApiKey } from "../auth/apiKeys.ts";
import { sendApiKeyQuotaExhausted , setApiKeyQuotaHeaders , toApiKeyQuotaResponse } from "./apiKeyQuota.ts";

import { consumeApiKeyQuota } from "../auth/apiKeyUsage.ts";
type ProductResponse = {
  id: number;
  name: string;
  description: string;
  image_path: string;
  price_cents: number;
};

type OrderResponse = {
  id: number;
  status: Order["status"];
  total_cents: number;
  created_at: string;
};

type OrderItemResponse = {
  product_id: number;
  product_name: string;
  quantity: number;
  price_cents: number;
};


function toProductResponse(product: Product): ProductResponse {
  return {
    id: product.id,
    name: product.name,
    description: product.description,
    image_path: product.image_path,
    price_cents: product.price_cents,
  };
}

function toOrderResponse(order: Order): OrderResponse {
  return {
    id: order.id,
    status: order.status,
    total_cents: order.total_cents,
    created_at: order.created_at,
  };
}

function toOrderItemResponse(item: OrderItem): OrderItemResponse {
  return {
    product_id: item.product_id,
    product_name: item.product_name,
    quantity: item.quantity,
    price_cents: item.price_cents,
  };
}


export function createApiRouter(deps: Dependencies): Router {
  const { db } = deps;
  const router = Router();

  router.get("/api/account/orders", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    res.json({ orders: listOrdersForUser(db, current.user.id).map(toOrderResponse) });
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

    res.json({ 
      order :  toOrderResponse(order), 
      items: listOrderItems(db, order.id).map(toOrderItemResponse) });
  });

  router.get("/api/products", (_req, res) => {
    res.json({ 
      products: listPublicProducts(
        db, 
        deps.maxPublicProductResults,
      ).map(toProductResponse),
    });
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

  const quota = consumeApiKeyQuota(db, key.id);

if (!quota.allowed) {
  sendApiKeyQuotaExhausted(res, quota);
  return;
}

setApiKeyQuotaHeaders(res, quota);

  res.json({
    integration: "Warehouse Fulfillment Integration",
    orders,
    quota : toApiKeyQuotaResponse(quota),
  });
});

  return router;
}
