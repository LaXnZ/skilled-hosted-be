import { Router } from "express";

import { verifyToken } from "../middlewares/AuthMiddleware.js";
import {
  confirmOrder,
  addOrder,
  getBuyerOrders,
  getSellerOrders,
} from "../controllers/OrderControllers.js";

export const orderRoutes = Router();

orderRoutes.post("/create", verifyToken, addOrder);
orderRoutes.put("/success", verifyToken, confirmOrder);
orderRoutes.get("/get-buyer-orders", verifyToken, getBuyerOrders);
orderRoutes.get("/get-seller-orders", verifyToken, getSellerOrders);