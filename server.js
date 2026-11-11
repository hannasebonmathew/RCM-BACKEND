require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Razorpay = require("razorpay");

process.on('uncaughtException', (err) => {
  if (err.code === 'ECONNRESET' || err.message?.includes('ECONNRESET')) {
    console.warn("⚠️ Caught transient MongoDB ECONNRESET error safely:", err.message);
    return;
  }
  console.error("Uncaught Exception:", err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error("⚠️ Unhandled Rejection at:", promise, "reason:", reason);
});

const {
  PORT = 5000,
  MONGO_URI = "mongodb://127.0.0.1:27017/hannan_supermarket",
  JWT_SECRET,
  CLIENT_URL = "*",
  RAZORPAY_KEY_ID,
  RAZORPAY_KEY_SECRET,
  TELEGRAM_BOT_TOKEN,
  TELEGRAM_CHAT_ID,
} = process.env;

if (!JWT_SECRET) throw new Error("JWT_SECRET is required in .env");

// ---------- Business rules & Store Coordinates ----------
const MIN_ORDER_AMOUNT = 1000; // Minimum order subtotal required
const SHIPPING_FEE = 60;
const COD_MAX = 10000;
const STORE_LAT = 10.4226643;
const STORE_LNG = 76.2707509;

const STATUSES = ["Placed", "Confirmed", "Packed", "Shipped", "Out for delivery", "Delivered", "Cancelled"];
const CANCELLABLE = ["Placed", "Confirmed"];
const CATEGORIES = ["wellness", "personal-care", "home-care", "kitchen"];

// Calculate straight-line distance in kilometers using Haversine formula
function getDistanceInKm(lat1, lon1, lat2, lon2) {
  const R = 6371; // Radius of the Earth in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Free delivery if client is within 5km of the store
const calcShippingByCoords = (subtotal, lat, lng) => {
  if (subtotal <= 0) return 0;
  if (lat && lng) {
    const distanceKm = getDistanceInKm(STORE_LAT, STORE_LNG, Number(lat), Number(lng));
    if (distanceKm <= 5) return 0; // Free delivery within 5 km
  }
  return SHIPPING_FEE; // Standard fee outside 5 km
};

// ---------- Models ----------
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, trim: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ["customer", "admin"], default: "customer" },
    isNrpAllowed: { type: Boolean, default: false }, 
  },
  { timestamps: true },
);
const User = mongoose.model("User", userSchema);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    category: { type: String, enum: CATEGORIES, required: true },
    mrp: { type: Number, required: true, min: 0 },
    nrp: { type: Number, required: true, min: 1 }, // Net/Special price
    stock: { type: Number, required: true, min: 0, default: 0 },
    featured: { type: Boolean, default: false },
    description: { type: String, default: "" },
    images: [String],
  },
  { timestamps: true },
);
productSchema.pre("validate", function (next) {
  if (this.mrp < this.nrp) return next(new Error("MRP cannot be less than NRP"));
  if (!Number.isInteger(this.stock)) return next(new Error("Stock must be a whole number"));
  next();
});
productSchema.index({ name: "text", description: "text" });
const Product = mongoose.model("Product", productSchema);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, unique: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    customerEmail: String,
    guest: { type: Boolean, default: true },
    address: {
      name: String, phone: String, email: String, line1: String, line2: String,
      city: String, district: String, state: String, pincode: String, lat: Number, lng: Number,
    },
    items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" }, name: String, price: Number, mrp: Number, qty: Number, image: String }],
    subtotal: Number,
    shipping: Number,
    discount: { type: Number, default: 0 },
    total: Number,
    paymentMethod: { type: String, enum: ["COD", "Razorpay"], required: true },
    paymentStatus: { type: String, enum: ["Pending", "Paid", "Failed", "Refunded"], default: "Pending" },
    razorpayOrderId: String,
    paymentId: String,
    status: { type: String, enum: STATUSES, default: "Placed" },
    history: [{ status: String, at: { type: Date, default: Date.now } }],
  },
  { timestamps: true },
);
const Order = mongoose.model("Order", orderSchema);

// ---------- App & middleware ----------
const app = express();
app.use(cors({ origin: CLIENT_URL === "*" ? true : CLIENT_URL.split(",") }));
app.use(express.json({ limit: "2mb" }));

const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const httpError = (status, message) => Object.assign(new Error(message), { status });
const sign = (u) => jwt.sign({ id: u._id, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
const publicUser = (u) => ({ 
  id: u._id, 
  name: u.name, 
  email: u.email, 
  phone: u.phone, 
  role: u.role, 
  isNrpAllowed: u.isNrpAllowed 
});

const optionalAuth = ah(async (req, _res, next) => {
  const token = req.headers.authorization?.replace(/^Bearer /, "");
  if (token) {
    try {
      const { id } = jwt.verify(token, JWT_SECRET);
      req.user = await User.findById(id);
    } catch { /* treat as guest */ }
  }
  next();
});
const requireAuth = [optionalAuth, (req, _res, next) => (req.user ? next() : next(httpError(401, "Please log in")))];
const requireAdmin = [...requireAuth, (req, _res, next) => (req.user.role === "admin" ? next() : next(httpError(403, "Admins only")))];

// ---------- Auth ----------
app.post("/api/auth/register", ah(async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !password) throw httpError(400, "Name, email and password are required");
  if (password.length < 6) throw httpError(400, "Password must be at least 6 characters");
  if (await User.exists({ email: email.toLowerCase() })) throw httpError(409, "An account with this email already exists");
  const user = await User.create({ name, email, phone, password: await bcrypt.hash(password, 10) });
  res.status(201).json({ token: sign(user), user: publicUser(user) });
}));

app.post("/api/auth/login", ah(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: String(email).toLowerCase() }).select("+password");
  if (!user || !(await bcrypt.compare(String(password), user.password))) throw httpError(401, "Incorrect email or password");
  res.json({ token: sign(user), user: publicUser(user) });
}));

app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------- Simple Password Reset (No Token Required) ----------
app.post("/api/auth/simple-reset-password", ah(async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) throw httpError(400, "Email and new password are required");
  if (newPassword.length < 6) throw httpError(400, "Password must be at least 6 characters long");

  const user = await User.findOne({ email: String(email).toLowerCase() });
  if (!user) throw httpError(404, "No account found with this email");

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();
  res.json({ ok: true, message: "Password updated successfully. You can now log in." });
}));

// ---------- Admin User Management ----------
app.get("/api/admin/users", requireAdmin, ah(async (_req, res) => {
  const users = await User.find({ role: "customer" }).sort({ createdAt: -1 });
  res.json(users.map(publicUser));
}));

app.put("/api/admin/users/:id/nrp", requireAdmin, ah(async (req, res) => {
  const { isNrpAllowed } = req.body;
  const user = await User.findById(req.params.id);
  if (!user) throw httpError(404, "User not found");
  
  user.isNrpAllowed = Boolean(isNrpAllowed);
  await user.save();
  res.json(publicUser(user));
}));

app.delete("/api/admin/users/:id", requireAdmin, ah(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) throw httpError(404, "User not found");
  if (user.role === "admin") throw httpError(403, "Cannot delete admin accounts");

  await User.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
}));

// ---------- Products (public with conditional pricing) ----------
app.get("/api/categories", (_req, res) => res.json(CATEGORIES));

app.get(["/api/products", "/products"], optionalAuth, ah(async (req, res) => {
  const { q, category, sort = "featured", page = 1, limit = 12, featured } = req.query;
  const filter = {};
  if (q) filter.name = { $regex: String(q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), $options: "i" };
  if (category) filter.category = category;
  if (featured === "true") filter.featured = true;

  const sorts = { "price-asc": { nrp: 1 }, "price-desc": { nrp: -1 }, name: { name: 1 }, newest: { createdAt: -1 }, featured: { featured: -1, name: 1 } };
  const lim = Math.min(Number(limit) || 12, 100);
  const pg = Math.max(Number(page) || 1, 1);

  const [items, total] = await Promise.all([
    Product.find(filter).sort(sorts[sort] || sorts.featured).skip((pg - 1) * lim).limit(lim),
    Product.countDocuments(filter),
  ]);

  const allowNrp = req.user?.role === "admin" || req.user?.isNrpAllowed === true;
  const formattedItems = items.map((p) => {
    const obj = p.toObject();
    return {
      ...obj,
      price: allowNrp ? obj.nrp : obj.mrp,
      showNrp: allowNrp,
    };
  });

  res.json({ items: formattedItems, total, page: pg, pages: Math.ceil(total / lim) });
}));

app.get(["/api/products/:id", "/products/:id"], optionalAuth, ah(async (req, res) => {
  const p = mongoose.isValidObjectId(req.params.id) && (await Product.findById(req.params.id));
  if (!p) throw httpError(404, "Product not found");

  const allowNrp = req.user?.role === "admin" || req.user?.isNrpAllowed === true;
  const obj = p.toObject();

  res.json({
    ...obj,
    price: allowNrp ? obj.nrp : obj.mrp,
    showNrp: allowNrp,
  });
}));

// ---------- Products (admin) ----------
const productFields = (b) => {
  const out = {};
  ["name", "category", "description", "images", "featured"].forEach((k) => b[k] !== undefined && (out[k] = b[k]));
  ["mrp", "nrp", "stock"].forEach((k) => b[k] !== undefined && (out[k] = Number(b[k])));
  return out;
};
app.post("/api/admin/products", requireAdmin, ah(async (req, res) => {
  res.status(201).json(await Product.create(productFields(req.body)));
}));
app.put("/api/admin/products/:id", requireAdmin, ah(async (req, res) => {
  const p = await Product.findById(req.params.id);
  if (!p) throw httpError(404, "Product not found");
  p.set(productFields(req.body));
  res.json(await p.save());
}));
app.delete("/api/admin/products/:id", requireAdmin, ah(async (req, res) => {
  const p = await Product.findByIdAndDelete(req.params.id);
  if (!p) throw httpError(404, "Product not found");
  res.json({ ok: true });
}));

// ---------- Orders & Rules Helpers ----------
async function buildOrder(items, address = {}, user = null) {
  if (!Array.isArray(items) || !items.length) throw httpError(400, "Your cart is empty");
  const lines = [];
  const allowNrp = user?.role === "admin" || user?.isNrpAllowed === true;

  for (const { id, qty } of items) {
    const p = mongoose.isValidObjectId(id) && (await Product.findById(id));
    if (!p) throw httpError(400, "A product in your cart is no longer available");
    const q = Math.floor(Number(qty));
    if (!(q > 0)) throw httpError(400, "Invalid quantity");
    if (q > p.stock) throw httpError(400, `Only ${p.stock} left of ${p.name}`);
    
    const activePrice = allowNrp ? p.nrp : p.mrp;
    lines.push({ product: p._id, name: p.name, price: activePrice, mrp: p.mrp, qty: q, image: p.images?.[0] });
  }

  const subtotal = lines.reduce((s, l) => s + l.price * l.qty, 0);

  if (subtotal < MIN_ORDER_AMOUNT) {
    throw httpError(400, `Minimum order amount is ₹${MIN_ORDER_AMOUNT}. Your current subtotal is ₹${subtotal}.`);
  }

  const shipping = calcShippingByCoords(subtotal, address.lat, address.lng);
  return { items: lines, subtotal, shipping, discount: 0, total: subtotal + shipping };
}

function validateAddress(a = {}) {
  if (!a.name?.trim()) throw httpError(400, "Name is required");
  if (!/^[6-9]\d{9}$/.test(a.phone || "")) throw httpError(400, "Enter a 10-digit mobile number");
  if (!/^\S+@\S+\.\S+$/.test(a.email || "")) throw httpError(400, "Enter a valid email");
  if (!a.line1?.trim() || !a.city?.trim()) throw httpError(400, "Address is incomplete");
}

const decrementStock = (items) =>
  Promise.all(items.map((l) => Product.updateOne({ _id: l.product }, { $inc: { stock: -l.qty } })));
const newOrderId = () => `HSM-${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(2).toString("hex").toUpperCase()}`;

// Telegram Notification Helper
async function sendTelegramNotification(order) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    console.log("Telegram credentials missing in environment variables. Skipping notification.");
    return;
  }

  const addr = order.address;
  const itemsList = order.items.map(i => `• ${i.name} x ${i.qty} (₹${i.price * i.qty})`).join("\n");
  
  const text = 
    `🛒 *New Order Received!* (\`${order.orderId}\`)\n\n` +
    `👤 *Customer:* ${addr.name}\n` +
    `📞 *Phone:* ${addr.phone}\n` +
    `📧 *Email:* ${addr.email}\n\n` +
    `📍 *Address:*\n` +
    `${addr.line1}${addr.line2 ? `, ${addr.line2}` : ""}\n` +
    `${addr.city}, ${addr.district}, ${addr.state}\n\n` +
    `📦 *Items:*\n${itemsList}\n\n` +
    `🚚 *Shipping:* ₹${order.shipping}\n` +
    `💰 *Total:* ₹${order.total} (${order.paymentMethod})`;

  try {
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text: text,
        parse_mode: "Markdown",
      }),
    });
    
    if (res.ok) {
      console.log(`✅ Telegram alert sent for order ${order.orderId}`);
    } else {
      const err = await res.json();
      console.error("Telegram API Error:", err.description);
    }
  } catch (err) {
    console.error("Failed to send Telegram notification:", err.message);
  }
}

// Price quote for the cart
app.post("/api/orders/quote", optionalAuth, ah(async (req, res) => {
  const o = await buildOrder(req.body.items, req.body.address, req.user);
  res.json({ ...o, codAvailable: o.total <= COD_MAX });
}));

// COD order
app.post("/api/orders", optionalAuth, ah(async (req, res) => {
  validateAddress(req.body.address);
  const o = await buildOrder(req.body.items, req.body.address, req.user);
  if (o.total > COD_MAX) throw httpError(400, `COD not available above ₹${COD_MAX}`);
  
  const order = await Order.create({
    ...o, orderId: newOrderId(), user: req.user?._id ?? null, customerEmail: req.user?.email ?? req.body.address.email,
    guest: !req.user, address: req.body.address, paymentMethod: "COD", paymentStatus: "Pending",
    history: [{ status: "Placed" }],
  });
  await decrementStock(o.items);

  sendTelegramNotification(order).catch(console.error);

  res.status(201).json(order);
}));

// Razorpay step 1: create payment order
const razorpay = RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET ? new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET }) : null;
app.post("/api/payments/razorpay/order", optionalAuth, ah(async (req, res) => {
  if (!razorpay) throw httpError(503, "Online payment is not configured");
  validateAddress(req.body.address);
  const o = await buildOrder(req.body.items, req.body.address, req.user);
  const rp = await razorpay.orders.create({ amount: o.total * 100, currency: "INR", receipt: `rcpt_${Date.now()}` });
  res.json({ keyId: RAZORPAY_KEY_ID, razorpayOrderId: rp.id, amount: rp.amount, currency: rp.currency });
}));

// Razorpay step 2: verify signature, then save order
app.post("/api/payments/razorpay/verify", optionalAuth, ah(async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, items, address } = req.body;
  const expected = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET || "").update(`${razorpay_order_id}|${razorpay_payment_id}`).digest("hex");
  if (!razorpay_signature || expected.length !== razorpay_signature.length ||
      !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(razorpay_signature))) throw httpError(400, "Payment verification failed");
  if (await Order.exists({ paymentId: razorpay_payment_id })) throw httpError(409, "Payment already used");
  validateAddress(address);
  const o = await buildOrder(items, address, req.user);
  const rp = await razorpay.orders.fetch(razorpay_order_id);
  if (rp.amount !== o.total * 100) throw httpError(400, "Amount mismatch");
  
  const order = await Order.create({
    ...o, orderId: newOrderId(), user: req.user?._id ?? null, customerEmail: req.user?.email ?? address.email,
    guest: !req.user, address, paymentMethod: "Razorpay", paymentStatus: "Paid",
    razorpayOrderId: razorpay_order_id, paymentId: razorpay_payment_id, history: [{ status: "Placed" }],
  });
  await decrementStock(o.items);

  sendTelegramNotification(order).catch(console.error);

  res.status(201).json(order);
}));

// My orders
app.get("/api/orders/mine", requireAuth, ah(async (req, res) => {
  res.json(await Order.find({ user: req.user._id }).sort({ createdAt: -1 }));
}));

// Track an order
app.get("/api/orders/:orderId", optionalAuth, ah(async (req, res) => {
  const order = await Order.findOne({ orderId: req.params.orderId });
  if (!order) throw httpError(404, "Order not found");
  const isOwner = req.user && (String(order.user) === String(req.user._id) || req.user.role === "admin");
  const contact = String(req.query.contact || "").toLowerCase();
  const guestMatch = contact && (contact === order.address.email?.toLowerCase() || contact === order.address.phone);
  if (!isOwner && !guestMatch) throw httpError(403, "Not allowed to view this order");
  res.json(order);
}));

// Cancel order
app.post("/api/orders/:orderId/cancel", optionalAuth, ah(async (req, res) => {
  const order = await Order.findOne({ orderId: req.params.orderId });
  if (!order) throw httpError(404, "Order not found");
  const contact = String(req.body.contact || "").toLowerCase();
  const allowed = (req.user && String(order.user) === String(req.user._id)) ||
    (order.guest && contact && (contact === order.address.email?.toLowerCase() || contact === order.address.phone));
  if (!allowed) throw httpError(403, "Not allowed");
  if (!CANCELLABLE.includes(order.status)) throw httpError(400, "This order can no longer be cancelled");
  order.status = "Cancelled";
  order.history.push({ status: "Cancelled" });
  await order.save();
  await Promise.all(order.items.map((l) => Product.updateOne({ _id: l.product }, { $inc: { stock: l.qty } })));
  res.json(order);
}));

// ---------- Orders (admin) ----------
app.get("/api/admin/orders", requireAdmin, ah(async (req, res) => {
  const filter = req.query.status ? { status: req.query.status } : {};
  res.json(await Order.find(filter).sort({ createdAt: -1 }));
}));
app.put("/api/admin/orders/:orderId/status", requireAdmin, ah(async (req, res) => {
  const { status } = req.body;
  if (!STATUSES.includes(status)) throw httpError(400, "Choose a valid order status");
  const order = await Order.findOne({ orderId: req.params.orderId });
  if (!order) throw httpError(404, "Order not found");
  if (order.status !== status) {
    order.status = status;
    order.history.push({ status });
    if (status === "Delivered" && order.paymentMethod === "COD") order.paymentStatus = "Paid";
    await order.save();
  }
  res.json(order);
}));
app.delete("/api/admin/orders/:orderId", requireAdmin, ah(async (req, res) => {
  const r = await Order.deleteOne({ orderId: req.params.orderId });
  if (!r.deletedCount) throw httpError(404, "Order not found");
  res.json({ ok: true });
}));
app.get("/api/admin/stats", requireAdmin, ah(async (_req, res) => {
  const [orders, revenue, lowStock, customers] = await Promise.all([
    Order.countDocuments(),
    Order.aggregate([{ $match: { status: { $ne: "Cancelled" } } }, { $group: { _id: null, sum: { $sum: "$total" } } }]),
    Product.find({ stock: { $lte: 5 } }).sort({ stock: 1 }),
    User.countDocuments({ role: "customer" }),
  ]);
  res.json({ orders, revenue: revenue[0]?.sum ?? 0, customers, lowStock });
}));

// ---------- Health & errors ----------
app.get("/api/health", (_req, res) => res.json({ ok: true, store: "HANNAN SUPERMARKET-RCM PUDUKKAD" }));
app.use((_req, _res, next) => next(httpError(404, "Not found")));
app.use((err, _req, res, _next) => {
  const status = err.status || (err.name === "ValidationError" || err.name === "CastError" ? 400 : 500);
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? "Something went wrong" : err.message });
});

mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
}).then(() => {
  app.listen(PORT, () => console.log(`HANNAN SUPERMARKET API running on http://localhost:${PORT}`));
}).catch((e) => { 
  console.log("MongoDB connection failed:", e.message); 
  process.exit(1); 
});