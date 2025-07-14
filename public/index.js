// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
import { pgTable, text, serial, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  email: text("email"),
  createdAt: timestamp("created_at").defaultNow(),
  isActive: boolean("is_active").default(true)
});
var sessions = pgTable("sessions", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id),
  token: text("token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow()
});
var sites = pgTable("sites", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(),
  icon: text("icon").notNull(),
  color: text("color").notNull(),
  userId: serial("user_id").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow()
});
var insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  email: true
});
var loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required")
});
var forgotPasswordSchema = z.object({
  username: z.string().min(1, "Username is required")
});
var insertSiteSchema = createInsertSchema(sites).pick({
  name: true,
  url: true,
  icon: true,
  color: true
});
var addSiteSchema = z.object({
  name: z.string().min(1, "Site name is required"),
  url: z.string().url("Please enter a valid URL"),
  icon: z.string().min(1, "Icon is required"),
  color: z.string().min(1, "Color is required")
});

// server/storage.ts
import { eq, and, gt } from "drizzle-orm";
import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import crypto from "crypto";
var db = null;
try {
  if (process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith("postgresql://")) {
    const sql = neon(process.env.DATABASE_URL);
    db = drizzle(sql);
  }
} catch (error) {
  console.log("Database connection failed, using in-memory storage");
}
var DbStorage = class {
  async getUser(id) {
    if (!db) return void 0;
    const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return result[0];
  }
  async getUserByUsername(username) {
    if (!db) return void 0;
    const result = await db.select().from(users).where(eq(users.username, username)).limit(1);
    return result[0];
  }
  async createUser(insertUser) {
    if (!db) throw new Error("Database not available");
    const result = await db.insert(users).values(insertUser).returning();
    return result[0];
  }
  async createSession(userId) {
    if (!db) throw new Error("Database not available");
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1e3);
    const result = await db.insert(sessions).values({
      userId,
      token,
      expiresAt
    }).returning();
    return result[0];
  }
  async getSessionByToken(token) {
    if (!db) return void 0;
    const result = await db.select().from(sessions).where(
      and(
        eq(sessions.token, token),
        gt(sessions.expiresAt, /* @__PURE__ */ new Date())
      )
    ).limit(1);
    return result[0];
  }
  async deleteSession(token) {
    if (!db) return;
    await db.delete(sessions).where(eq(sessions.token, token));
  }
  async validateSession(token) {
    const session = await this.getSessionByToken(token);
    if (!session) return void 0;
    const user = await this.getUser(session.userId);
    return user;
  }
  async getSitesByUserId(userId) {
    if (!db) return [];
    const result = await db.select().from(sites).where(eq(sites.userId, userId));
    return result;
  }
  async createSite(site, userId) {
    if (!db) throw new Error("Database not available");
    const result = await db.insert(sites).values({
      ...site,
      userId
    }).returning();
    return result[0];
  }
  async deleteSite(siteId, userId) {
    if (!db) return;
    await db.delete(sites).where(and(eq(sites.id, siteId), eq(sites.userId, userId)));
  }
  async updateSite(siteId, site, userId) {
    if (!db) return void 0;
    const result = await db.update(sites).set(site).where(and(eq(sites.id, siteId), eq(sites.userId, userId))).returning();
    return result[0];
  }
};
var MemStorage = class {
  users;
  sessions;
  sites;
  currentUserId;
  currentSessionId;
  currentSiteId;
  constructor() {
    this.users = /* @__PURE__ */ new Map();
    this.sessions = /* @__PURE__ */ new Map();
    this.sites = /* @__PURE__ */ new Map();
    this.currentUserId = 1;
    this.currentSessionId = 1;
    this.currentSiteId = 1;
    const hardcodedUser = {
      id: 1,
      username: "Gun47890",
      password: "159753",
      email: null,
      createdAt: /* @__PURE__ */ new Date(),
      isActive: true
    };
    this.users.set(1, hardcodedUser);
    this.currentUserId = 2;
    const defaultSites = [
      {
        id: 1,
        name: "SmartBiz",
        url: "https://www.amazon.in/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fsmartbiz.amazon.in%2Fhome&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_rangoli_seller_in&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=amzn_rangoli_seller_in&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
        icon: "Store",
        color: "text-orange-500",
        userId: 1,
        createdAt: /* @__PURE__ */ new Date()
      },
      {
        id: 2,
        name: "PhonePe",
        url: "https://business.phonepe.com/login",
        icon: "Smartphone",
        color: "text-purple-500",
        userId: 1,
        createdAt: /* @__PURE__ */ new Date()
      },
      {
        id: 3,
        name: "WhatsApp",
        url: "https://web.whatsapp.com/",
        icon: "MessageCircle",
        color: "text-green-500",
        userId: 1,
        createdAt: /* @__PURE__ */ new Date()
      },
      {
        id: 4,
        name: "WCommerce",
        url: "https://partner.wcommerce.store/auth/login",
        icon: "ShoppingCart",
        color: "text-blue-500",
        userId: 1,
        createdAt: /* @__PURE__ */ new Date()
      },
      {
        id: 5,
        name: "Instagram",
        url: "https://instagram.com",
        icon: "Instagram",
        color: "text-pink-500",
        userId: 1,
        createdAt: /* @__PURE__ */ new Date()
      },
      {
        id: 6,
        name: "Facebook",
        url: "https://facebook.com",
        icon: "Facebook",
        color: "text-blue-600",
        userId: 1,
        createdAt: /* @__PURE__ */ new Date()
      }
    ];
    defaultSites.forEach((site) => {
      this.sites.set(site.id, site);
    });
    this.currentSiteId = 7;
  }
  async getUser(id) {
    return this.users.get(id);
  }
  async getUserByUsername(username) {
    return Array.from(this.users.values()).find(
      (user) => user.username === username
    );
  }
  async createUser(insertUser) {
    const id = this.currentUserId++;
    const user = {
      ...insertUser,
      id,
      createdAt: /* @__PURE__ */ new Date(),
      isActive: true,
      email: insertUser.email || null
    };
    this.users.set(id, user);
    return user;
  }
  async createSession(userId) {
    const id = this.currentSessionId++;
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1e3);
    const session = {
      id,
      userId,
      token,
      expiresAt,
      createdAt: /* @__PURE__ */ new Date()
    };
    this.sessions.set(token, session);
    return session;
  }
  async getSessionByToken(token) {
    const session = this.sessions.get(token);
    if (!session || session.expiresAt < /* @__PURE__ */ new Date()) {
      if (session) this.sessions.delete(token);
      return void 0;
    }
    return session;
  }
  async deleteSession(token) {
    this.sessions.delete(token);
  }
  async validateSession(token) {
    const session = await this.getSessionByToken(token);
    if (!session) return void 0;
    const user = await this.getUser(session.userId);
    return user;
  }
  async getSitesByUserId(userId) {
    return Array.from(this.sites.values()).filter((site) => site.userId === userId);
  }
  async createSite(site, userId) {
    const id = this.currentSiteId++;
    const newSite = {
      ...site,
      id,
      userId,
      createdAt: /* @__PURE__ */ new Date()
    };
    this.sites.set(id, newSite);
    return newSite;
  }
  async deleteSite(siteId, userId) {
    const site = this.sites.get(siteId);
    if (site && site.userId === userId) {
      this.sites.delete(siteId);
    }
  }
  async updateSite(siteId, siteData, userId) {
    const site = this.sites.get(siteId);
    if (site && site.userId === userId) {
      const updatedSite = { ...site, ...siteData };
      this.sites.set(siteId, updatedSite);
      return updatedSite;
    }
    return void 0;
  }
};
var storage = db ? new DbStorage() : new MemStorage();

// server/routes.ts
import { z as z2 } from "zod";
async function registerRoutes(app2) {
  app2.post("/api/auth/login", async (req, res) => {
    try {
      const { username, password } = loginSchema.parse(req.body);
      const user = await storage.getUserByUsername(username);
      if (!user || user.password !== password) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
      if (!user.isActive) {
        return res.status(401).json({ message: "Account is disabled" });
      }
      const session = await storage.createSession(user.id);
      res.json({
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        },
        token: session.token
      });
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Invalid input", errors: error.errors });
      }
      console.error("Login error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.post("/api/auth/logout", async (req, res) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (token) {
        await storage.deleteSession(token);
      }
      res.json({ message: "Logged out successfully" });
    } catch (error) {
      console.error("Logout error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.get("/api/auth/me", async (req, res) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (!token) {
        return res.status(401).json({ message: "No token provided" });
      }
      const user = await storage.validateSession(token);
      if (!user) {
        return res.status(401).json({ message: "Invalid session" });
      }
      res.json({
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        }
      });
    } catch (error) {
      console.error("Session validation error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.post("/api/auth/forgot-password", async (req, res) => {
    try {
      const { username } = forgotPasswordSchema.parse(req.body);
      const user = await storage.getUserByUsername(username);
      if (!user) {
        return res.json({ message: "If the username exists, password reset instructions have been sent." });
      }
      res.json({ message: "Password reset instructions have been sent to your email." });
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Invalid input", errors: error.errors });
      }
      console.error("Forgot password error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.get("/api/sites", async (req, res) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (!token) {
        return res.status(401).json({ message: "No token provided" });
      }
      const user = await storage.validateSession(token);
      if (!user) {
        return res.status(401).json({ message: "Invalid session" });
      }
      const sites2 = await storage.getSitesByUserId(user.id);
      res.json(sites2);
    } catch (error) {
      console.error("Get sites error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.post("/api/sites", async (req, res) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (!token) {
        return res.status(401).json({ message: "No token provided" });
      }
      const user = await storage.validateSession(token);
      if (!user) {
        return res.status(401).json({ message: "Invalid session" });
      }
      const siteData = addSiteSchema.parse(req.body);
      const site = await storage.createSite(siteData, user.id);
      res.json(site);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Invalid input", errors: error.errors });
      }
      console.error("Create site error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.delete("/api/sites/:id", async (req, res) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (!token) {
        return res.status(401).json({ message: "No token provided" });
      }
      const user = await storage.validateSession(token);
      if (!user) {
        return res.status(401).json({ message: "Invalid session" });
      }
      const siteId = parseInt(req.params.id);
      await storage.deleteSite(siteId, user.id);
      res.json({ message: "Site deleted successfully" });
    } catch (error) {
      console.error("Delete site error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.put("/api/sites/:id", async (req, res) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (!token) {
        return res.status(401).json({ message: "No token provided" });
      }
      const user = await storage.validateSession(token);
      if (!user) {
        return res.status(401).json({ message: "Invalid session" });
      }
      const siteId = parseInt(req.params.id);
      const siteData = addSiteSchema.parse(req.body);
      const site = await storage.updateSite(siteId, siteData, user.id);
      if (!site) {
        return res.status(404).json({ message: "Site not found" });
      }
      res.json(site);
    } catch (error) {
      if (error instanceof z2.ZodError) {
        return res.status(400).json({ message: "Invalid input", errors: error.errors });
      }
      console.error("Update site error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  const host = process.env.HOST || (process.platform === "win32" ? "localhost" : "0.0.0.0");
  server.listen(port, host, () => {
    log(`\u2705 Server running at http://${host}:${port}`);
  });
})();
