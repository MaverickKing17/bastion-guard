import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import Anthropic from "@anthropic-ai/sdk";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Claude Proxy Endpoint
  app.post("/api/chat", async (req, res) => {
    const { messages } = req.body;
    const apiKey = process.env.CLAUDE_API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: "CLAUDE_API_KEY is not configured in environment variables." });
    }

    try {
      const anthropic = new Anthropic({ apiKey });
      const response = await anthropic.messages.create({
        model: "claude-3-5-sonnet-20241022",
        max_tokens: 1024,
        system: "You are BastionAudit AI, a security assistant specialized in Canadian financial compliance (OSFI B-10, B-13, PIPEDA, FINTRAC). You help security admins analyze audit logs, identify PII leaks, and ensure data residency compliance in Canadian banking environments.",
        messages: messages,
      });

      res.json(response);
    } catch (error: any) {
      console.error("Claude API Error:", error);
      
      // Handle specific billing error
      if (error.status === 400 && error.message?.includes("credit balance is too low")) {
        return res.status(402).json({ 
          error: "Anthropic billing error: Your credit balance is too low. Please upgrade your plan or purchase credits at console.anthropic.com.",
          code: "BILLING_ERROR"
        });
      }

      res.status(500).json({ error: error.message || "Failed to communicate with Claude." });
    }
  });

  // Health check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", environment: process.env.NODE_ENV });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`BastionAudit Server running on http://localhost:${PORT}`);
  });
}

startServer();
