import { serve } from "https://deno.land/std@0.203.0/http/server.ts";
import { config } from "https://deno.land/std@0.203.0/dotenv/mod.ts";
import { Client } from "https://deno.land/x/mysql@v2.12.1/mod.ts";

const env = await config();

const client = await new Client().connect({
  hostname: env.MYSQL_HOST,
  username: env.MYSQL_USER,
  db: env.MYSQL_DB,
  password: env.MYSQL_PASSWORD,
  port: Number(env.MYSQL_PORT),
});

console.log("✅ Connected to MySQL & table ready.");

// Helper for JSON responses
function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      "Content-Type": "application/json"
      // "Access-Control-Allow-Origin": "*",
      // "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      // "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

// HTTP server
serve(async (req) => {
  const url = new URL(req.url);
  const { pathname } = url;

  // CORS headers
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  
  // Handle OPTIONS (CORS preflight)
  if (req.method === "OPTIONS") {
    return new Response(null, { headers });
  }

  // GET /users
  if (req.method === "GET" && pathname === "/users") {
    const users = await client.query("SELECT * FROM users");
    return jsonResponse(users);
  }

  // GET /users/:id
  if (req.method === "GET" && pathname.startsWith("/users/")) {
    const id = pathname.split("/")[2];
    const [user] = await client.query("SELECT * FROM users WHERE id = ?", [id]);
    return user ? jsonResponse(user) : jsonResponse({ error: "User not found" }, 404);
  }

  // POST /users
  if (req.method === "POST" && pathname === "/users") {
    const body = await req.json();
    if (!body.name || !body.email) {
      return jsonResponse({ error: "Missing name or email" }, 400);
    }

    await client.execute("INSERT INTO users (name, email) VALUES (?, ?)", [
      body.name,
      body.email,
    ]);
    return jsonResponse({ success: true });
  }

  return jsonResponse({ error: "Not Found" }, 404);
});

console.log("🚀 Server running on http://localhost:8000");
