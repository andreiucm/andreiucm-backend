import * as dotenv from "https://deno.land/std@0.203.0/dotenv/mod.ts";
import { Client } from "https://deno.land/x/mysql@v2.12.1/mod.ts";
// import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";


import {
	create,
	verify,
	getNumericDate,
} from "https://deno.land/x/djwt@v3.0.2/mod.ts";

//HACK: BYCRYPT ALTERNATIVE becaue it not working in deno deploy
// Hash a password using SHA-256
export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Compare a plain password with a stored hash
export async function comparePassword(
  plainPassword: string,
  hashedPassword: string,
): Promise<boolean> {
  const hashOfInput = await hashPassword(plainPassword);
  return hashOfInput === hashedPassword;
}

// Load environment variables
const env = await dotenv.load();

// Import JWT secret key
const JWT_SECRET = await crypto.subtle.importKey(
	"raw",
	new TextEncoder().encode(env.JWT_SECRET),
	{ name: "HMAC", hash: "SHA-256" },
	false,
	["sign", "verify"],
);

// MySQL connection
const client = await new Client().connect({
	hostname: env.MYSQL_HOST,
	username: env.MYSQL_USER,
	db: env.MYSQL_DB,
	password: env.MYSQL_PASSWORD,
	port: Number(env.MYSQL_PORT),
});

console.log("✅ Connected to MySQL & table ready.");

// JSON response helper
function jsonResponse(data: unknown, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			"Content-Type": "application/json",
      // ✅ CORS headers
      // "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Origin": "https://andreiucm.github.io",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
	});
}

// Create JWT token
async function createToken(userId: number) {
	return await create(
		{ alg: "HS256", typ: "JWT" },
		{ userId, exp: getNumericDate(60 * 60 * 24) }, // expires in 1 day
		JWT_SECRET,
	);
}

// Verify JWT
async function verifyToken(token: string) {
	try {
		const payload = await verify(token, JWT_SECRET);
		return payload as { userId: number };
	} catch {
		return null;
	}
}

// Server logic
Deno.serve(async (req) => {
	const url = new URL(req.url);
	const { pathname } = url;

  // CORS headers
	const headers = {
    // "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Origin": "https://andreiucm.github.io",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization",
	};

	if (req.method === "OPTIONS") {
		// Handle OPTIONS (CORS preflight)
		return new Response(null, { headers });
	}

	// ✅ Signup
	if (req.method === "POST" && pathname === "/signup") {
		const { name, email, password } = await req.json();
		if (!name || !email || !password)
			return jsonResponse({ error: "Missing fields" }, 400);

		// const hashed = await bcrypt.hash(password);
		const hashed = await hashPassword(password);
		try {
			await client.execute(
				"INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
				[name, email, hashed],
			);
			return jsonResponse({ success: true });
		} catch {
			return jsonResponse({ error: "Email already exists" }, 400);
		}
	}

	// ✅ Login
	if (req.method === "POST" && pathname === "/login") {
		const { email, password } = await req.json();
		const [user] = await client.query("SELECT * FROM users WHERE email = ?", [
			email,
		]);
    console.log(user);
		// if (!user || !(await bcrypt.compare(password, user.password))) {
		if (!user || !(await comparePassword(password, user.password))) {
			return jsonResponse({ error: "Invalid credentials" }, 401);
		}
    console.log("Generating token");
		const token = await createToken(user.id);
    console.log("Token generated:", token);
		return jsonResponse({ token });
	}

	// ✅ Protected route example
	if (req.method === "GET" && pathname === "/profile") {
    console.log("Accessing protected /profile route");
		const auth = req.headers.get("Authorization");
		if (!auth || !auth.startsWith("Bearer ")) {
			return jsonResponse({ error: "Unauthorized" }, 401);
		}

		const token = auth.split(" ")[1];
		const payload = await verifyToken(token);
		if (!payload) return jsonResponse({ error: "Invalid token" }, 401);

		const [user] = await client.query(
			"SELECT id, name, email FROM users WHERE id = ?",
			[payload.userId],
		);
		return jsonResponse(user);
	}

  // ✅ Protected /books route example
  if (req.method === "GET" && pathname === "/books") {
    console.log("Accessing protected /books route");

    // Check Authorization header
    const auth = req.headers.get("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    // Verify JWT token
    const token = auth.split(" ")[1];
    const payload = await verifyToken(token); // your verifyToken function
    if (!payload) return jsonResponse({ error: "Invalid token" }, 401);

    // Fetch books from MySQL
    const books = await client.query(
      "SELECT id, title, author, published_year FROM books",
    );

    // Return books as JSON
    return jsonResponse(books);
  }

  // --- POST: add a new book ---
  if (req.method === "POST" && pathname === "/books") {
    try {
      const { title, author, published_year } = await req.json();

      if (!title || !author || !published_year) {
        return jsonResponse({ error: "Missing fields" }, 400);
      }

      const result = await client.execute(
        "INSERT INTO books (title, author, published_year) VALUES (?, ?, ?)",
        [title, author, published_year],
      );

      // Fetch the newly inserted book by its ID
      const [newBook] = await client.query(
        "SELECT id, title, author, published_year FROM books WHERE id = ?",
        [result.lastInsertId],
      );

      return jsonResponse(newBook, 201);
    } catch (err) {
      console.error("Error creating book:", err);
      return jsonResponse({ error: "Failed to create book" }, 500);
    }
  }

	return jsonResponse({ error: "Not Found" }, 404);
});

console.log("🚀 Server running...");
