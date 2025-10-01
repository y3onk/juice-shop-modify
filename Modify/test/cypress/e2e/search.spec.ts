"// routes/products.js  (patched snippet)

import express from ""express"";
import pool from ""../db/pool""; // assume this exports a pg Pool
const router = express.Router();

/**
 * Helper: basic validation for search query.
 * - Trim, limit length
 * - Allow only a safe subset of characters (alphanum, space, -, _, ., @, :)
 * - If the client needs to search arbitrary characters, relax rules carefully,
 *   but always use parameterized queries (never string concat).
 */
function validateSearchQuery(q) {
  if (q == null) return """";
  const trimmed = String(q).trim();
  // maximum length: 200 chars (tune as needed)
  if (trimmed.length === 0 || trimmed.length > 200) return null;
  // allow alphanum, spaces and a few safe punctuation characters
  // This blocks injection payloads like: ""') union select ...
  const allowRegex = /^[\w\s\-\._@:]+$/u;
  if (!allowRegex.test(trimmed)) return null;
  return trimmed;
}

router.get(""/rest/products/search"", async (req, res, next) => {
  try {
    const rawQ = req.query.q ?? """";
    const q = validateSearchQuery(rawQ);
    if (q === null) {
      // Invalid query — return empty results rather than erroring,
      // preserving API contract while denying suspicious inputs.
      return res.json({ products: [] });
    }

    // Use parameterized query to avoid SQL injection.
    // Example: search by name or description using ILIKE and % wildcards.
    const sql = `
      SELECT id, name, description, price
      FROM products
      WHERE name ILIKE $1 OR description ILIKE $1
      LIMIT 100
    `;

    // Build the search pattern safely (client input is already validated)
    const pattern = `%${q}%`;

    const { rows } = await pool.query(sql, [pattern]);

    // Return products as JSON (no HTML here)
    return res.json({ products: rows });
  } catch (err) {
    // Log server-side; return safe generic error
    console.error(""Search handler error:"", err);
    return res.status(500).json({ error: ""internal_server_error"" });
  }
});

export default router;
// safe rendering: set textContent so HTML is not interpreted
const li = document.createElement(""li"");
li.textContent = item.name; // safe: renders as plain text
resultContainer.appendChild(li);
"