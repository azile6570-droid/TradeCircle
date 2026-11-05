require("dotenv").config();

const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

async function main() {
    if (!process.env.DATABASE_URL) {
        throw new Error("DATABASE_URL must be configured before initializing the database.");
    }

    const schemaPath = path.join(__dirname, "..", "database", "schema.sql");
    const schema = fs.readFileSync(schemaPath, "utf8");
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: true } : false
    });

    let client;
    try {
        client = await pool.connect();
        await client.query("BEGIN");
        await client.query(schema);
        await client.query("COMMIT");
        console.log("TradeCircle database schema initialized.");
    } catch (error) {
        if (client) await client.query("ROLLBACK");
        throw error;
    } finally {
        if (client) client.release();
        await pool.end();
    }
}

main().catch((error) => {
    console.error("TradeCircle database initialization failed:", error.message);
    process.exitCode = 1;
});
