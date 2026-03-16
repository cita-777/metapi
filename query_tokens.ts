import Database from 'better-sqlite3';
import fs from 'fs';

const dbPath = './data/hub.db';
const db = new Database(dbPath, { readonly: true });

const tokens = db.prepare(`SELECT * FROM account_tokens WHERE account_id = 18`).all();
fs.writeFileSync('account_tokens_18.json', JSON.stringify(tokens, null, 2));
console.log('Saved tokens to account_tokens_18.json', tokens.length);
