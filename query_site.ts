import Database from 'better-sqlite3';
import fs from 'fs';

const dbPath = './data/hub.db';
const db = new Database(dbPath, { readonly: true });

async function run() {
    const sites = db.prepare(`SELECT * FROM sites WHERE url LIKE '%openai.api-test.us.ci%'`).all() as any[];
    if (sites.length === 0) {
        console.log("No sites found");
        return;
    }

    const site = sites[0];
    const accounts = db.prepare(`SELECT * FROM accounts WHERE site_id = ?`).all(site.id) as any[];

    if (accounts.length === 0) {
        console.log("No accounts found");
        return;
    }

    const account = accounts[0];
    const accessToken = account.access_token;

    console.log(`Site: ${site.url}, Platform: ${site.platform}`);
    console.log(`Access Token: ${accessToken.substring(0, 10)}...`);

    try {
        const res = await fetch(`${site.url}/api/token/?p=0`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });
        const data = await res.json();
        fs.writeFileSync('tokens_result.json', JSON.stringify({ site, accounts, apiData: data }, null, 2));
        console.log('Saved result to tokens_result.json');
    } catch (err: any) {
        console.error('Fetch error:', err.message);
    }
}

run();
