import fs from 'fs';

async function run() {
    const url = 'https://openai.api-test.us.ci';
    const accessToken = 'nMld3p6XNa6dB2CjwDKPAnJFb35Z';
    const userId = '2434';

    try {
        const res = await fetch(`${url}/api/token/?p=0`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'New-Api-User': userId,
                'Accept': 'application/json'
            }
        });
        const data = await res.json();
        fs.writeFileSync('tokens_result2.json', JSON.stringify({ apiData: data }, null, 2));
        console.log('Saved result to tokens_result2.json');
    } catch (err: any) {
        console.error('Fetch error:', err.message);
    }
}

run();
