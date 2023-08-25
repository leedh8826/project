import { queryDatabase } from '@/lib/db';

export default async function handler(req, res) {
    try {
        const query = 'SELECT harmful_domain,date_time FROM harmful_domain_index';
        const result = await queryDatabase(query);
        const harmfulDomains = result.map(row => ({ harmful_domain: row.harmful_domain,
                                                    datetime:row.date_time
        }));
        
        res.status(200).json({ harmfulDomains });
    } catch (error) {
        console.error('Error fetching harmful domain data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
