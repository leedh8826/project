import { queryDatabase } from '@/lib/db';

export default async function handler(req, res) {
    try {
        const query = 'SELECT * FROM pcap_harmful_log ORDER BY created_at DESC LIMIT 10;';
        const result = await queryDatabase(query);
        const pcapHarmfulLog = result.map(row => ({ 
                                    pcap_index: row.pcap_index.toString(),
                                    harmful_domain: row.harmful_domain,
                                    src_ip: row.src_ip,
                                    des_ip: row.des_ip,
                                    src_port: row.src_port,
                                    des_port: row.des_port,
                                    created_at: row.created_at
                                }));
        console.log(pcapHarmfulLog);
        res.status(200).json({ pcapHarmfulLog });
    } catch (error) {
        console.error('Error fetching harmful domain data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
