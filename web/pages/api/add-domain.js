import { queryDatabase } from '@/lib/db';

export default async function handler(req, res) {
  if (req.method === 'POST') {
    const { domain } = req.body;

    try {
      const querySel = 'SELECT count(*) FROM harmful_domain_index WHERE harmful_domain = (?)';
      const [{'count(*)': count}] = await queryDatabase(querySel, [domain]);
      
      if(count != 0) {
        res.status(202).json({ message: 'Domain already exists' });
      } else {
        const query = 'INSERT INTO harmful_domain_index (harmful_domain) VALUES (?)';
        await queryDatabase(query, [domain]);
        res.status(201).json({ message: 'Domain added successfully' });
      }
    } catch (error) {
      console.error('Error adding domain:', error);
      res.status(500).json({ message: 'Error adding domain' });
    }
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}
