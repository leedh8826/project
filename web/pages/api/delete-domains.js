import { queryDatabase } from '@/lib/db';

export default async function handler(req, res) {
  if (req.method === 'POST') {
    try {
      const { domains } = req.body;

      if (!Array.isArray(domains)) {
        return res.status(400).json({ message: 'Invalid data format.' });
      }

      // 도메인 삭제 처리
      const deleteQuery = 'DELETE FROM harmful_domain_index WHERE harmful_domain IN (?)';
      await queryDatabase(deleteQuery, [domains]);

      return res.status(200).json({ message: 'Domains deleted successfully.' });
    } catch (error) {
      console.error('Error deleting domains:', error);
      return res.status(500).json({ message: 'Error deleting domains.' });
    }
  } else {
    res.status(405).end(); // Method Not Allowed
  }
}
