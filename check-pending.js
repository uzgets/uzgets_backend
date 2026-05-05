import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config();

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function check() {
  try {
    // Pending orders by type
    const pending = await pool.query(`
      SELECT order_type, type_amount, COUNT(*) as cnt, MIN(created_at) as oldest
      FROM orders 
      WHERE status = 'pending' AND payment_status = 'pending'
      GROUP BY order_type, type_amount 
      ORDER BY cnt DESC
    `);
    
    console.log('\n📊 Pending orders by type:');
    console.table(pending.rows);
    
    // Total pending count
    const total = await pool.query(`
      SELECT COUNT(*) as total 
      FROM orders 
      WHERE status = 'pending' AND payment_status = 'pending'
    `);
    console.log('Total pending orders:', total.rows[0].total);
    
    // Old pending orders (older than 8 minutes)
    const old = await pool.query(`
      SELECT COUNT(*) as old_count 
      FROM orders 
      WHERE status = 'pending' AND payment_status = 'pending'
        AND created_at < NOW() - INTERVAL '8 minutes'
    `);
    console.log('Old pending orders (>8 min):', old.rows[0].old_count);
    
    // Recent pending orders by stars amount (for slot analysis)
    const recent = await pool.query(`
      SELECT type_amount, summ, created_at 
      FROM orders 
      WHERE order_type = 'stars' AND status = 'pending' AND payment_status = 'pending'
        AND created_at >= NOW() - INTERVAL '8 minutes'
      ORDER BY type_amount, summ
    `);
    console.log('\n⭐ Recent pending STARS orders (last 8 min):');
    console.table(recent.rows);
    
  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    await pool.end();
  }
}

check();
