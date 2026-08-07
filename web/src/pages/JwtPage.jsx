import { useState } from 'react';
import { post } from '../lib/api.js';

export default function JwtPage() {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState(null);
  const [error, setError] = useState('');

  async function decode() {
    setError('');
    try {
      const d = await post('/jwt/decode', { token });
      setDecoded(d);
    } catch (e) {
      setError(e.message);
      setDecoded(null);
    }
  }

  return (
    <div className="card">
      <h2>JWT Decode & Analisis</h2>
      <textarea rows={4} value={token} onChange={(e) => setToken(e.target.value)} placeholder="eyJhbGciOi..." />
      <button type="button" onClick={decode}>Decode</button>
      {error && <p className="err">{error}</p>}
      {decoded && (
        <div>
          <h3>Header</h3>
          <pre>{JSON.stringify(decoded.header, null, 2)}</pre>
          <h3>Payload</h3>
          <pre>{JSON.stringify(decoded.payload, null, 2)}</pre>
          <p className="note">
            {decoded.header.alg === 'none' && <b>Peringatan: alg=none terdeteksi!</b>} <br />
            {!decoded.payload.exp && <b>Klaim exp tidak ada (token tidak berakhir).</b>}{' '}
            {(!decoded.payload.iss || !decoded.payload.aud) && <b>Klaim iss/aud hilang.</b>}
          </p>
        </div>
      )}
    </div>
  );
}