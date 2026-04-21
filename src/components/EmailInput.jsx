import React, { useState, useRef } from 'react';

export default function EmailInput({ onAnalyze, isAnalyzing }) {
  const [rawEmail, setRawEmail] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState('');
  const fileRef = useRef(null);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) readFile(file);
  };

  const readFile = (file) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => setRawEmail(e.target.result);
    reader.readAsText(file);
  };

  const handleAnalyze = () => {
    if (rawEmail.trim()) onAnalyze(rawEmail);
  };

  const loadSample = () => {
    const sample = `Received: from mail-evil.example.com (mail-evil.example.com [203.0.113.66])
        by mx.google.com with ESMTPS id abc123
        for <victim@company.com>;
        Mon, 21 Apr 2025 10:30:00 -0700 (PDT)
Received: from unknown (HELO suspicious-server.xyz) (192.168.1.100)
        by mail-evil.example.com with SMTP; Mon, 21 Apr 2025 10:29:55 -0700
Authentication-Results: mx.google.com;
       dkim=fail header.i=@paypa1.com header.s=selector1;
       spf=softfail (google.com: domain of noreply@paypa1.com does not designate 203.0.113.66 as permitted sender);
       dmarc=fail (p=REJECT sp=REJECT) header.from=paypa1.com
From: PayPal Security <security@paypa1.com>
Reply-To: paypal-verify@gmail.com
To: victim@company.com
Subject: URGENT: Your PayPal Account Has Been Suspended!!!
Date: Mon, 21 Apr 2025 10:30:00 -0700
X-Mailer: PHPMailer 5.2.28
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_12345"

------=_Part_12345
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Dear Valued Customer,</p>

<p>We have detected <b>unusual activity</b> on your PayPal account. Your account has been TEMPORARILY SUSPENDED due to unauthorized access attempts.</p>

<p>You must <b>verify your identity immediately</b> or your account will be permanently terminated within 24 hours.</p>

<p>Click here to verify your account: <a href="http://paypa1-secure-login.xyz/verify?id=victim@company.com&token=abc123">https://www.paypal.com/verify</a></p>

<p>Please update your payment information and confirm your identity by clicking below:</p>
<p><a href="http://192.168.1.50:8080/paypal/login.php">Confirm Your Account Now</a></p>

<p>FAILURE TO ACT IMMEDIATELY will result in permanent account deactivation. This is your FINAL WARNING!!!</p>

<p>If you do not confirm your credit card details within 24 hours, we will have no choice but to suspend your account.</p>

<p>Best regards,<br>PayPal Security Team<br>Do not share this email with anyone.</p>
</body>
</html>

------=_Part_12345
Content-Type: application/octet-stream; name="PayPal_Invoice.pdf.exe"
Content-Disposition: attachment; filename="PayPal_Invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAA==

------=_Part_12345--`;
    setRawEmail(sample);
    setFileName('sample-phishing.eml');
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title"><span className="card-icon">📧</span> Email Input</div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-secondary btn-sm" onClick={loadSample}>Load Sample</button>
          <button className="btn btn-secondary btn-sm" onClick={() => { setRawEmail(''); setFileName(''); }}>Clear</button>
        </div>
      </div>

      <div
        className={`drop-zone ${dragOver ? 'drag-over' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
        style={{ marginBottom: '16px' }}
      >
        <div className="drop-icon">📁</div>
        <div className="drop-text">{fileName || 'Drag & drop .eml file or click to browse'}</div>
        <div className="drop-hint">Supports .eml, .txt, or raw email text files</div>
        <input ref={fileRef} type="file" accept=".eml,.txt,.msg" style={{ display: 'none' }} onChange={handleFileSelect} />
      </div>

      <textarea
        className="textarea"
        value={rawEmail}
        onChange={(e) => setRawEmail(e.target.value)}
        placeholder="Or paste raw email headers and body here..."
        spellCheck={false}
      />

      <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
        <button className="btn btn-primary" onClick={handleAnalyze} disabled={!rawEmail.trim() || isAnalyzing}>
          {isAnalyzing ? <><span className="loading-spinner" style={{ width: 16, height: 16 }} /> Analyzing...</> : '🔍 Analyze Email'}
        </button>
      </div>
    </div>
  );
}
