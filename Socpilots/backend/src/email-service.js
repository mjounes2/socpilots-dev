// ============================================================
//  SOCPilots — Email Notification Service
//  Sends SMTP emails for alerts, playbook actions, approvals
// ============================================================

const nodemailer = require('nodemailer');
const db = require('./db');

let smtpConfig = null;
let lastConfigFetch = 0;

// Cache SMTP config for 5 minutes to avoid constant DB reads
async function getSmtpConfig() {
  const now = Date.now();
  if (smtpConfig && (now - lastConfigFetch) < 5 * 60 * 1000) {
    return smtpConfig;
  }

  try {
    smtpConfig = await db.getSmtpSettings();
    lastConfigFetch = now;
    return smtpConfig;
  } catch (e) {
    console.error('[Email] Failed to load SMTP config:', e.message);
    return null;
  }
}

// Create SMTP transporter from config
async function createTransporter() {
  const config = await getSmtpConfig();
  if (!config || !config.enabled || !config.host) {
    return null;
  }

  const auth = config.auth_required
    ? { user: config.user, pass: config.password }
    : undefined;

  return nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.use_ssl,  // true for 465, false for 587
    requireTLS: config.use_tls && !config.use_ssl,
    auth: auth,
    tls: { rejectUnauthorized: false },
    logger: false,
    debug: false
  });
}

// Send email to single recipient
async function sendEmail(to, subject, htmlBody) {
  try {
    const config = await getSmtpConfig();
    if (!config || !config.enabled || !config.host) {
      console.warn('[Email] SMTP not configured, email not sent');
      return { success: false, error: 'SMTP not configured' };
    }

    const transporter = await createTransporter();
    if (!transporter) {
      return { success: false, error: 'Failed to create SMTP transporter' };
    }

    const info = await transporter.sendMail({
      from: config.from_address,
      to: to,
      subject: subject,
      html: htmlBody,
      text: htmlBody.replace(/<[^>]*>/g, '')  // Strip HTML for plain text version
    });

    console.log(`[Email] Sent to ${to}: ${subject}`, info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('[Email] Failed to send:', error.message);
    return { success: false, error: error.message };
  }
}

// Send email to all configured recipients
async function sendToRecipients(subject, htmlBody) {
  try {
    const config = await getSmtpConfig();
    if (!config || !config.enabled || !config.recipients.length) {
      console.warn('[Email] No recipients configured or SMTP disabled');
      return { success: false, error: 'No recipients configured' };
    }

    const results = [];
    for (const to of config.recipients) {
      const result = await sendEmail(to, subject, htmlBody);
      results.push({ to, ...result });
    }

    return {
      success: results.some(r => r.success),
      results: results
    };
  } catch (error) {
    console.error('[Email] sendToRecipients failed:', error.message);
    return { success: false, error: error.message };
  }
}

// Test SMTP connection by sending test email
// Bypasses the enabled flag — testing is how you verify config before enabling.
async function testSmtpConnection() {
  try {
    // Force-flush the 5-min cache so we pick up the latest saved values.
    smtpConfig = null;
    lastConfigFetch = 0;

    const config = await getSmtpConfig();
    if (!config || !config.host) {
      return { success: false, error: 'SMTP host not configured' };
    }

    if (!config.from_address) {
      return { success: false, error: 'From address not configured' };
    }

    if (!config.recipients.length) {
      return { success: false, error: 'No recipients configured' };
    }

    // Build transporter directly — do NOT check config.enabled here.
    const auth = config.auth_required
      ? { user: config.user, pass: config.password }
      : undefined;

    const transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.use_ssl,
      requireTLS: config.use_tls && !config.use_ssl,
      auth: auth,
      tls: { rejectUnauthorized: false },
    });

    const primaryRecipient = config.recipients[0];
    const info = await transporter.sendMail({
      from: config.from_address,
      to: primaryRecipient,
      subject: '[SOCPilots] SMTP Test Email',
      html: `<p>This is a test email from SOCPilots.</p><p>SMTP configuration is working correctly!</p>`
    });

    console.log('[Email] Test email sent successfully:', info.messageId);
    return { success: true, messageId: info.messageId, to: primaryRecipient };
  } catch (error) {
    console.error('[Email] Test failed:', error.message);
    return { success: false, error: error.message };
  }
}

// Email template: Investigation marked as True Positive
function generateInvestigationTPEmail(investigation) {
  const severity = (investigation.severity || 'unknown').toUpperCase();
  const severityColor = severity === 'CRITICAL' ? '#f32013' : severity === 'HIGH' ? '#ff9800' : '#2196f3';

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #4caf50">
        <h2 style="margin-top:0;color:#333">✓ Investigation Confirmed: True Positive</h2>

        <div style="background:#f0f8f0;padding:15px;border-radius:4px;margin:15px 0">
          <p style="margin:0"><strong>Rule ID:</strong> ${investigation.rule_id || '—'}</p>
          <p style="margin:5px 0"><strong>Agent:</strong> ${investigation.agent || '—'}</p>
          <p style="margin:5px 0"><strong>Source IP:</strong> ${investigation.src_ip || '—'}</p>
          <p style="margin:5px 0"><strong>Severity:</strong> <span style="color:${severityColor};font-weight:bold">${severity}</span></p>
          <p style="margin:5px 0"><strong>Description:</strong> ${investigation.description || '—'}</p>
        </div>

        <p style="color:#666;font-size:12px">
          Marked by: ${investigation.tp_marked_by || 'Unknown'}<br>
          Time: ${new Date(investigation.tp_marked_at).toLocaleString()}
        </p>
      </div>
    </div>
  `;
}

// Email template: Playbook action executed (with full alert context and AI investigation report)
function generatePlaybookExecutionEmail(playbookName, actionType, assetRef, result, alert = {}, investigationText = '') {
  const statusColor = result.success ? '#4caf50' : '#f32013';
  const statusText  = result.success ? '✓ EXECUTED' : '✗ FAILED';
  const severity    = (alert.severity || '').toUpperCase();
  const sevColor    = severity === 'CRITICAL' ? '#f32013' : severity === 'HIGH' ? '#ff9800' : '#2196f3';
  const mitre       = Array.isArray(alert.mitre) && alert.mitre.length
    ? alert.mitre.join(', ')
    : (alert.mitre || '—');

  const escHtml = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const MAX_REPORT = 3000;
  const reportSnippet = investigationText
    ? escHtml(investigationText.slice(0, MAX_REPORT)) +
      (investigationText.length > MAX_REPORT ? '\n\n*(truncated — full report in SOCPilots Investigations view)*' : '')
    : '';

  return `
    <div style="font-family:Arial,sans-serif;max-width:700px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:24px;border-radius:8px;border-left:4px solid ${statusColor}">
        <h2 style="margin-top:0;color:#333">${statusText}: ${escHtml(playbookName)}</h2>

        <div style="background:#f9f9f9;padding:15px;border-radius:4px;margin:15px 0">
          <h3 style="margin:0 0 10px;color:#555;font-size:13px;text-transform:uppercase;letter-spacing:.5px">Action Executed</h3>
          <p style="margin:0"><strong>Action:</strong> ${escHtml(actionType)}</p>
          <p style="margin:5px 0"><strong>Target:</strong> ${escHtml(assetRef || 'Unknown')}</p>
          ${result.detail ? `<p style="margin:5px 0"><strong>Detail:</strong> ${escHtml(result.detail)}</p>` : ''}
          ${result.hiveCaseId ? `<p style="margin:5px 0"><strong>TheHive Case:</strong> #${escHtml(result.hiveCaseId)}</p>` : ''}
        </div>

        <div style="background:#e8f4fd;padding:15px;border-radius:4px;margin:15px 0">
          <h3 style="margin:0 0 10px;color:#555;font-size:13px;text-transform:uppercase;letter-spacing:.5px">Alert Details</h3>
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <tr><td style="padding:5px 10px;color:#666;width:140px;vertical-align:top">Rule ID</td><td style="padding:5px 10px"><strong>${escHtml(alert.ruleId || '—')}</strong></td></tr>
            <tr style="background:#f0f8ff"><td style="padding:5px 10px;color:#666;vertical-align:top">Rule Level</td><td style="padding:5px 10px">${escHtml(String(alert.level || '—'))}</td></tr>
            <tr><td style="padding:5px 10px;color:#666;vertical-align:top">Severity</td><td style="padding:5px 10px"><span style="color:${sevColor};font-weight:bold">${escHtml(severity || '—')}</span></td></tr>
            <tr style="background:#f0f8ff"><td style="padding:5px 10px;color:#666;vertical-align:top">Agent / Host</td><td style="padding:5px 10px">${escHtml(alert.agent || '—')}</td></tr>
            <tr><td style="padding:5px 10px;color:#666;vertical-align:top">Source IP</td><td style="padding:5px 10px">${escHtml(alert.srcIp || '—')}</td></tr>
            <tr style="background:#f0f8ff"><td style="padding:5px 10px;color:#666;vertical-align:top">MITRE ATT&amp;CK</td><td style="padding:5px 10px">${escHtml(mitre)}</td></tr>
            <tr><td style="padding:5px 10px;color:#666;vertical-align:top">Timestamp</td><td style="padding:5px 10px">${escHtml(alert.timestamp || new Date().toISOString())}</td></tr>
            <tr style="background:#f0f8ff"><td style="padding:5px 10px;color:#666;vertical-align:top">Description</td><td style="padding:5px 10px">${escHtml(alert.description || '—')}</td></tr>
          </table>
        </div>

        ${reportSnippet ? `
        <div style="background:#fff8e1;padding:15px;border-radius:4px;margin:15px 0;border-left:3px solid #ffc107">
          <h3 style="margin:0 0 10px;color:#555;font-size:13px;text-transform:uppercase;letter-spacing:.5px">AI Investigation Report</h3>
          <pre style="font-size:12px;color:#333;white-space:pre-wrap;word-wrap:break-word;margin:0;font-family:monospace">${reportSnippet}</pre>
        </div>
        ` : ''}

        <p style="color:#999;font-size:11px;margin-top:15px;border-top:1px solid #eee;padding-top:10px">
          Executed at: ${new Date().toUTCString()} &mdash; SOCPilots Dark SOC Engine
        </p>
      </div>
    </div>
  `;
}

// Email template: Isolation approval needed
function generateIsolationApprovalEmail(approval, timeoutMinutes) {
  const expiresAt = new Date(approval.expires_at || (Date.now() + timeoutMinutes * 60000));

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #ff9800">
        <h2 style="margin-top:0;color:#d32f2f;text-transform:uppercase">⚠️ Isolation Approval Needed</h2>

        <div style="background:#fff3e0;padding:15px;border-radius:4px;margin:15px 0;border:1px solid #ffb74d">
          <p style="margin:0;font-weight:bold;color:#e65100">Protected Asset Triggered</p>
          <p style="margin:5px 0"><strong>Host/IP:</strong> ${approval.asset_ip || approval.agent || '—'}</p>
          <p style="margin:5px 0"><strong>Threat Source IP:</strong> ${approval.src_ip || '—'}</p>
          <p style="margin:5px 0"><strong>Reason:</strong> ${approval.reason || 'Alert matched isolation playbook'}</p>
        </div>

        <div style="background:#fff8e1;padding:12px;border-radius:4px;margin:15px 0;text-align:center">
          <p style="margin:0;color:#f57f17;font-weight:bold">
            ⏱️ EXPIRES IN ${timeoutMinutes} MINUTES
          </p>
          <p style="margin:5px 0 0 0;color:#999;font-size:11px">
            ${expiresAt.toLocaleString()} UTC
          </p>
        </div>

        <p style="color:#666;font-size:13px;margin:15px 0 0 0">
          <strong>Action Required:</strong><br>
          Please approve or reject this isolation immediately via the SOCPilots dashboard.<br>
          If no action is taken within ${timeoutMinutes} minutes, the request will be automatically rejected.
        </p>

        <p style="color:#999;font-size:11px;margin-top:15px">
          Created at: ${new Date(approval.created_at).toLocaleString()} UTC
        </p>
      </div>
    </div>
  `;
}

// Email template: New auto-triaged investigation
function generateAutoTriageEmail(investigation) {
  const severity = (investigation.severity || 'unknown').toUpperCase();
  const severityColor = severity === 'CRITICAL' ? '#f32013' : severity === 'HIGH' ? '#ff9800' : '#2196f3';

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #2196f3">
        <h2 style="margin-top:0;color:#333">🤖 New Investigation Auto-Triaged</h2>

        <div style="background:#e3f2fd;padding:15px;border-radius:4px;margin:15px 0">
          <p style="margin:0"><strong>Rule ID:</strong> ${investigation.rule_id || '—'}</p>
          <p style="margin:5px 0"><strong>Agent:</strong> ${investigation.agent || '—'}</p>
          <p style="margin:5px 0"><strong>Source IP:</strong> ${investigation.src_ip || '—'}</p>
          <p style="margin:5px 0"><strong>Severity:</strong> <span style="color:${severityColor};font-weight:bold">${severity}</span></p>
          <p style="margin:5px 0"><strong>Description:</strong> ${investigation.description || '—'}</p>
        </div>

        <p style="color:#666;font-size:12px">
          Auto-triaged at: ${new Date().toLocaleString()} UTC<br>
          Review this investigation in the SOCPilots dashboard.
        </p>
      </div>
    </div>
  `;
}

// Email template: New TheHive case created
function generateCaseCreatedEmail(caseData) {
  const severity = (caseData.severity || 'unknown').toUpperCase();
  const severityColor = severity === 'CRITICAL' ? '#f32013' : severity === 'HIGH' ? '#ff9800' : '#ff9800';

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #9c27b0">
        <h2 style="margin-top:0;color:#333">📋 New SP-CM Case Created</h2>

        <div style="background:#f3e5f5;padding:15px;border-radius:4px;margin:15px 0">
          <p style="margin:0"><strong>Title:</strong> ${caseData.title || '—'}</p>
          <p style="margin:5px 0"><strong>Severity:</strong> <span style="color:${severityColor};font-weight:bold">${severity}</span></p>
          ${caseData.description ? `<p style="margin:5px 0"><strong>Description:</strong> ${caseData.description}</p>` : ''}
          ${caseData.createdBy ? `<p style="margin:5px 0"><strong>Created by:</strong> ${caseData.createdBy}</p>` : ''}
        </div>

        <p style="color:#666;font-size:12px">
          Case created at: ${new Date().toLocaleString()} UTC<br>
          Review in the SOCPilots Cases module.
        </p>
      </div>
    </div>
  `;
}

// Email template: Password reset
function generatePasswordResetEmail(resetLink, username) {
  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #00e5ff">
        <h2 style="margin-top:0;color:#333">🔐 Password Reset Request</h2>

        <p style="color:#333">Hello <strong>${username}</strong>,</p>
        <p style="color:#555">A password reset was requested for your SOCPilots account. Click the button below to set a new password. This link expires in 30 minutes.</p>

        <div style="text-align:center;margin:24px 0">
          <a href="${resetLink}" style="background:#0d47a1;color:white;padding:12px 28px;border-radius:4px;text-decoration:none;font-weight:bold;font-size:14px">
            Reset My Password
          </a>
        </div>

        <p style="color:#888;font-size:12px">
          If you did not request a password reset, ignore this email — your password will not change.<br><br>
          Link expires at: ${new Date(Date.now() + 30 * 60 * 1000).toLocaleString()} UTC
        </p>
      </div>
    </div>
  `;
}

module.exports = {
  getSmtpConfig,
  createTransporter,
  sendEmail,
  sendToRecipients,
  testSmtpConnection,
  generateInvestigationTPEmail,
  generatePlaybookExecutionEmail,
  generateIsolationApprovalEmail,
  generateAutoTriageEmail,
  generateCaseCreatedEmail,
  generatePasswordResetEmail
};
