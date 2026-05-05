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

  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.use_ssl,  // true for 465, false for 587
    requireTLS: config.use_tls && !config.use_ssl,
    auth: auth,
    logger: true,
    debug: true,
    tls: {
      // Allow self-signed certificates (for internal mail servers)
      rejectUnauthorized: false
    }
  });

  // Log the connection attempt
  console.log('[Email] SMTP Transporter created:', {
    host: config.host,
    port: config.port,
    secure: config.use_ssl,
    requireTLS: config.use_tls && !config.use_ssl,
    auth: auth ? 'enabled' : 'disabled',
    allowSelfSigned: true
  });

  return transporter;
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
async function testSmtpConnection() {
  try {
    const config = await getSmtpConfig();

    // Detailed validation with clear error messages
    if (!config) {
      return { success: false, error: 'SMTP settings not found in database. Please save configuration first.' };
    }

    if (!config.host) {
      return { success: false, error: 'SMTP Host is not configured. Please enter the SMTP server hostname (e.g., smtp.gmail.com).' };
    }

    if (!config.from_address) {
      return { success: false, error: 'From Address is not configured. Please enter the sender email address.' };
    }

    if (!config.recipients || !Array.isArray(config.recipients) || config.recipients.length === 0) {
      return { success: false, error: 'No recipient emails configured. Please add at least one recipient email address.' };
    }

    const transporter = await createTransporter();
    if (!transporter) {
      return { success: false, error: 'Failed to create SMTP transporter. Check SMTP host, port, TLS/SSL settings, and credentials.' };
    }

    // Ensure recipients is an array
    const recipientsList = Array.isArray(config.recipients)
      ? config.recipients
      : (typeof config.recipients === 'string'
          ? config.recipients.split(',').map(r => r.trim()).filter(r => r)
          : []);

    if (recipientsList.length === 0) {
      return { success: false, error: 'No valid recipient emails to send test message to.' };
    }

    const primaryRecipient = recipientsList[0];
    const info = await transporter.sendMail({
      from: config.from_address,
      to: primaryRecipient,
      subject: '[SOCPilots] SMTP Test Email',
      html: `<p>This is a test email from SOCPilots.</p><p>SMTP configuration is working correctly!</p>`
    });

    console.log('[Email] Test email sent successfully:', info.messageId);
    return { success: true, messageId: info.messageId, to: primaryRecipient };
  } catch (error) {
    console.error('[Email] Test failed:', {
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response,
      stack: error.stack
    });
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

// Email template: Playbook action executed
function generatePlaybookExecutionEmail(playbookName, actionType, assetRef, result) {
  const statusColor = result.success ? '#4caf50' : '#f32013';
  const statusText = result.success ? '✓ EXECUTED' : '✗ FAILED';

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5">
      <div style="background:white;padding:20px;border-radius:8px;border-left:4px solid ${statusColor}">
        <h2 style="margin-top:0;color:#333">${statusText}: ${playbookName}</h2>

        <div style="background:#f9f9f9;padding:15px;border-radius:4px;margin:15px 0">
          <p style="margin:0"><strong>Action:</strong> ${actionType}</p>
          <p style="margin:5px 0"><strong>Target:</strong> ${assetRef || 'Unknown'}</p>
          ${result.detail ? `<p style="margin:5px 0"><strong>Detail:</strong> ${result.detail}</p>` : ''}
          ${result.duration ? `<p style="margin:5px 0"><strong>Duration:</strong> ${result.duration}ms</p>` : ''}
        </div>

        <p style="color:#999;font-size:11px">
          Executed at: ${new Date().toLocaleString()} UTC
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

module.exports = {
  getSmtpConfig,
  createTransporter,
  sendEmail,
  sendToRecipients,
  testSmtpConnection,
  generateInvestigationTPEmail,
  generatePlaybookExecutionEmail,
  generateIsolationApprovalEmail
};
