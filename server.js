/* ================================================================
   /zzzs — Key Server + Discord Bot (with Ticket System)
   Run: node server.js
   ================================================================ */
require('dotenv').config();

const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const {
  Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder,
  PermissionFlagsBits, ActionRowBuilder, ButtonBuilder, ButtonStyle,
  ChannelType, EmbedBuilder, AttachmentBuilder
} = require('discord.js');

/* ── Config ──────────────────────────────────────────────────── */
const PORT          = process.env.PORT            || 3000;
const ADMIN_TOKEN   = process.env.ADMIN_TOKEN     || 'change_me';
const DISCORD_TOKEN = process.env.DISCORD_TOKEN   || '';
const CLIENT_ID     = process.env.CLIENT_ID       || '';
const GUILD_ID      = process.env.GUILD_ID        || '';
const ADMIN_ROLE    = process.env.ADMIN_ROLE       || '';
const KEYS_FILE     = process.env.KEYS_FILE        || path.join(__dirname, 'keys.json');
const SESSION_TTL   = 15 * 60 * 1000;
const ADMIN_HTML = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');


// Ticket bot env vars
const SUPPORT_ROLE_ID      = process.env.SUPPORT_ROLE_ID      || '';
const TRANSCRIPT_CHANNEL_ID= process.env.TRANSCRIPT_CHANNEL_ID|| '';
const MESSAGE_LOG_CHANNEL_ID=process.env.MESSAGE_LOG_CHANNEL_ID|| '';
const STATUS_CHANNEL_ID    = process.env.STATUS_CHANNEL_ID    || '';
const HEARTBEAT_CHANNEL_ID = process.env.HEARTBEAT_CHANNEL_ID || '';
const TICKET_CATEGORY_ID   = process.env.TICKET_CATEGORY_ID   || '';

/* ── Key store ────────────────────────────────────────────────── */
function loadKeys() {
  try {
    if (!fs.existsSync(KEYS_FILE)) return {};
    return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  } catch (e) { return {}; }
}
function saveKeys(keys) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

/* ── Helpers ──────────────────────────────────────────────────── */
function sha256(s) {
  return crypto.createHash('sha256').update(s.trim().toUpperCase()).digest('hex');
}
function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
function genKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = n => Array.from({ length: n }, () => chars[crypto.randomInt(chars.length)]).join('');
  return `ZZZ-${seg(4)}-${seg(4)}-${seg(4)}`;
}
function addKey(keys, plaintext, opts = {}) {
  const key  = plaintext.trim().toUpperCase();
  const hash = sha256(key);
  if (keys[hash]) return null;
  keys[hash] = {
    plaintext,
    active:       true,
    hwid:         null,
    expires:      opts.expires   || null,
    discord:      opts.discord   || '',
    discordId:    opts.discordId || '',
    note:         opts.note      || '',
    createdAt:    Date.now(),
    lastSeen:     null,
    sessionToken: null,
    sessionExp:   null,
  };
  return hash;
}

/* ── HTTP helpers ─────────────────────────────────────────────── */
function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods':'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers':'Content-Type, Authorization',
  });
  res.end(body);
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', c => { b += c; });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function checkAdmin(req) {
  return (req.headers['authorization'] || '') === 'Bearer ' + ADMIN_TOKEN;
}

/* ── HTTP Routes ──────────────────────────────────────────────── */
async function handleValidate(req, res) {
  let body;
  try { body = await parseBody(req); } catch (e) { return sendJson(res, 400, { valid: false, error: 'Bad JSON.' }); }
  const { key, hwid } = body;
  if (!key || !hwid) return sendJson(res, 400, { valid: false, error: 'Missing key or hwid.' });
  const keys  = loadKeys();
  const hash  = sha256(key);
  const entry = keys[hash];
  if (!entry)         return sendJson(res, 200, { valid: false, error: 'Invalid key.' });
  if (!entry.active)  return sendJson(res, 200, { valid: false, error: 'This key has been revoked.' });
  if (entry.expires && entry.expires < Date.now())
                      return sendJson(res, 200, { valid: false, error: 'This key has expired.' });
  if (entry.hwid && entry.hwid !== hwid)
                      return sendJson(res, 200, { valid: false, error: 'Key already activated on another device.' });
  entry.hwid         = hwid;
  entry.sessionToken = newToken();
  entry.sessionExp   = Date.now() + SESSION_TTL;
  entry.lastSeen     = Date.now();
  keys[hash] = entry;
  saveKeys(keys);
  sendJson(res, 200, { valid: true, expires: entry.expires || null, discord: entry.discord || '', note: entry.note || '', sessionToken: entry.sessionToken, sessionExp: entry.sessionExp });
}

async function handleCheckSession(req, res) {
  let body;
  try { body = await parseBody(req); } catch (e) { return sendJson(res, 200, { valid: false }); }
  const { sessionToken, hwid } = body;
  if (!sessionToken || !hwid) return sendJson(res, 200, { valid: false });
  const keys  = loadKeys();
  const entry = Object.values(keys).find(e => e.sessionToken === sessionToken && e.hwid === hwid);
  if (!entry || !entry.active) return sendJson(res, 200, { valid: false });
  if (entry.expires && entry.expires < Date.now()) return sendJson(res, 200, { valid: false });
  entry.sessionExp = Date.now() + SESSION_TTL;
  entry.lastSeen   = Date.now();
  saveKeys(keys);
  sendJson(res, 200, { valid: true, discord: entry.discord || '', sessionExp: entry.sessionExp });
}

async function handleAdminList(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });
  const keys = loadKeys();
  sendJson(res, 200, { ok: true, keys: Object.entries(keys).map(([hash, e]) => ({ hash, key: e.plaintext, active: e.active, hwid: e.hwid || null, expires: e.expires || null, discord: e.discord || '', note: e.note || '', lastSeen: e.lastSeen || null })) });
}
async function handleAdminAdd(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });
  let body; try { body = await parseBody(req); } catch { return sendJson(res, 400, { error: 'Bad JSON.' }); }
  const keys = loadKeys();
  const hash = addKey(keys, body.key || genKey(), body);
  if (!hash) return sendJson(res, 409, { error: 'Key already exists.' });
  saveKeys(keys);
  sendJson(res, 200, { ok: true, hash, key: keys[hash].plaintext });
}
async function handleAdminBulk(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });
  let body; try { body = await parseBody(req); } catch { return sendJson(res, 400, { error: 'Bad JSON.' }); }
  const keys = loadKeys();
  const added = (body.keys || []).filter(k => addKey(keys, k, body));
  saveKeys(keys);
  sendJson(res, 200, { ok: true, added: added.length, keys: added });
}
async function handleAdminRevoke(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });
  let body; try { body = await parseBody(req); } catch { return sendJson(res, 400, { error: 'Bad JSON.' }); }
  const keys = loadKeys();
  const hash = body.hash || sha256(body.key || '');
  if (!keys[hash]) return sendJson(res, 404, { error: 'Key not found.' });
  keys[hash].active = false;
  saveKeys(keys);
  sendJson(res, 200, { ok: true });
}
async function handleAdminResetHwid(req, res) {
  if (!checkAdmin(req)) return sendJson(res, 401, { error: 'Unauthorized.' });
  let body; try { body = await parseBody(req); } catch { return sendJson(res, 400, { error: 'Bad JSON.' }); }
  const keys = loadKeys();
  const hash = body.hash || sha256(body.key || '');
  if (!keys[hash]) return sendJson(res, 404, { error: 'Key not found.' });
  keys[hash].hwid = keys[hash].sessionToken = keys[hash].sessionExp = null;
  saveKeys(keys);
  sendJson(res, 200, { ok: true });
}

/* ── HTTP Server ──────────────────────────────────────────────── */
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,GET,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,Authorization' });
    return res.end();
  }
  const url = req.url.split('?')[0];
  if (req.method === 'GET'  && (url === '/' || url === '/ping' || url === '/health')) return sendJson(res, 200, { ok: true });
  if (req.method === 'GET'  && url === '/admin') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(ADMIN_HTML);
  }
  if (req.method === 'POST' && url === '/validate')         return handleValidate(req, res);
  if (req.method === 'POST' && url === '/check-session')    return handleCheckSession(req, res);
  if (req.method === 'GET'  && url === '/admin/keys')       return handleAdminList(req, res);
  if (req.method === 'POST' && url === '/admin/add')        return handleAdminAdd(req, res);
  if (req.method === 'POST' && url === '/admin/bulk')       return handleAdminBulk(req, res);
  if (req.method === 'POST' && url === '/admin/revoke')     return handleAdminRevoke(req, res);
  if (req.method === 'POST' && url === '/admin/reset-hwid') return handleAdminResetHwid(req, res);
  sendJson(res, 404, { error: 'Not found.' });
});

server.listen(PORT, () => {
  console.log(`[zzzs] Key server running on port ${PORT}`);
});

/* ════════════════════════════════════════════════════════════════
   DISCORD BOT
   ════════════════════════════════════════════════════════════════ */
if (!DISCORD_TOKEN || !CLIENT_ID || !GUILD_ID) {
  console.log('[zzzs] Discord bot disabled — set DISCORD_TOKEN, CLIENT_ID, GUILD_ID in .env to enable.');
} else {

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
      GatewayIntentBits.GuildMembers,
      GatewayIntentBits.GuildInvites,
    ]
  });

  const cachedInvites = new Map();

  /* ── Slash commands ─────────────────────────────────────────── */
  const commands = [
    new SlashCommandBuilder()
      .setName('genkey')
      .setDescription('[Admin] Generate key(s) and optionally DM to a user')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addIntegerOption(o => o.setName('amount').setDescription('How many keys').setMinValue(1).setMaxValue(50).setRequired(false))
      .addUserOption(o => o.setName('user').setDescription('DM key to this user').setRequired(false))
      .addStringOption(o => o.setName('note').setDescription('Note e.g. buyer name').setRequired(false)),

    new SlashCommandBuilder()
      .setName('revoke')
      .setDescription('[Admin] Revoke a key')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addStringOption(o => o.setName('key').setDescription('Key to revoke').setRequired(true)),

    new SlashCommandBuilder()
      .setName('resethwid')
      .setDescription('[Admin] Reset HWID so key works on a new device')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addStringOption(o => o.setName('key').setDescription('Key to reset').setRequired(true)),

    new SlashCommandBuilder()
      .setName('keyinfo')
      .setDescription('[Admin] Look up info on a key')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
      .addStringOption(o => o.setName('key').setDescription('Key to look up').setRequired(true)),

    new SlashCommandBuilder()
      .setName('keys')
      .setDescription('[Admin] List all keys')
      .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),

    new SlashCommandBuilder()
      .setName('mykey')
      .setDescription('Get your /zzzs key sent to your DMs'),
  ].map(c => c.toJSON());

  function isAdmin(interaction) {
    if (ADMIN_ROLE) return interaction.member.roles.cache.has(ADMIN_ROLE) || interaction.member.permissions.has(PermissionFlagsBits.ManageGuild);
    return interaction.member.permissions.has(PermissionFlagsBits.ManageGuild);
  }

  /* ── Ready ──────────────────────────────────────────────────── */
  client.once('ready', async () => {
    console.log(`[zzzs] Discord bot logged in as ${client.user.tag}`);

    // Set presence
    client.user.setPresence({
      status: 'dnd',
      activities: [{ name: 'bloodrain', type: 3 }]
    });

    // Cache invites
    client.guilds.cache.forEach(async (guild) => {
      try {
        const invites = await guild.invites.fetch();
        invites.forEach(i => cachedInvites.set(i.code, i.uses));
      } catch {}
    });

    // Status channel
    if (STATUS_CHANNEL_ID) {
      const statusChannel = client.channels.cache.get(STATUS_CHANNEL_ID);
      if (statusChannel) await statusChannel.setName('🟢-ticket-bot-works').catch(() => {});
    }

    // Heartbeat
    if (HEARTBEAT_CHANNEL_ID) {
      const heartbeatChannel = client.channels.cache.get(HEARTBEAT_CHANNEL_ID);
      if (heartbeatChannel) {
        setInterval(async () => {
          await heartbeatChannel.send(`✅ Bot is alive — ${new Date().toLocaleTimeString()}`).catch(() => {});
        }, 30000);
      }
    }

    // Register slash commands
    const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
    try {
      await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
      console.log('[zzzs] Slash commands registered.');
    } catch (e) {
      console.error('[zzzs] Failed to register commands:', e.message);
    }
  });

  /* ── Ticket panel command ────────────────────────────────────── */
  client.on('messageCreate', async (message) => {
    if (message.content === '!ticket-panel' && message.member.permissions.has(PermissionFlagsBits.Administrator)) {
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('open_ticket').setLabel('Open Ticket').setStyle(ButtonStyle.Primary)
      );
      await message.channel.send({ content: 'Please click on the button below to create a ticket.', components: [row] });
    }
  });

  /* ── Interactions ────────────────────────────────────────────── */
  client.on('interactionCreate', async (interaction) => {

    /* ── Button interactions (tickets) ── */
    if (interaction.isButton()) {
      if (interaction.customId === 'open_ticket') {
        const existing = interaction.guild.channels.cache.find(c => c.name === `ticket-${interaction.user.username.toLowerCase()}`);
        if (existing) {
          return interaction.reply({ content: `You already have a ticket: ${existing}`, ephemeral: true });
        }
        const channel = await interaction.guild.channels.create({
          name: `ticket-${interaction.user.username}`,
          type: ChannelType.GuildText,
          parent: TICKET_CATEGORY_ID || null,
          permissionOverwrites: [
            { id: interaction.guild.id, deny: [PermissionFlagsBits.ViewChannel] },
            { id: interaction.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
            { id: SUPPORT_ROLE_ID, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] }
          ]
        });
        const closeRow = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId('close_ticket').setLabel('Close Ticket').setStyle(ButtonStyle.Danger)
        );
        await channel.send({ content: `Hello ${interaction.user}! Seller will be with you shortly.\n<@&${SUPPORT_ROLE_ID}>`, components: [closeRow] });
        await interaction.reply({ content: `Your ticket: ${channel}`, ephemeral: true });
      }

      if (interaction.customId === 'close_ticket') {
        await interaction.reply('Saving transcript and closing in 5 seconds...');
        const messages = await interaction.channel.messages.fetch({ limit: 100 });
        const sorted = messages.sort((a, b) => a.createdTimestamp - b.createdTimestamp);
        const transcript = sorted.map(m =>
          `[${new Date(m.createdTimestamp).toLocaleString()}] ${m.author.tag}: ${m.content}`
        ).join('\n');
        if (TRANSCRIPT_CHANNEL_ID) {
          const logChannel = interaction.guild.channels.cache.get(TRANSCRIPT_CHANNEL_ID);
          if (logChannel) {
            const buffer = Buffer.from(transcript, 'utf-8');
            const attachment = new AttachmentBuilder(buffer, { name: `${interaction.channel.name}.txt` });
            await logChannel.send({ content: `📜 Transcript for **${interaction.channel.name}**`, files: [attachment] });
          }
        }
        setTimeout(() => interaction.channel.delete(), 5000);
      }
      return;
    }

    /* ── Slash command interactions ── */
    if (!interaction.isChatInputCommand()) return;
    const cmd = interaction.commandName;

    if (cmd === 'genkey') {
      if (!isAdmin(interaction)) return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      await interaction.deferReply({ ephemeral: true });
      const amount  = interaction.options.getInteger('amount') || 1;
      const target  = interaction.options.getUser('user');
      const note    = interaction.options.getString('note') || '';
      const keys    = loadKeys();
      const newKeys = [];
      for (let i = 0; i < amount; i++) {
        const k = genKey();
        addKey(keys, k, { discord: target ? target.tag : '', discordId: target ? target.id : '', note });
        newKeys.push(k);
      }
      saveKeys(keys);
      const keyList = newKeys.map(k => `\`${k}\``).join('\n');
      if (target && amount === 1) {
        try {
          await target.send(`## Your /zzzs Key\n\`\`\`\n${newKeys[0]}\n\`\`\`\nActivate it in the extension. Keep this private!`);
          return interaction.editReply(`✅ Key generated and DMed to **${target.tag}**.\n${keyList}`);
        } catch {
          return interaction.editReply(`✅ Generated (couldn't DM — DMs may be off):\n${keyList}`);
        }
      }
      return interaction.editReply(`✅ Generated **${amount}** key${amount > 1 ? 's' : ''}:\n${keyList}`);
    }

    if (cmd === 'revoke') {
      if (!isAdmin(interaction)) return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      const k = interaction.options.getString('key').trim().toUpperCase();
      const keys = loadKeys();
      const hash = sha256(k);
      if (!keys[hash]) return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
      keys[hash].active = false;
      saveKeys(keys);
      return interaction.reply({ content: `✅ \`${k}\` revoked.`, ephemeral: true });
    }

    if (cmd === 'resethwid') {
      if (!isAdmin(interaction)) return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      const k = interaction.options.getString('key').trim().toUpperCase();
      const keys = loadKeys();
      const hash = sha256(k);
      if (!keys[hash]) return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
      keys[hash].hwid = keys[hash].sessionToken = keys[hash].sessionExp = null;
      saveKeys(keys);
      return interaction.reply({ content: `✅ HWID reset for \`${k}\`.`, ephemeral: true });
    }

    if (cmd === 'keyinfo') {
      if (!isAdmin(interaction)) return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      const k = interaction.options.getString('key').trim().toUpperCase();
      const keys = loadKeys();
      const e = keys[sha256(k)];
      if (!e) return interaction.reply({ content: '❌ Key not found.', ephemeral: true });
      return interaction.reply({
        embeds: [{
          title: '🔑 Key Info',
          color: e.active ? 0x22c55e : 0xef4444,
          fields: [
            { name: 'Key',      value: `\`${e.plaintext}\``,                                  inline: false },
            { name: 'Status',   value: e.active ? '✅ Active' : '❌ Revoked',                  inline: true  },
            { name: 'Expires',  value: e.expires ? `<t:${Math.floor(e.expires/1000)}:R>` : 'Lifetime', inline: true },
            { name: 'HWID',     value: e.hwid ? `\`${e.hwid.slice(0,8)}…\`` : 'Unbound',     inline: true  },
            { name: 'Discord',  value: e.discord  || 'None',                                  inline: true  },
            { name: 'Note',     value: e.note     || 'None',                                  inline: true  },
            { name: 'Last Seen',value: e.lastSeen ? `<t:${Math.floor(e.lastSeen/1000)}:R>` : 'Never', inline: true },
          ],
        }],
        ephemeral: true,
      });
    }

    if (cmd === 'keys') {
      if (!isAdmin(interaction)) return interaction.reply({ content: '❌ No permission.', ephemeral: true });
      const keys = loadKeys();
      const all  = Object.values(keys);
      const lines = all.slice(0, 25).map(e =>
        `${e.active ? '✅' : '❌'}${e.hwid ? '🔒' : '🔓'} \`${e.plaintext}\`${e.discord ? ' — ' + e.discord : ''}${e.note ? ' (' + e.note + ')' : ''}`
      ).join('\n');
      return interaction.reply({
        embeds: [{
          title: '🔑 /zzzs Keys',
          description: lines || 'No keys yet.',
          color: 0xa855f7,
          footer: { text: `Total: ${all.length} | Active: ${all.filter(e=>e.active).length} | Bound: ${all.filter(e=>e.hwid).length}${all.length > 25 ? ' | Showing first 25' : ''}` },
        }],
        ephemeral: true,
      });
    }

    if (cmd === 'mykey') {
      await interaction.deferReply({ ephemeral: true });
      const keys  = loadKeys();
      const entry = Object.values(keys).find(e => e.discordId === interaction.user.id && e.active);
      if (!entry) return interaction.editReply('❌ No active key found for your account. Ask an admin to generate one with `/genkey @you`.');
      try {
        await interaction.user.send(`## Your /zzzs Key\n\`\`\`\n${entry.plaintext}\n\`\`\`\nActivate it in the extension. **Keep this private!**`);
        return interaction.editReply('✅ Key sent to your DMs!');
      } catch {
        return interaction.editReply(`✅ Your key (only visible to you):\n\`${entry.plaintext}\``);
      }
    }
  });

  /* ── Message logging ─────────────────────────────────────────── */
  client.on('messageDelete', async (message) => {
    if (message.author?.bot) return;
    if (!MESSAGE_LOG_CHANNEL_ID) return;
    const logChannel = message.guild?.channels.cache.get(MESSAGE_LOG_CHANNEL_ID);
    if (!logChannel) return;
    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setTitle('🗑️ Message Deleted')
      .addFields(
        { name: 'Author', value: `${message.author.tag} (${message.author.id})`, inline: true },
        { name: 'Channel', value: `${message.channel}`, inline: true },
        { name: 'Content', value: message.content || '*empty*' }
      )
      .setTimestamp();
    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  client.on('messageUpdate', async (oldMessage, newMessage) => {
    if (oldMessage.author?.bot) return;
    if (oldMessage.content === newMessage.content) return;
    if (!MESSAGE_LOG_CHANNEL_ID) return;
    const logChannel = oldMessage.guild?.channels.cache.get(MESSAGE_LOG_CHANNEL_ID);
    if (!logChannel) return;
    const embed = new EmbedBuilder()
      .setColor(0xffa500)
      .setTitle('✏️ Message Edited')
      .addFields(
        { name: 'Author', value: `${oldMessage.author.tag} (${oldMessage.author.id})`, inline: true },
        { name: 'Channel', value: `${oldMessage.channel}`, inline: true },
        { name: 'Before', value: oldMessage.content || '*empty*' },
        { name: 'After', value: newMessage.content || '*empty*' }
      )
      .setTimestamp();
    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  /* ── Member join/leave logging ───────────────────────────────── */
  client.on('guildMemberAdd', async (member) => {
    if (!MESSAGE_LOG_CHANNEL_ID) return;
    const logChannel = member.guild.channels.cache.get(MESSAGE_LOG_CHANNEL_ID);
    if (!logChannel) return;
    let inviter = 'Unknown';
    try {
      const invites = await member.guild.invites.fetch();
      const usedInvite = invites.find(i => i.uses > (cachedInvites.get(i.code) || 0));
      if (usedInvite) inviter = `<@${usedInvite.inviter.id}>`;
      invites.forEach(i => cachedInvites.set(i.code, i.uses));
    } catch {}
    const embed = new EmbedBuilder()
      .setColor(0x00ff00)
      .setTitle('📥 Member Joined')
      .addFields(
        { name: 'Member', value: `${member.user.tag} (${member.id})`, inline: true },
        { name: 'Invited by', value: inviter, inline: true }
      )
      .setTimestamp();
    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  client.on('guildMemberRemove', async (member) => {
    if (!MESSAGE_LOG_CHANNEL_ID) return;
    const logChannel = member.guild.channels.cache.get(MESSAGE_LOG_CHANNEL_ID);
    if (!logChannel) return;
    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setTitle('📤 Member Left')
      .addFields(
        { name: 'Member', value: `${member.user.tag} (${member.id})`, inline: true }
      )
      .setTimestamp();
    await logChannel.send({ embeds: [embed] }).catch(() => {});
  });

  /* ── Shutdown ────────────────────────────────────────────────── */
  process.on('SIGINT', async () => {
    if (STATUS_CHANNEL_ID) {
      const statusChannel = client.channels.cache.get(STATUS_CHANNEL_ID);
      if (statusChannel) await statusChannel.setName('🔴-ticket-bot-offline').catch(() => {});
    }
    process.exit();
  });

  client.login(DISCORD_TOKEN).catch(e => console.error('[zzzs] Discord login failed:', e.message));
}
